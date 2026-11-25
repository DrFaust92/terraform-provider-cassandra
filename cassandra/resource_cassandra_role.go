package cassandra

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/crypto/bcrypt"
)

const defaultRoleTimeout = time.Minute

var (
	_ resource.Resource                     = &roleResource{}
	_ resource.ResourceWithConfigure        = &roleResource{}
	_ resource.ResourceWithImportState      = &roleResource{}
	_ resource.ResourceWithConfigValidators = &roleResource{}
)

// errRoleNotFound is returned by readRole when the role does not exist.
var errRoleNotFound = errors.New("role not found")

type roleResource struct {
	clusterResource
}

func newRoleResource() resource.Resource {
	return &roleResource{}
}

type roleModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	SuperUser types.Bool   `tfsdk:"super_user"`
	Login     types.Bool   `tfsdk:"login"`
	Password  types.String `tfsdk:"password"`
	// PasswordWO is write-only: it is only ever set in the configuration.
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.String `tfsdk:"password_wo_version"`
	Timeouts          types.Object `tfsdk:"timeouts"`
}

var timeoutsAttrTypes = map[string]attr.Type{"default": types.StringType}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cassandra role.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Name of the role.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Name of the role, 1 to 256 characters with no double quotes.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[^"]{1,256}$`), "name must contain between 1 and 256 chars and must not contain double quote character"),
				},
			},
			"super_user": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Allow the role to create and manage other roles. Defaults to `false`.",
			},
			"login": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Allow the role to log in. Defaults to `true`.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Password for the role when using Cassandra internal authentication, 40 to 512 characters. Stored in state; use `password_wo` to keep it out. Exactly one of `password` and `password_wo` must be set.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(40, 512),
					// Warns on Terraform 1.11+, which supports password_wo.
					stringvalidator.PreferWriteOnlyAttribute(path.MatchRoot("password_wo")),
				},
			},
			"password_wo": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Write-only alternative to `password`, never stored in state, 40 to 512 characters. Requires Terraform 1.11 or later.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(40, 512),
					stringvalidator.AlsoRequires(path.MatchRoot("password_wo_version")),
				},
			},
			"password_wo_version": schema.StringAttribute{
				Optional:    true,
				Description: "Change this value to update `password_wo`, Terraform cannot detect changes to write-only attributes.",
				Validators:  []validator.String{stringvalidator.AlsoRequires(path.MatchRoot("password_wo"))},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": schema.SingleNestedBlock{
				Description: "Timeouts for role operations.",
				Attributes: map[string]schema.Attribute{
					"default": schema.StringAttribute{
						Optional:    true,
						Description: "How long to retry a password change that Cassandra throttles, as a duration such as `30s` or `2m`. Defaults to `1m`.",
					},
				},
			},
		},
	}
}

func (r *roleResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(path.MatchRoot("password"), path.MatchRoot("password_wo")),
	}
}

// configPassword returns the password to send: password_wo from the
// configuration when set, otherwise password.
func configPassword(ctx context.Context, cfg tfsdk.Config, plan roleModel) (string, diag.Diagnostics) {
	var wo types.String
	diags := cfg.GetAttribute(ctx, path.Root("password_wo"), &wo)
	if !wo.IsNull() && !wo.IsUnknown() {
		return wo.ValueString(), diags
	}
	return plan.Password.ValueString(), diags
}

func readRole(session *gocql.Session, name string) (string, bool, bool, string, error) {
	var (
		role        string
		canLogin    bool
		isSuperUser bool
		saltedHash  string
	)

	iter := session.Query(`select role, can_login, is_superuser, salted_hash from system_auth.roles where role = ?`, name).Iter()
	found := iter.Scan(&role, &canLogin, &isSuperUser, &saltedHash)
	if err := iter.Close(); err != nil {
		return "", false, false, "", err
	}
	if !found {
		return "", false, false, "", fmt.Errorf("cannot read role with name %s: %w", name, errRoleNotFound)
	}
	return role, canLogin, isSuperUser, saltedHash, nil
}

func roleTimeout(m roleModel) (time.Duration, error) {
	if m.Timeouts.IsNull() || m.Timeouts.IsUnknown() {
		return defaultRoleTimeout, nil
	}
	v, ok := m.Timeouts.Attributes()["default"].(types.String)
	if !ok || v.IsNull() || v.ValueString() == "" {
		return defaultRoleTimeout, nil
	}
	d, err := time.ParseDuration(v.ValueString())
	if err != nil {
		return 0, fmt.Errorf("timeouts.default: %w", err)
	}
	return d, nil
}

// writeRole runs CREATE or ALTER ROLE. The password is only sent when
// setPassword is true: Cassandra 5 rejects a password change within
// credentials_update_interval of the previous one, so a throttled change is
// retried until the role's timeout.
func (r *roleResource) writeRole(ctx context.Context, session *gocql.Session, create bool, password *string, plan roleModel) error {
	options := fmt.Sprintf(`LOGIN = %v AND SUPERUSER = %v`, plan.Login.ValueBool(), plan.SuperUser.ValueBool())
	if password != nil {
		options = fmt.Sprintf(`PASSWORD = '%s' AND %s`, cqlEscape(*password), options)
	}
	query := fmt.Sprintf(`%s ROLE '%s' WITH %s`, boolToAction[create], cqlEscape(plan.Name.ValueString()), options)

	timeout, err := roleTimeout(plan)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)

	for {
		err := session.Query(query).Exec()
		if err == nil || !strings.Contains(err.Error(), "can only be changed every") || time.Now().After(deadline) {
			return err
		}
		tflog.Debug(ctx, "password change throttled, retrying", map[string]interface{}{"role": plan.Name.ValueString(), "error": err.Error()})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	password, d := configPassword(ctx, req.Config, plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.writeRole(ctx, session, true, &password, plan); err != nil {
		resp.Diagnostics.AddError("Unable to create role", err.Error())
		return
	}

	plan.ID = plan.Name
	plan.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	name := state.ID.ValueString()
	role, login, superUser, saltedHash, err := readRole(session, name)
	if errors.Is(err, errRoleNotFound) {
		tflog.Warn(ctx, "role no longer exists, removing it from state", map[string]interface{}{"name": name})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read role", err.Error())
		return
	}

	state.ID = types.StringValue(role)
	state.Name = types.StringValue(role)
	state.Login = types.BoolValue(login)
	state.SuperUser = types.BoolValue(superUser)
	// Cassandra stores only a salted hash. Keep the known password while it
	// still matches; otherwise record the hash so the change shows as a diff.
	// With password_wo there is no password in state to compare.
	if !state.Password.IsNull() && bcrypt.CompareHashAndPassword([]byte(saltedHash), []byte(state.Password.ValueString())) != nil {
		state.Password = types.StringValue(saltedHash)
	}
	if state.Timeouts.IsUnknown() {
		state.Timeouts = types.ObjectNull(timeoutsAttrTypes)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	// Send the password only when it changed: password itself, or a new
	// password_wo_version.
	var password *string
	if !plan.Password.Equal(state.Password) || !plan.PasswordWOVersion.Equal(state.PasswordWOVersion) {
		p, d := configPassword(ctx, req.Config, plan)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		password = &p
	}
	if err := r.writeRole(ctx, session, false, password, plan); err != nil {
		resp.Diagnostics.AddError("Unable to update role", err.Error())
		return
	}

	plan.ID = plan.Name
	plan.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	if err := session.Query(fmt.Sprintf(`DROP ROLE IF EXISTS '%s'`, cqlEscape(state.Name.ValueString()))).Exec(); err != nil {
		resp.Diagnostics.AddError("Unable to delete role", err.Error())
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	// Read fills in the rest; the password is recorded as Cassandra's hash.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password"), "")...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("timeouts"), types.ObjectNull(timeoutsAttrTypes))...)
}
