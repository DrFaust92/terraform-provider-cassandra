package cassandra

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const keyspaceLiteralPattern = `^[a-zA-Z0-9][a-zA-Z0-9_]{0,48}$`

var (
	keyspaceRegex = regexp.MustCompile(keyspaceLiteralPattern)
	boolToAction  = map[bool]string{
		true:  "CREATE",
		false: "ALTER",
	}
)

var (
	_ resource.Resource                = &keyspaceResource{}
	_ resource.ResourceWithConfigure   = &keyspaceResource{}
	_ resource.ResourceWithImportState = &keyspaceResource{}
)

type keyspaceResource struct {
	clusterResource
}

func newKeyspaceResource() resource.Resource {
	return &keyspaceResource{}
}

type keyspaceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	ReplicationStrategy types.String `tfsdk:"replication_strategy"`
	StrategyOptions     types.Map    `tfsdk:"strategy_options"`
	DurableWrites       types.Bool   `tfsdk:"durable_writes"`
}

func (r *keyspaceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keyspace"
}

func (r *keyspaceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cassandra keyspace.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Name of the keyspace.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Name of the keyspace, 1 to 48 characters.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(keyspaceRegex, "invalid keyspace name - must match "+keyspaceLiteralPattern),
					stringvalidator.NoneOf("system"),
				},
			},
			"replication_strategy": schema.StringAttribute{
				Required:    true,
				Description: "Replication strategy: `SimpleStrategy` or `NetworkTopologyStrategy`.",
				Validators:  []validator.String{stringvalidator.OneOf("SimpleStrategy", "NetworkTopologyStrategy", "SingleRegionStrategy")},
			},
			"strategy_options": schema.MapAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "Options for the replication strategy. `SimpleStrategy` takes `replication_factor`; `NetworkTopologyStrategy` takes data center names mapped to their replication factor.",
				Validators:  []validator.Map{mapvalidator.SizeAtLeast(1)},
			},
			"durable_writes": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Enable durable writes. Disabling them is not recommended. Defaults to `true`.",
			},
		},
	}
}

func keyspaceQuery(create bool, m keyspaceModel) string {
	options := map[string]string{}
	for k, v := range m.StrategyOptions.Elements() {
		options[k] = v.(types.String).ValueString()
	}
	keys := make([]string, 0, len(options))
	for k := range options {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	query := fmt.Sprintf(`%s KEYSPACE %s WITH REPLICATION = { 'class' : '%s'`, boolToAction[create], m.Name.ValueString(), cqlEscape(m.ReplicationStrategy.ValueString()))
	for _, k := range keys {
		query += fmt.Sprintf(`, '%s' : '%s'`, cqlEscape(k), cqlEscape(options[k]))
	}
	return query + fmt.Sprintf(` } AND DURABLE_WRITES = %t`, m.DurableWrites.ValueBool())
}

func (r *keyspaceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan keyspaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	query := keyspaceQuery(true, plan)
	tflog.Debug(ctx, "creating keyspace", map[string]interface{}{"query": query})
	if err := session.Query(query).Exec(); err != nil {
		resp.Diagnostics.AddError("Unable to create keyspace", err.Error())
		return
	}

	// Store the configured options: Cassandra may expand them (for example
	// replication_factor under NetworkTopologyStrategy), which shows as a diff
	// on the next plan, as it always has.
	plan.ID = plan.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *keyspaceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state keyspaceModel
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
	metadata, err := session.KeyspaceMetadata(name)
	if errors.Is(err, gocql.ErrKeyspaceDoesNotExist) {
		tflog.Warn(ctx, "keyspace no longer exists, removing it from state", map[string]interface{}{"name": name})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read keyspace", err.Error())
		return
	}

	options := map[string]string{}
	for k, v := range metadata.StrategyOptions {
		options[k] = fmt.Sprint(v)
	}
	strategyOptions, d := types.MapValueFrom(ctx, types.StringType, options)
	resp.Diagnostics.Append(d...)

	state.ID = types.StringValue(name)
	state.Name = types.StringValue(name)
	state.ReplicationStrategy = types.StringValue(strings.TrimPrefix(metadata.StrategyClass, "org.apache.cassandra.locator."))
	state.StrategyOptions = strategyOptions
	state.DurableWrites = types.BoolValue(metadata.DurableWrites)

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *keyspaceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan keyspaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	query := keyspaceQuery(false, plan)
	tflog.Debug(ctx, "updating keyspace", map[string]interface{}{"query": query})
	if err := session.Query(query).Exec(); err != nil {
		resp.Diagnostics.AddError("Unable to update keyspace", err.Error())
		return
	}

	plan.ID = plan.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *keyspaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state keyspaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	if err := session.Query(fmt.Sprintf(`DROP KEYSPACE IF EXISTS %s`, state.Name.ValueString())).Exec(); err != nil {
		resp.Diagnostics.AddError("Unable to delete keyspace", err.Error())
	}
}

func (r *keyspaceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
