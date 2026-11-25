package cassandra

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	deleteGrantRawTemplate = `REVOKE {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace}}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} FROM "{{.Grantee}}"`
	createGrantRawTemplate = `GRANT {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace}}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} TO "{{.Grantee}}"`
	readGrantRawTemplate   = `LIST {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace }}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} OF "{{.Grantee}}"`

	privilegeAll       = "all"
	privilegeCreate    = "create"
	privilegeAlter     = "alter"
	privilegeDrop      = "drop"
	privilegeSelect    = "select"
	privilegeModify    = "modify"
	privilegeAuthorize = "authorize"
	privilegeDescribe  = "describe"
	privilegeExecute   = "execute"

	resourceAllFunctions           = "all functions"
	resourceAllFunctionsInKeyspace = "all functions in keyspace"
	resourceFunction               = "function"
	resourceAllKeyspaces           = "all keyspaces"
	resourceKeyspace               = "keyspace"
	resourceTable                  = "table"
	resourceAllRoles               = "all roles"
	resourceRole                   = "role"
	resourceRoles                  = "roles"
	resourceMbean                  = "mbean"
	resourceMbeans                 = "mbeans"
	resourceAllMbeans              = "all mbeans"

	identifierFunctionName = "function_name"
	identifierTableName    = "table_name"
	identifierMbeanName    = "mbean_name"
	identifierMbeanPattern = "mbean_pattern"
	identifierRoleName     = "role_name"
	identifierKeyspaceName = "keyspace_name"
	identifierGrantee      = "grantee"
	identifierPrivilege    = "privilege"
	identifierResourceType = "resource_type"
)

var (
	templateDelete = template.Must(template.New("delete_grant").Parse(deleteGrantRawTemplate))
	templateCreate = template.Must(template.New("create_grant").Parse(createGrantRawTemplate))
	templateRead   = template.Must(template.New("read_grant").Parse(readGrantRawTemplate))

	validIdentifierRegex = regexp.MustCompile(`^[^"]{1,256}$`)
	validTableNameRegex  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_]{0,255}$`)

	allPrivileges = []string{privilegeSelect, privilegeCreate, privilegeAlter, privilegeDrop, privilegeModify, privilegeAuthorize, privilegeDescribe, privilegeExecute}

	allResources = []string{resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllRoles, resourceRole, resourceRoles, resourceMbean, resourceMbeans, resourceAllMbeans}

	privilegeToResourceTypesMap = map[string][]string{
		privilegeAll:       {resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllRoles, resourceRole},
		privilegeCreate:    {resourceAllKeyspaces, resourceKeyspace, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceAllRoles},
		privilegeAlter:     {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllRoles, resourceRole},
		privilegeDrop:      {resourceKeyspace, resourceTable, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllRoles, resourceRole},
		privilegeSelect:    {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllMbeans, resourceMbeans, resourceMbean},
		privilegeModify:    {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllMbeans, resourceMbeans, resourceMbean},
		privilegeAuthorize: {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceFunction, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceAllRoles, resourceRoles},
		privilegeDescribe:  {resourceAllRoles, resourceAllMbeans},
		privilegeExecute:   {resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction},
	}

	resourcesThatRequireKeyspaceQualifier = []string{resourceAllFunctionsInKeyspace, resourceFunction, resourceKeyspace, resourceTable}

	resourceTypeToIdentifier = map[string]string{
		resourceFunction: identifierFunctionName,
		resourceMbean:    identifierMbeanName,
		resourceMbeans:   identifierMbeanPattern,
		resourceTable:    identifierTableName,
		resourceRole:     identifierRoleName,
	}
)

// Grant represents a Cassandra Grant
type Grant struct {
	Privilege    string
	ResourceType string
	Grantee      string
	Keyspace     string
	Identifier   string
}

var (
	_ resource.Resource                   = &grantResource{}
	_ resource.ResourceWithConfigure      = &grantResource{}
	_ resource.ResourceWithValidateConfig = &grantResource{}
)

type grantResource struct {
	clusterResource
}

func newGrantResource() resource.Resource {
	return &grantResource{}
}

type grantModel struct {
	ID           types.String `tfsdk:"id"`
	Privilege    types.String `tfsdk:"privilege"`
	Grantee      types.String `tfsdk:"grantee"`
	ResourceType types.String `tfsdk:"resource_type"`
	KeyspaceName types.String `tfsdk:"keyspace_name"`
	FunctionName types.String `tfsdk:"function_name"`
	TableName    types.String `tfsdk:"table_name"`
	RoleName     types.String `tfsdk:"role_name"`
	MbeanName    types.String `tfsdk:"mbean_name"`
	MbeanPattern types.String `tfsdk:"mbean_pattern"`
}

func (m *grantModel) identifier(name string) types.String {
	switch name {
	case identifierFunctionName:
		return m.FunctionName
	case identifierTableName:
		return m.TableName
	case identifierRoleName:
		return m.RoleName
	case identifierMbeanName:
		return m.MbeanName
	case identifierMbeanPattern:
		return m.MbeanPattern
	}
	return types.StringNull()
}

// normalize maps "" left by the SDKv2 provider in optional attributes to null.
func (m *grantModel) normalize() {
	m.KeyspaceName = nullIfEmpty(m.KeyspaceName)
	m.FunctionName = nullIfEmpty(m.FunctionName)
	m.TableName = nullIfEmpty(m.TableName)
	m.RoleName = nullIfEmpty(m.RoleName)
	m.MbeanName = nullIfEmpty(m.MbeanName)
	m.MbeanPattern = nullIfEmpty(m.MbeanPattern)
}

func (r *grantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant"
}

func conflicts(names ...string) validator.String {
	paths := make([]path.Expression, 0, len(names))
	for _, n := range names {
		paths = append(paths, path.MatchRoot(n))
	}
	return stringvalidator.ConflictsWith(paths...)
}

func (r *grantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	identifierMessage := func(what string) string { return fmt.Sprintf("must be a valid %s name", what) }

	resp.Schema = schema.Schema{
		Description: "Grants a privilege on a resource to a Cassandra role. All arguments force a new grant.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Hash identifying the grant.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			identifierPrivilege: schema.StringAttribute{
				Required:      true,
				Description:   fmt.Sprintf("Privilege to grant: `all`, `%s`.", strings.Join(allPrivileges, "`, `")),
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.OneOf(append([]string{privilegeAll}, allPrivileges...)...)},
			},
			identifierGrantee: schema.StringAttribute{
				Required:      true,
				Description:   "Name of the role the privilege is granted to.",
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 256)},
			},
			identifierResourceType: schema.StringAttribute{
				Required:      true,
				Description:   fmt.Sprintf("Type of resource the privilege applies to: `%s`.", strings.Join(allResources, "`, `")),
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.OneOf(allResources...)},
			},
			identifierKeyspaceName: schema.StringAttribute{
				Optional:      true,
				Description:   fmt.Sprintf("Keyspace of the resource. Required when `resource_type` is `%s`.", strings.Join(resourcesThatRequireKeyspaceQualifier, "`, `")),
				PlanModifiers: replace,
				Validators: []validator.String{
					stringvalidator.RegexMatches(keyspaceRegex, "must be a valid keyspace name"),
					conflicts(identifierRoleName, identifierMbeanName, identifierMbeanPattern),
				},
			},
			identifierFunctionName: schema.StringAttribute{
				Optional:      true,
				Description:   fmt.Sprintf("Name of the function. Required when `resource_type` is `%s`.", resourceFunction),
				PlanModifiers: replace,
				Validators: []validator.String{
					stringvalidator.RegexMatches(validIdentifierRegex, identifierMessage("function")),
					conflicts(identifierTableName, identifierRoleName, identifierMbeanName, identifierMbeanPattern),
				},
			},
			identifierTableName: schema.StringAttribute{
				Optional:      true,
				Description:   fmt.Sprintf("Name of the table. Required when `resource_type` is `%s`.", resourceTable),
				PlanModifiers: replace,
				Validators: []validator.String{
					stringvalidator.RegexMatches(validTableNameRegex, identifierMessage("table")),
					conflicts(identifierFunctionName, identifierRoleName, identifierMbeanName, identifierMbeanPattern),
				},
			},
			identifierRoleName: schema.StringAttribute{
				Optional:      true,
				Description:   fmt.Sprintf("Name of the role. Required when `resource_type` is `%s`.", resourceRole),
				PlanModifiers: replace,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 256),
					conflicts(identifierFunctionName, identifierTableName, identifierMbeanName, identifierMbeanPattern, identifierKeyspaceName),
				},
			},
			identifierMbeanName: schema.StringAttribute{
				Optional:      true,
				Description:   fmt.Sprintf("Name of the MBean. Required when `resource_type` is `%s`.", resourceMbean),
				PlanModifiers: replace,
				Validators: []validator.String{
					stringvalidator.RegexMatches(validIdentifierRegex, identifierMessage("mbean")),
					conflicts(identifierFunctionName, identifierTableName, identifierRoleName, identifierMbeanPattern, identifierKeyspaceName),
				},
			},
			identifierMbeanPattern: schema.StringAttribute{
				Optional:      true,
				Description:   fmt.Sprintf("Pattern selecting MBeans. Required when `resource_type` is `%s`.", resourceMbeans),
				PlanModifiers: replace,
				Validators: []validator.String{
					regexpValidator{},
					conflicts(identifierFunctionName, identifierTableName, identifierRoleName, identifierMbeanName, identifierKeyspaceName),
				},
			},
		},
	}
}

// ValidateConfig checks the privilege, resource type and qualifiers fit together.
func (r *grantResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m grantModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Privilege.IsUnknown() || m.ResourceType.IsUnknown() {
		return
	}
	if _, err := grantFromModel(m, true); err != nil {
		resp.Diagnostics.AddError("Invalid grant", err.Error())
	}
}

// grantFromModel builds the Grant for m. With validateOnly, unknown qualifier
// values are accepted.
func grantFromModel(m grantModel, validateOnly bool) (*Grant, error) {
	privilege := m.Privilege.ValueString()
	resourceType := m.ResourceType.ValueString()

	allowed := privilegeToResourceTypesMap[privilege]
	if !slices.Contains(allowed, resourceType) {
		return nil, fmt.Errorf("%s resource not applicable for privilege %s - valid resourceTypes are %s", resourceType, privilege, strings.Join(allowed, ", "))
	}

	grant := &Grant{Privilege: privilege, ResourceType: resourceType, Grantee: m.Grantee.ValueString()}

	if slices.Contains(resourcesThatRequireKeyspaceQualifier, resourceType) {
		if m.KeyspaceName.IsUnknown() && validateOnly {
			// known at apply time
		} else if m.KeyspaceName.ValueString() == "" {
			return nil, fmt.Errorf("keyspace name must be set for resourceType %s", resourceType)
		}
		grant.Keyspace = m.KeyspaceName.ValueString()
	}

	if key := resourceTypeToIdentifier[resourceType]; key != "" {
		v := m.identifier(key)
		if v.IsUnknown() && validateOnly {
			// known at apply time
		} else if v.ValueString() == "" {
			return nil, fmt.Errorf("%s needs to be set when resourceType = %s", key, resourceType)
		}
		grant.Identifier = v.ValueString()
	}

	return grant, nil
}

func render(t *template.Template, grant *Grant) (string, error) {
	var buffer bytes.Buffer
	if err := t.Execute(&buffer, grant); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func grantExists(session *gocql.Session, grant *Grant) (bool, error) {
	query, err := render(templateRead, grant)
	if err != nil {
		return false, err
	}
	iter := session.Query(query).Iter()
	rows := iter.NumRows()
	if err := iter.Close(); err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (r *grantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	grant, err := grantFromModel(plan, false)
	if err != nil {
		resp.Diagnostics.AddError("Invalid grant", err.Error())
		return
	}
	query, err := render(templateCreate, grant)
	if err != nil {
		resp.Diagnostics.AddError("Unable to render grant", err.Error())
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	tflog.Debug(ctx, "creating grant", map[string]interface{}{"query": query})
	if err := session.Query(query).Exec(); err != nil {
		resp.Diagnostics.AddError("Unable to create grant", err.Error())
		return
	}

	// The ID format is unchanged from the SDKv2 provider.
	plan.ID = types.StringValue(hash(fmt.Sprintf("%+v", grant)))
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *grantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.normalize()

	grant, err := grantFromModel(state, false)
	if err != nil {
		resp.Diagnostics.AddError("Invalid grant in state", err.Error())
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	exists, err := grantExists(session, grant)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read grant", err.Error())
		return
	}
	if !exists {
		tflog.Warn(ctx, "grant no longer exists, removing it from state", map[string]interface{}{"id": state.ID.ValueString()})
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update is never called with changes: every argument requires replacement.
func (r *grantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *grantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.normalize()

	grant, err := grantFromModel(state, false)
	if err != nil {
		resp.Diagnostics.AddError("Invalid grant in state", err.Error())
		return
	}
	query, err := render(templateDelete, grant)
	if err != nil {
		resp.Diagnostics.AddError("Unable to render grant", err.Error())
		return
	}

	session := r.session(&resp.Diagnostics)
	if session == nil {
		return
	}
	defer session.Close()

	if err := session.Query(query).Exec(); err != nil {
		resp.Diagnostics.AddError("Unable to delete grant", err.Error())
	}
}

// regexpValidator checks that a value compiles as a regular expression.
type regexpValidator struct{}

func (regexpValidator) Description(context.Context) string {
	return "value must be a valid regular expression"
}

func (v regexpValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (regexpValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := regexp.Compile(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid mbean pattern", fmt.Sprintf("%s is not a valid pattern: %s", req.ConfigValue.ValueString(), err))
	}
}
