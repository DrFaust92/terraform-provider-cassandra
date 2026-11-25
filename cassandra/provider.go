package cassandra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/providervalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	allowedTLSProtocols = map[string]uint16{
		"TLS1.0": tls.VersionTLS10,
		"TLS1.1": tls.VersionTLS11,
		"TLS1.2": tls.VersionTLS12,
		"TLS1.3": tls.VersionTLS13,
	}

	allowedConsistencies = map[string]gocql.Consistency{
		"ANY":          gocql.Any,
		"ONE":          gocql.One,
		"TWO":          gocql.Two,
		"THREE":        gocql.Three,
		"QUORUM":       gocql.Quorum,
		"ALL":          gocql.All,
		"LOCAL_QUORUM": gocql.LocalQuorum,
		"EACH_QUORUM":  gocql.EachQuorum,
		"LOCAL_ONE":    gocql.LocalOne,
	}
)

var (
	_ provider.Provider                     = &cassandraProvider{}
	_ provider.ProviderWithConfigValidators = &cassandraProvider{}
)

type cassandraProvider struct {
	version string
}

// New returns a constructor for the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &cassandraProvider{version: version}
	}
}

type providerModel struct {
	Username                 types.String `tfsdk:"username"`
	Password                 types.String `tfsdk:"password"`
	Port                     types.Int64  `tfsdk:"port"`
	Host                     types.String `tfsdk:"host"`
	Hosts                    types.List   `tfsdk:"hosts"`
	HostFilter               types.Bool   `tfsdk:"host_filter"`
	ConnectionTimeout        types.Int64  `tfsdk:"connection_timeout"`
	RootCA                   types.String `tfsdk:"root_ca"`
	UseSSL                   types.Bool   `tfsdk:"use_ssl"`
	MinTLSVersion            types.String `tfsdk:"min_tls_version"`
	ProtocolVersion          types.Int64  `tfsdk:"protocol_version"`
	Consistency              types.String `tfsdk:"consistency"`
	CQLVersion               types.String `tfsdk:"cql_version"`
	Keyspace                 types.String `tfsdk:"keyspace"`
	DisableInitialHostLookup types.Bool   `tfsdk:"disable_initial_host_lookup"`
	ClientCertificate        types.String `tfsdk:"client_certificate"`
	ClientKey                types.String `tfsdk:"client_key"`
	LocalDC                  types.String `tfsdk:"local_dc"`
	QueryTimeout             types.Int64  `tfsdk:"query_timeout"`
}

func (p *cassandraProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cassandra"
	resp.Version = p.version
}

func (p *cassandraProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Apache Cassandra keyspaces, roles and grants.",
		Attributes: map[string]schema.Attribute{
			"username": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Cassandra client username. Can also be set with the `CASSANDRA_USERNAME` environment variable.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Cassandra client password. Can also be set with the `CASSANDRA_PASSWORD` environment variable.",
			},
			"port": schema.Int64Attribute{
				Optional:    true,
				Description: "Cassandra CQL port. Can also be set with the `CASSANDRA_PORT` environment variable. Defaults to `9042`.",
				Validators:  []validator.Int64{int64validator.Between(1, 65535)},
			},
			"host": schema.StringAttribute{
				Optional:    true,
				Description: "Host of a node in the Cassandra cluster. Can also be set with the `CASSANDRA_HOST` environment variable. Conflicts with `hosts`.",
				Validators:  []validator.String{stringvalidator.ConflictsWith(path.MatchRoot("hosts"))},
			},
			"hosts": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Hosts of nodes in the Cassandra cluster.",
				Validators:  []validator.List{listvalidator.SizeAtLeast(1)},
			},
			"host_filter": schema.BoolAttribute{
				Optional:    true,
				Description: "Only connect to the configured hosts, ignoring other nodes the driver discovers. The hosts must exist before the provider is used.",
			},
			"connection_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "Connection timeout to the cluster, in milliseconds. Defaults to `1000`.",
				Validators:  []validator.Int64{int64validator.AtLeast(1)},
			},
			"root_ca": schema.StringAttribute{
				Optional:    true,
				Description: "PEM-encoded root CA used to verify the cluster certificate, instead of the system roots. Can also be set with the `CASSANDRA_ROOT_CA` environment variable. Applies only when `use_ssl` is `true`.",
				Validators:  []validator.String{pemValidator{}},
			},
			"use_ssl": schema.BoolAttribute{
				Optional:    true,
				Description: "Use TLS when connecting to the cluster. Can also be set with the `CASSANDRA_USE_SSL` environment variable.",
			},
			"min_tls_version": schema.StringAttribute{
				Optional:    true,
				Description: "Minimum TLS version used to connect to the cluster: one of `TLS1.0`, `TLS1.1`, `TLS1.2`, `TLS1.3`. Defaults to `TLS1.2`. Applies only when `use_ssl` is `true`.",
				Validators:  []validator.String{stringvalidator.OneOf("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")},
			},
			"protocol_version": schema.Int64Attribute{
				Optional:    true,
				Description: "CQL binary protocol version, `3` to `5`. Defaults to `4`.",
				Validators:  []validator.Int64{int64validator.Between(3, 5)},
			},
			"consistency": schema.StringAttribute{
				Optional:    true,
				Description: "Default consistency level for queries: one of `ANY`, `ONE`, `TWO`, `THREE`, `QUORUM`, `ALL`, `LOCAL_QUORUM`, `EACH_QUORUM`, `LOCAL_ONE`. Defaults to `QUORUM`.",
				Validators:  []validator.String{stringvalidator.OneOf("ANY", "ONE", "TWO", "THREE", "QUORUM", "ALL", "LOCAL_QUORUM", "EACH_QUORUM", "LOCAL_ONE")},
			},
			"cql_version": schema.StringAttribute{
				Optional:    true,
				Description: "CQL version. Defaults to `3.0.0`.",
			},
			"keyspace": schema.StringAttribute{
				Optional:    true,
				Description: "Initial keyspace for the connection.",
			},
			"client_certificate": schema.StringAttribute{
				Optional:    true,
				Description: "PEM-encoded client certificate, for clusters that require TLS client authentication (`require_client_auth`). Set it together with `client_key`, both in the configuration or both in environment variables. Can also be set with the `CASSANDRA_CLIENT_CERTIFICATE` environment variable. Applies only when `use_ssl` is `true`.",
				Validators:  []validator.String{pemValidator{}},
			},
			"client_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "PEM-encoded private key of `client_certificate`. Can also be set with the `CASSANDRA_CLIENT_KEY` environment variable.",
			},
			"local_dc": schema.StringAttribute{
				Optional:    true,
				Description: "Data center to send queries to, for multi-DC clusters. Queries go to nodes in this data center first, and to other data centers only when none are available; use it with the `LOCAL_*` consistency levels. Can also be set with the `CASSANDRA_LOCAL_DC` environment variable. By default queries are spread over all data centers.",
			},
			"query_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "Timeout of each query, in milliseconds. Defaults to `60000`.",
				Validators:  []validator.Int64{int64validator.AtLeast(1)},
			},
			"disable_initial_host_lookup": schema.BoolAttribute{
				Optional:    true,
				Description: "Do not look up the other nodes in the `system.peers` table; connect only to the configured hosts.",
			},
		},
	}
}

func (p *cassandraProvider) ConfigValidators(context.Context) []provider.ConfigValidator {
	return []provider.ConfigValidator{
		providervalidator.RequiredTogether(path.MatchRoot("client_certificate"), path.MatchRoot("client_key")),
	}
}

func (p *cassandraProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Unknown values (e.g. from resources not yet created) cannot configure a
	// connection; resources will fail with a clear error if they are used.
	for _, v := range []interface{ IsUnknown() bool }{
		config.Host, config.Hosts, config.Username, config.Password, config.Port,
		config.RootCA, config.UseSSL, config.ClientCertificate, config.ClientKey, config.LocalDC,
	} {
		if v.IsUnknown() {
			resp.Diagnostics.AddWarning("Unknown provider configuration", "The Cassandra provider configuration depends on values that are not known yet, so it cannot connect during this plan.")
			return
		}
	}

	cluster, err := clusterConfig(ctx, config)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Cassandra provider configuration", err.Error())
		return
	}

	resp.ResourceData = &connection{
		cluster: cluster,
		localDC: stringOrEnv(config.LocalDC, "CASSANDRA_LOCAL_DC", ""),
	}
}

func (p *cassandraProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newKeyspaceResource,
		newRoleResource,
		newGrantResource,
	}
}

func (p *cassandraProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func stringOrEnv(v types.String, env, def string) string {
	if !v.IsNull() && v.ValueString() != "" {
		return v.ValueString()
	}
	if e := os.Getenv(env); e != "" {
		return e
	}
	return def
}

func stringOr(v types.String, def string) string {
	if v.IsNull() {
		return def
	}
	return v.ValueString()
}

func int64Or(v types.Int64, def int64) int64 {
	if v.IsNull() {
		return def
	}
	return v.ValueInt64()
}

// clusterConfig builds the gocql cluster configuration from the provider
// configuration, falling back to the CASSANDRA_* environment variables.
func clusterConfig(ctx context.Context, config providerModel) (*gocql.ClusterConfig, error) {
	port := int64(9042)
	if !config.Port.IsNull() {
		port = config.Port.ValueInt64()
	} else if e := os.Getenv("CASSANDRA_PORT"); e != "" {
		p, err := strconv.ParseInt(e, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("CASSANDRA_PORT: %w", err)
		}
		port = p
	}

	var hosts []string
	if !config.Hosts.IsNull() {
		for _, h := range config.Hosts.Elements() {
			hosts = append(hosts, h.(types.String).ValueString())
		}
	}
	if len(hosts) == 0 {
		host := stringOrEnv(config.Host, "CASSANDRA_HOST", "")
		if host == "" {
			return nil, fmt.Errorf("one of host or hosts must be set (or the CASSANDRA_HOST environment variable)")
		}
		hosts = []string{host}
	}

	consistencyName := stringOr(config.Consistency, gocql.Quorum.String())
	consistency, ok := allowedConsistencies[consistencyName]
	if !ok {
		return nil, fmt.Errorf("consistency %q is not one of ANY, ONE, TWO, THREE, QUORUM, ALL, LOCAL_QUORUM, EACH_QUORUM, LOCAL_ONE", consistencyName)
	}

	cluster := gocql.NewCluster(hosts...)
	cluster.Port = int(port)
	cluster.Authenticator = &gocql.PasswordAuthenticator{
		Username: stringOrEnv(config.Username, "CASSANDRA_USERNAME", ""),
		Password: stringOrEnv(config.Password, "CASSANDRA_PASSWORD", ""),
	}
	cluster.ConnectTimeout = time.Duration(int64Or(config.ConnectionTimeout, 1000)) * time.Millisecond
	cluster.Timeout = time.Duration(int64Or(config.QueryTimeout, 60000)) * time.Millisecond
	cluster.CQLVersion = stringOr(config.CQLVersion, "3.0.0")
	cluster.Keyspace = config.Keyspace.ValueString()
	cluster.Consistency = consistency
	cluster.ProtoVersion = int(int64Or(config.ProtocolVersion, 4))
	cluster.DisableInitialHostLookup = config.DisableInitialHostLookup.ValueBool()

	if dc := stringOrEnv(config.LocalDC, "CASSANDRA_LOCAL_DC", ""); dc != "" {
		// Token awareness sends each query to a replica in the local data
		// center; other data centers are used only when it has no nodes up.
		cluster.PoolConfig.HostSelectionPolicy = gocql.TokenAwareHostPolicy(gocql.DCAwareRoundRobinPolicy(dc))
	}

	if config.HostFilter.ValueBool() {
		filter, err := whiteListHostFilter(hosts)
		if err != nil {
			return nil, err
		}
		cluster.HostFilter = filter
	}

	useSSL := config.UseSSL.ValueBool()
	if config.UseSSL.IsNull() {
		if e := os.Getenv("CASSANDRA_USE_SSL"); e != "" {
			b, err := strconv.ParseBool(e)
			if err != nil {
				return nil, fmt.Errorf("CASSANDRA_USE_SSL: %w", err)
			}
			useSSL = b
		}
	}

	if useSSL {
		tlsConfig := &tls.Config{
			MinVersion: allowedTLSProtocols[stringOr(config.MinTLSVersion, "TLS1.2")],
		}

		if rootCA := stringOrEnv(config.RootCA, "CASSANDRA_ROOT_CA", ""); rootCA != "" {
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM([]byte(rootCA)) {
				return nil, fmt.Errorf("root_ca: unable to load the PEM certificate")
			}
			tlsConfig.RootCAs = caPool
		}

		clientCert := stringOrEnv(config.ClientCertificate, "CASSANDRA_CLIENT_CERTIFICATE", "")
		clientKey := stringOrEnv(config.ClientKey, "CASSANDRA_CLIENT_KEY", "")
		if (clientCert == "") != (clientKey == "") {
			return nil, fmt.Errorf("client_certificate and client_key must be set together")
		}
		if clientCert != "" {
			pair, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
			if err != nil {
				return nil, fmt.Errorf("client_certificate and client_key: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		}

		cluster.SslOpts = &gocql.SslOptions{Config: tlsConfig}
	}

	tflog.Debug(ctx, "configured Cassandra cluster", map[string]interface{}{"hosts": hosts, "port": port, "ssl": useSSL})

	return cluster, nil
}

// whiteListHostFilter wraps gocql.WhiteListHostFilter, which panics when a
// host cannot be resolved, and returns that as an error instead.
func whiteListHostFilter(hosts []string) (filter gocql.HostFilter, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("host_filter: %v", r)
		}
	}()
	return gocql.WhiteListHostFilter(hosts...), nil
}

// pemValidator checks that a non-empty value is a PEM-encoded certificate.
type pemValidator struct{}

func (pemValidator) Description(context.Context) string {
	return "value must be a PEM-encoded certificate"
}

func (v pemValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (pemValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() == "" {
		return
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(req.ConfigValue.ValueString())) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid PEM", "The value is not a valid PEM-encoded certificate.")
	}
}

// connection is the provider data passed to resources by Configure.
type connection struct {
	cluster *gocql.ClusterConfig
	localDC string

	mu        sync.Mutex
	dcChecked bool
}

// connectionFromProviderData returns the connection passed to resources by Configure.
func connectionFromProviderData(data any) (*connection, error) {
	if data == nil {
		return nil, nil
	}
	conn, ok := data.(*connection)
	if !ok {
		return nil, fmt.Errorf("unexpected provider data type %T", data)
	}
	return conn, nil
}

// checkLocalDC verifies once per provider instance that local_dc names a data
// center of the cluster. The driver would otherwise send every query to the
// other data centers without an error. A failed check is retried by the next
// session.
func (c *connection) checkLocalDC(session *gocql.Session) error {
	if c.localDC == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dcChecked {
		return nil
	}

	dcs, err := clusterDataCenters(session)
	if err != nil {
		return fmt.Errorf("checking local_dc: %w", err)
	}
	if !slices.Contains(dcs, c.localDC) {
		return fmt.Errorf("local_dc %q is not a data center of the cluster, which has: %s", c.localDC, strings.Join(dcs, ", "))
	}
	c.dcChecked = true
	return nil
}

// clusterDataCenters returns the sorted data center names of the cluster.
func clusterDataCenters(session *gocql.Session) ([]string, error) {
	var dc string
	if err := session.Query(`SELECT data_center FROM system.local`).Scan(&dc); err != nil {
		return nil, err
	}
	dcs := []string{dc}

	iter := session.Query(`SELECT data_center FROM system.peers`).Iter()
	for iter.Scan(&dc) {
		if !slices.Contains(dcs, dc) {
			dcs = append(dcs, dc)
		}
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	slices.Sort(dcs)
	return dcs, nil
}
