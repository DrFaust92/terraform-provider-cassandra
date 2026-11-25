package cassandra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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

var _ provider.Provider = &cassandraProvider{}

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
			},
			"root_ca": schema.StringAttribute{
				Optional:    true,
				Description: "PEM-encoded root CA used to verify the cluster certificate. Applies only when `use_ssl` is `true`.",
				Validators:  []validator.String{pemValidator{}},
			},
			"use_ssl": schema.BoolAttribute{
				Optional:    true,
				Description: "Use TLS when connecting to the cluster.",
			},
			"min_tls_version": schema.StringAttribute{
				Optional:    true,
				Description: "Minimum TLS version used to connect to the cluster: one of `TLS1.0`, `TLS1.1`, `TLS1.2`, `TLS1.3`. Defaults to `TLS1.2`. Applies only when `use_ssl` is `true`.",
				Validators:  []validator.String{stringvalidator.OneOf("TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")},
			},
			"protocol_version": schema.Int64Attribute{
				Optional:    true,
				Description: "CQL binary protocol version. Defaults to `4`.",
			},
			"consistency": schema.StringAttribute{
				Optional:    true,
				Description: "Default consistency level for queries. Defaults to `QUORUM`.",
			},
			"cql_version": schema.StringAttribute{
				Optional:    true,
				Description: "CQL version. Defaults to `3.0.0`.",
			},
			"keyspace": schema.StringAttribute{
				Optional:    true,
				Description: "Initial keyspace for the connection.",
			},
			"disable_initial_host_lookup": schema.BoolAttribute{
				Optional:    true,
				Description: "Do not look up the other nodes in the `system.peers` table; connect only to the configured hosts.",
			},
		},
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
	if config.Host.IsUnknown() || config.Hosts.IsUnknown() || config.Username.IsUnknown() || config.Password.IsUnknown() || config.Port.IsUnknown() {
		resp.Diagnostics.AddWarning("Unknown provider configuration", "The Cassandra provider configuration depends on values that are not known yet, so it cannot connect during this plan.")
		return
	}

	cluster, err := clusterConfig(ctx, config)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Cassandra provider configuration", err.Error())
		return
	}

	resp.ResourceData = cluster
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
	cluster.Timeout = time.Minute
	cluster.CQLVersion = stringOr(config.CQLVersion, "3.0.0")
	cluster.Keyspace = config.Keyspace.ValueString()
	cluster.Consistency = consistency
	cluster.ProtoVersion = int(int64Or(config.ProtocolVersion, 4))
	cluster.DisableInitialHostLookup = config.DisableInitialHostLookup.ValueBool()

	if config.HostFilter.ValueBool() {
		filter, err := whiteListHostFilter(hosts)
		if err != nil {
			return nil, err
		}
		cluster.HostFilter = filter
	}

	if config.UseSSL.ValueBool() {
		tlsConfig := &tls.Config{
			MinVersion: allowedTLSProtocols[stringOr(config.MinTLSVersion, "TLS1.2")],
		}

		if rootCA := config.RootCA.ValueString(); rootCA != "" {
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM([]byte(rootCA)) {
				return nil, fmt.Errorf("root_ca: unable to load the PEM certificate")
			}
			tlsConfig.RootCAs = caPool
		}

		cluster.SslOpts = &gocql.SslOptions{Config: tlsConfig}
	}

	tflog.Debug(ctx, "configured Cassandra cluster", map[string]interface{}{"hosts": hosts, "port": port, "ssl": config.UseSSL.ValueBool()})

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
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid PEM", "root_ca is not a valid PEM-encoded certificate")
	}
}

// clusterFromProviderData returns the cluster configuration passed to resources by Configure.
func clusterFromProviderData(data any) (*gocql.ClusterConfig, error) {
	if data == nil {
		return nil, nil
	}
	cluster, ok := data.(*gocql.ClusterConfig)
	if !ok {
		return nil, fmt.Errorf("unexpected provider data type %T", data)
	}
	return cluster, nil
}
