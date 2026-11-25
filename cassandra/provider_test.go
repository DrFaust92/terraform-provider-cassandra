package cassandra

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"cassandra": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	if os.Getenv("CASSANDRA_HOST") == "" {
		t.Fatal("CASSANDRA_HOST must be set for acceptance tests")
	}
}

// testAccCluster returns a cluster configuration built from the CASSANDRA_*
// environment variables, for checks that talk to Cassandra directly.
func testAccCluster() *gocql.ClusterConfig {
	cluster, err := clusterConfig(context.Background(), providerModel{
		Hosts: types.ListNull(types.StringType),
	})
	if err != nil {
		panic(err)
	}
	return cluster
}

func TestProvider_schema(t *testing.T) {
	ctx := context.Background()
	p := New("test")()

	var resp provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema: %v", resp.Diagnostics)
	}
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("provider schema: %v", diags)
	}
}

func TestClusterConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("host", func(t *testing.T) {
		cluster, err := clusterConfig(ctx, providerModel{
			Host:     types.StringValue("asdf"),
			Hosts:    types.ListNull(types.StringType),
			Port:     types.Int64Value(9042),
			Username: types.StringValue("cassandra"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(cluster.Hosts) != 1 || cluster.Hosts[0] != "asdf" {
			t.Fatalf("hosts = %v, want [asdf]", cluster.Hosts)
		}
		if cluster.Consistency != gocql.Quorum || cluster.ProtoVersion != 4 || cluster.CQLVersion != "3.0.0" {
			t.Fatalf("defaults not applied: %+v", cluster)
		}
	})

	t.Run("hosts", func(t *testing.T) {
		hosts, _ := types.ListValueFrom(ctx, types.StringType, []string{"127.0.0.1", "localhost"})
		cluster, err := clusterConfig(ctx, providerModel{Hosts: hosts, HostFilter: types.BoolValue(true)})
		if err != nil {
			t.Fatal(err)
		}
		if len(cluster.Hosts) != 2 || cluster.Hosts[0] != "127.0.0.1" {
			t.Fatalf("hosts = %v, want [127.0.0.1 localhost] with no empty entries", cluster.Hosts)
		}
	})

	t.Run("host_filter with an unresolvable host", func(t *testing.T) {
		hosts, _ := types.ListValueFrom(ctx, types.StringType, []string{"does-not-resolve.invalid"})
		if _, err := clusterConfig(ctx, providerModel{Hosts: hosts, HostFilter: types.BoolValue(true)}); err == nil {
			t.Fatal("expected an error, not a panic")
		}
	})

	t.Run("local_dc and query_timeout", func(t *testing.T) {
		cluster, err := clusterConfig(ctx, providerModel{
			Host:         types.StringValue("127.0.0.1"),
			Hosts:        types.ListNull(types.StringType),
			LocalDC:      types.StringValue("dc1"),
			QueryTimeout: types.Int64Value(5000),
		})
		if err != nil {
			t.Fatal(err)
		}
		if cluster.PoolConfig.HostSelectionPolicy == nil {
			t.Fatal("local_dc did not set a host selection policy")
		}
		if cluster.Timeout != 5*time.Second {
			t.Fatalf("query timeout = %s, want 5s", cluster.Timeout)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		t.Setenv("CASSANDRA_LOCAL_DC", "")
		cluster, err := clusterConfig(ctx, providerModel{Host: types.StringValue("127.0.0.1"), Hosts: types.ListNull(types.StringType)})
		if err != nil {
			t.Fatal(err)
		}
		if cluster.PoolConfig.HostSelectionPolicy != nil {
			t.Fatal("no local_dc: expected the driver's default host selection policy")
		}
		if cluster.Timeout != time.Minute {
			t.Fatalf("query timeout = %s, want 1m", cluster.Timeout)
		}
		if cluster.SslOpts != nil {
			t.Fatal("TLS enabled without use_ssl")
		}
	})

	t.Run("CASSANDRA_USE_SSL and CASSANDRA_LOCAL_DC", func(t *testing.T) {
		t.Setenv("CASSANDRA_USE_SSL", "true")
		t.Setenv("CASSANDRA_LOCAL_DC", "dc1")
		cluster, err := clusterConfig(ctx, providerModel{Host: types.StringValue("127.0.0.1"), Hosts: types.ListNull(types.StringType)})
		if err != nil {
			t.Fatal(err)
		}
		if cluster.SslOpts == nil || cluster.SslOpts.MinVersion != tls.VersionTLS12 {
			t.Fatalf("CASSANDRA_USE_SSL=true: SslOpts = %+v", cluster.SslOpts)
		}
		if cluster.PoolConfig.HostSelectionPolicy == nil {
			t.Fatal("CASSANDRA_LOCAL_DC did not set a host selection policy")
		}

		t.Setenv("CASSANDRA_USE_SSL", "yes please")
		if _, err := clusterConfig(ctx, providerModel{Host: types.StringValue("127.0.0.1"), Hosts: types.ListNull(types.StringType)}); err == nil {
			t.Fatal("expected an error for an invalid CASSANDRA_USE_SSL")
		}
	})

	t.Run("client certificate without key", func(t *testing.T) {
		_, err := clusterConfig(ctx, providerModel{
			Host:              types.StringValue("127.0.0.1"),
			Hosts:             types.ListNull(types.StringType),
			UseSSL:            types.BoolValue(true),
			ClientCertificate: types.StringValue("-----BEGIN CERTIFICATE-----"),
		})
		if err == nil || !strings.Contains(err.Error(), "must be set together") {
			t.Fatalf("expected a pairing error, got %v", err)
		}
	})

	t.Run("mismatched client certificate and key", func(t *testing.T) {
		_, err := clusterConfig(ctx, providerModel{
			Host:              types.StringValue("127.0.0.1"),
			Hosts:             types.ListNull(types.StringType),
			UseSSL:            types.BoolValue(true),
			ClientCertificate: types.StringValue("not a certificate"),
			ClientKey:         types.StringValue("not a key"),
		})
		if err == nil || !strings.Contains(err.Error(), "client_certificate and client_key") {
			t.Fatalf("expected a key pair error, got %v", err)
		}
	})

	t.Run("no host", func(t *testing.T) {
		t.Setenv("CASSANDRA_HOST", "")
		if _, err := clusterConfig(ctx, providerModel{Hosts: types.ListNull(types.StringType)}); err == nil {
			t.Fatal("expected an error without host or hosts")
		}
	})
}
