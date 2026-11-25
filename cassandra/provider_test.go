package cassandra

import (
	"context"
	"os"
	"testing"

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

	t.Run("no host", func(t *testing.T) {
		t.Setenv("CASSANDRA_HOST", "")
		if _, err := clusterConfig(ctx, providerModel{Hosts: types.ListNull(types.StringType)}); err == nil {
			t.Fatal("expected an error without host or hosts")
		}
	})
}
