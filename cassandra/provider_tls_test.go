package cassandra

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccCertsDir returns the directory written by `make testacc_certs`, or
// skips the test when the TLS test certificates are not available.
func testAccCertsDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("CASSANDRA_TEST_CERTS")
	if dir == "" {
		t.Skip("CASSANDRA_TEST_CERTS is not set; run `make testacc_setup` to start Cassandra with TLS")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Skipf("TLS test certificates not found: %v", err)
	}
	return dir
}

// The test cluster requires a client certificate on TLS connections. With
// one, the provider manages resources over TLS.
func TestAccCassandraProvider_clientCertificate(t *testing.T) {
	dir := testAccCertsDir(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderTLSConfig(dir, true) + `
resource "cassandra_keyspace" "tls" {
  name                 = "tls_keyspace"
  replication_strategy = "SimpleStrategy"
  strategy_options = {
    replication_factor = 1
  }
}
`,
				Check: resource.TestCheckResourceAttr("cassandra_keyspace.tls", "id", "tls_keyspace"),
			},
		},
	})
}

// Without a client certificate the cluster rejects the TLS connection.
func TestAccCassandraProvider_clientCertificateRequired(t *testing.T) {
	dir := testAccCertsDir(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderTLSConfig(dir, false) + `
resource "cassandra_keyspace" "tls" {
  name                 = "tls_rejected_keyspace"
  replication_strategy = "SimpleStrategy"
  strategy_options = {
    replication_factor = 1
  }
}
`,
				ExpectError: regexp.MustCompile(`Unable to connect to Cassandra`),
			},
		},
	})
}

func testAccProviderTLSConfig(dir string, withClientCert bool) string {
	clientCert := ""
	if withClientCert {
		clientCert = fmt.Sprintf(`
  client_certificate = file(%[1]q)
  client_key         = file(%[2]q)`, filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem"))
	}
	return fmt.Sprintf(`
provider "cassandra" {
  use_ssl       = true
  root_ca       = file(%[1]q)
  local_dc      = "datacenter1"
  query_timeout = 30000%[2]s
}
`, filepath.Join(dir, "ca.pem"), clientCert)
}
