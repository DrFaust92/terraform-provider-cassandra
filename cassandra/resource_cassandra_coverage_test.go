package cassandra

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccCassandraRole_update(t *testing.T) {
	newPassword := testAccRolePassword + "-rotated"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraRoleConfigFull("update_role", testAccRolePassword, true, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraRoleExists("cassandra_role.user"),
					resource.TestCheckResourceAttr("cassandra_role.user", "login", "true"),
					resource.TestCheckResourceAttr("cassandra_role.user", "super_user", "false"),
				),
			},
			{
				// Changing the password right after creation hits Cassandra 5's
				// credentials_update_interval; the provider retries until it passes.
				Config: testAccCassandraRoleConfigFull("update_role", newPassword, false, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraRoleExists("cassandra_role.user"),
					resource.TestCheckResourceAttr("cassandra_role.user", "login", "false"),
					resource.TestCheckResourceAttr("cassandra_role.user", "super_user", "true"),
					resource.TestCheckResourceAttr("cassandra_role.user", "password", newPassword),
				),
			},
		},
	})
}

// Changing only login/super_user must not resend the password, so it works
// straight after the role is created.
func TestAccCassandraRole_updateWithoutPassword(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraRoleConfigFull("update_login_role", testAccRolePassword, true, false),
			},
			{
				Config: testAccCassandraRoleConfigFull("update_login_role", testAccRolePassword, false, false),
				Check:  resource.TestCheckResourceAttr("cassandra_role.user", "login", "false"),
			},
		},
	})
}

func TestAccCassandraRole_import(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraRoleConfigFull("import_role", testAccRolePassword, true, false),
			},
			{
				ResourceName:      "cassandra_role.user",
				ImportState:       true,
				ImportStateVerify: true,
				// Cassandra only stores a salted hash of the password.
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

// A role dropped outside Terraform must be planned for re-creation, not fail
// the refresh.
func TestAccCassandraRole_disappears(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraRoleConfigFull("gone_role", testAccRolePassword, true, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraRoleExists("cassandra_role.user"),
					testAccCassandraExec(`DROP ROLE 'gone_role'`),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCassandraKeyspace_update(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraKeyspaceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraKeyspaceConfigFull("update_ks", "SimpleStrategy", `replication_factor = 1`, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraKeyspaceExists("cassandra_keyspace.keyspace"),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "durable_writes", "true"),
				),
			},
			{
				Config: testAccCassandraKeyspaceConfigFull("update_ks", "SimpleStrategy", `replication_factor = 2`, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraKeyspaceExists("cassandra_keyspace.keyspace"),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "durable_writes", "false"),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "strategy_options.replication_factor", "2"),
				),
			},
			{
				Config: testAccCassandraKeyspaceConfigFull("update_ks", "NetworkTopologyStrategy", `datacenter1 = 1`, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraKeyspaceExists("cassandra_keyspace.keyspace"),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "replication_strategy", "NetworkTopologyStrategy"),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "strategy_options.datacenter1", "1"),
				),
			},
			{
				ResourceName:      "cassandra_keyspace.keyspace",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// A keyspace dropped outside Terraform must be planned for re-creation.
func TestAccCassandraKeyspace_disappears(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraKeyspaceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraKeyspaceConfigFull("gone_ks", "SimpleStrategy", `replication_factor = 1`, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraKeyspaceExists("cassandra_keyspace.keyspace"),
					testAccCassandraExec(`DROP KEYSPACE gone_ks`),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCassandraRoleConfigFull(name, password string, login, superUser bool) string {
	return fmt.Sprintf(`
resource "cassandra_role" "user" {
    name       = %q
    password   = %q
    login      = %t
    super_user = %t
}
`, name, password, login, superUser)
}

func testAccCassandraKeyspaceConfigFull(name, strategy, options string, durableWrites bool) string {
	return fmt.Sprintf(`
resource "cassandra_keyspace" "keyspace" {
    name                 = %q
    replication_strategy = %q
    strategy_options     = {
      %s
    }
    durable_writes       = %t
}
`, name, strategy, options, durableWrites)
}

// testAccCassandraExec runs a CQL statement outside Terraform.
func testAccCassandraExec(cql string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		session, err := testAccCluster().CreateSession()
		if err != nil {
			return err
		}
		defer session.Close()
		return session.Query(cql).Exec()
	}
}
