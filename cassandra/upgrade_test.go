package cassandra

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// lastSDKv2Release is the last release built on terraform-plugin-sdk/v2.
const lastSDKv2Release = "1.3.0"

// testAccUpgradeSteps applies config with the last SDKv2 release, then
// requires the framework provider to plan no changes for the same state.
func testAccUpgradeSteps(config string) []resource.TestStep {
	return []resource.TestStep{
		{
			ExternalProviders: map[string]resource.ExternalProvider{
				"cassandra": {
					Source:            "DrFaust92/cassandra",
					VersionConstraint: lastSDKv2Release,
				},
			},
			Config: config,
		},
		{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Config:                   config,
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		},
	}
}

func TestAccCassandraKeyspace_upgradeFromSDKv2(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCassandraKeyspaceDestroy,
		Steps: testAccUpgradeSteps(`
resource "cassandra_keyspace" "simple" {
  name                 = "upgrade_simple"
  replication_strategy = "SimpleStrategy"
  strategy_options = {
    replication_factor = 1
  }
}

resource "cassandra_keyspace" "nts" {
  name                 = "upgrade_nts"
  replication_strategy = "NetworkTopologyStrategy"
  strategy_options = {
    datacenter1 = 1
  }
  durable_writes = false
}
`),
	})
}

func TestAccCassandraRole_upgradeFromSDKv2(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCassandraRoleDestroy,
		Steps: testAccUpgradeSteps(fmt.Sprintf(`
resource "cassandra_role" "defaults" {
  name     = "upgrade_defaults"
  password = %[1]q
}

resource "cassandra_role" "explicit" {
  name       = "upgrade_explicit"
  password   = %[1]q
  login      = false
  super_user = true

  timeouts {
    default = "2m"
  }
}
`, testAccRolePassword)),
	})
}

func TestAccCassandraGrant_upgradeFromSDKv2(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCassandraGrantDestroy,
		Steps: testAccUpgradeSteps(testAccCassandraGrantConfig("upgrade_grantee", `
    privilege     = "select"
    resource_type = "keyspace"
    keyspace_name = cassandra_keyspace.ks.name
`) + fmt.Sprintf(`
resource "cassandra_role" "target" {
  name     = "upgrade_target"
  password = %q
}

resource "cassandra_grant" "on_role" {
  privilege     = "alter"
  resource_type = "role"
  role_name     = cassandra_role.target.name
  grantee       = cassandra_role.grantee.name
}

resource "cassandra_grant" "all_keyspaces" {
  privilege     = "modify"
  resource_type = "all keyspaces"
  grantee       = cassandra_role.grantee.name
}
`, testAccRolePassword)),
	})
}
