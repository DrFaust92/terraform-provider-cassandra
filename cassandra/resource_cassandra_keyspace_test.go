package cassandra

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccCassandraKeyspace_basic(t *testing.T) {
	keyspace := "some_keyspace"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCassandraKeyspaceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraKeyspaceConfigBasic(keyspace),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraKeyspaceExists("cassandra_keyspace.keyspace"),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "name", keyspace),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "replication_strategy", "SimpleStrategy"),
					resource.TestCheckResourceAttr("cassandra_keyspace.keyspace", "strategy_options.replication_factor", "1"),
				),
			},
			{
				ResourceName:      "cassandra_keyspace.keyspace",
				ImportStateId:     keyspace,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCassandraKeyspace_broken(t *testing.T) {
	keyspace := "some_keyspace"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCassandraKeyspaceDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccCassandraKeyspaceConfigBroken(keyspace),
				ExpectError: regexp.MustCompile("Unrecognized strategy option"),
			},
		},
	})
}

func testAccCassandraKeyspaceConfigBasic(keyspace string) string {
	return fmt.Sprintf(`
resource "cassandra_keyspace" "keyspace" {
    name                 = "%s"
    replication_strategy = "SimpleStrategy"
    strategy_options     = {
      replication_factor = 1
    }
}
`, keyspace)
}

func testAccCassandraKeyspaceConfigBroken(keyspace string) string {
	return fmt.Sprintf(`
resource "cassandra_keyspace" "keyspace" {
    name                 = "%s"
    replication_strategy = "SimpleStrategy"
    strategy_options     = {
      datacenter1 = 1
    }
}
`, keyspace)
}

func testAccCassandraKeyspaceDestroy(s *terraform.State) error {
	cluster := testAccProvider.Meta().(*gocql.ClusterConfig)
	session, sessionCreateError := cluster.CreateSession()

	if sessionCreateError != nil {
		return sessionCreateError
	}

	defer session.Close()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "cassandra_keyspace" {
			continue
		}

		keyspace := rs.Primary.Attributes["name"]

		_, err := session.KeyspaceMetadata(keyspace)

		if err == gocql.ErrKeyspaceDoesNotExist {
			return nil
		}

		return fmt.Errorf("keyspace %s stil exists", keyspace)
	}
	return nil
}

func testAccCassandraKeyspaceExists(resourceKey string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceKey]

		if !ok {
			return fmt.Errorf("not found: %s", resourceKey)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("no ID is set")
		}

		cluster := testAccProvider.Meta().(*gocql.ClusterConfig)

		session, sessionCreateError := cluster.CreateSession()

		if sessionCreateError != nil {
			return sessionCreateError
		}

		_, err := session.KeyspaceMetadata(rs.Primary.ID)

		if err != nil {
			return err
		}

		return nil
	}
}
