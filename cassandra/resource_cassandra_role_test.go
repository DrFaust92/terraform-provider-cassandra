package cassandra

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// testAccRolePassword satisfies the 40-512 character password validation.
const testAccRolePassword = "sup3rS3cr3tPassw0rd-for-acceptance-tests-only"

func TestAccCassandraRole_basic(t *testing.T) {
	name := "user"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraRoleConfigBasic(name),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraRoleExists("cassandra_role.user"),
					resource.TestCheckResourceAttr("cassandra_role.user", "name", name),
					resource.TestCheckResourceAttr("cassandra_role.user", "password", testAccRolePassword),
				),
			},
		},
	})
}

func TestAccCassandraRole_invalid(t *testing.T) {
	name := "invalid\\\"name"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccCassandraRoleConfigBasic(name),
				ExpectError: regexp.MustCompile("name must contain between 1 and 256 chars and must not contain double quote"),
			},
		},
	})
}

// A single quote in the password must be escaped in the CREATE ROLE statement.
func TestAccCassandraRole_quotedPassword(t *testing.T) {
	password := testAccRolePassword + "-it's-quoted"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cassandra_role" "user" {
    name     = "quoted"
    password = %q
}
`, password),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraRoleExists("cassandra_role.user"),
					resource.TestCheckResourceAttr("cassandra_role.user", "password", password),
				),
			},
		},
	})
}

func testAccCassandraRoleConfigBasic(name string) string {
	return fmt.Sprintf(`
resource "cassandra_role" "user" {
    name     = "%s"
    password = "%s"
}
`, name, testAccRolePassword)
}

func testAccCassandraRoleDestroy(s *terraform.State) error {
	cluster := testAccProvider.Meta().(*gocql.ClusterConfig)
	session, sessionCreateError := cluster.CreateSession()

	if sessionCreateError != nil {
		return sessionCreateError
	}

	defer session.Close()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "cassandra_role" {
			continue
		}

		name := rs.Primary.Attributes["name"]

		_, _, _, _, err := readRole(session, name)

		if err != nil {
			return nil
		}

		return fmt.Errorf("role %s stil exists", name)
	}
	return nil
}

func testAccCassandraRoleExists(resourceKey string) resource.TestCheckFunc {
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

		_, _, _, _, err := readRole(session, rs.Primary.ID)

		if err != nil {
			return err
		}

		return nil
	}
}
