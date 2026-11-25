package cassandra

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestAccCassandraRole_passwordWO(t *testing.T) {
	first := testAccRolePassword + "-wo-1"
	second := testAccRolePassword + "-wo-2"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		CheckDestroy:             testAccCassandraRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraRoleConfigWO("wo_role", first, "1"),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraRoleExists("cassandra_role.user"),
					resource.TestCheckNoResourceAttr("cassandra_role.user", "password"),
					resource.TestCheckNoResourceAttr("cassandra_role.user", "password_wo"),
					resource.TestCheckResourceAttr("cassandra_role.user", "password_wo_version", "1"),
					testAccCassandraRoleCanLogin("wo_role", first, true),
				),
			},
			{
				// A changed password_wo alone is not detected...
				Config: testAccCassandraRoleConfigWO("wo_role", second, "1"),
				Check:  testAccCassandraRoleCanLogin("wo_role", first, true),
			},
			{
				// ...bumping password_wo_version sends it.
				Config: testAccCassandraRoleConfigWO("wo_role", second, "2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraRoleCanLogin("wo_role", second, true),
					testAccCassandraRoleCanLogin("wo_role", first, false),
				),
			},
			{
				ResourceName:            "cassandra_role.user",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password", "password_wo_version"},
			},
		},
	})
}

func TestAccCassandraRole_passwordAndPasswordWOConflict(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cassandra_role" "user" {
  name                = "wo_conflict"
  password            = %[1]q
  password_wo         = %[1]q
  password_wo_version = "1"
}
`, testAccRolePassword),
				ExpectError: regexp.MustCompile(`(?s)password.*password_wo`),
			},
			{
				Config: `
resource "cassandra_role" "user" {
  name = "wo_missing"
}
`,
				ExpectError: regexp.MustCompile(`(?s)password.*password_wo`),
			},
		},
	})
}

func testAccCassandraRoleConfigWO(name, password, version string) string {
	return fmt.Sprintf(`
resource "cassandra_role" "user" {
  name                = %q
  password_wo         = %q
  password_wo_version = %q
}
`, name, password, version)
}

// testAccCassandraRoleCanLogin checks whether the role can open a session
// with the given password.
func testAccCassandraRoleCanLogin(name, password string, want bool) resource.TestCheckFunc {
	return func(*terraform.State) error {
		cluster := *testAccCluster()
		cluster.Authenticator = &gocql.PasswordAuthenticator{Username: name, Password: password}
		session, err := cluster.CreateSession()
		if err == nil {
			session.Close()
		}
		if got := err == nil; got != want {
			return fmt.Errorf("login as %s: got success=%t, want %t (err: %v)", name, got, want, err)
		}
		return nil
	}
}
