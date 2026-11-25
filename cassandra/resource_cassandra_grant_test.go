package cassandra

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccCassandraGrant_keyspace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraGrantDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraGrantConfig("grant_ks_role", `
    privilege     = "select"
    resource_type = "keyspace"
    keyspace_name = cassandra_keyspace.ks.name
`),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraGrantExists("cassandra_grant.grant"),
					resource.TestCheckResourceAttr("cassandra_grant.grant", "privilege", "select"),
					resource.TestCheckResourceAttr("cassandra_grant.grant", "resource_type", "keyspace"),
					resource.TestCheckResourceAttr("cassandra_grant.grant", "keyspace_name", "grant_test_ks"),
					resource.TestCheckResourceAttr("cassandra_grant.grant", "grantee", "grant_ks_role"),
				),
			},
		},
	})
}

func TestAccCassandraGrant_allKeyspaces(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraGrantDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraGrantConfig("grant_all_ks_role", `
    privilege     = "modify"
    resource_type = "all keyspaces"
`),
				Check: testAccCassandraGrantExists("cassandra_grant.grant"),
			},
		},
	})
}

func TestAccCassandraGrant_role(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraGrantDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraGrantConfig("grant_role_role", `
    privilege     = "alter"
    resource_type = "role"
    role_name     = cassandra_role.target.name
`) + fmt.Sprintf(`
resource "cassandra_role" "target" {
    name     = "grant_role_target"
    password = %q
}
`, testAccRolePassword),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraGrantExists("cassandra_grant.grant"),
					resource.TestCheckResourceAttr("cassandra_grant.grant", "role_name", "grant_role_target"),
				),
			},
		},
	})
}

// A grantee name with characters that html/template would escape must reach
// Cassandra unchanged.
func TestAccCassandraGrant_granteeSpecialCharacters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraGrantDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraGrantConfig("app&ops<1>", `
    privilege     = "select"
    resource_type = "keyspace"
    keyspace_name = cassandra_keyspace.ks.name
`),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraGrantExists("cassandra_grant.grant"),
					resource.TestCheckResourceAttr("cassandra_grant.grant", "grantee", "app&ops<1>"),
				),
			},
		},
	})
}

// A grant revoked outside Terraform must be planned for re-creation, not fail
// the refresh.
func TestAccCassandraGrant_disappears(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCassandraGrantDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraGrantConfig("grant_gone_role", `
    privilege     = "select"
    resource_type = "keyspace"
    keyspace_name = cassandra_keyspace.ks.name
`),
				Check: resource.ComposeTestCheckFunc(
					testAccCassandraGrantExists("cassandra_grant.grant"),
					testAccCassandraGrantRevoke("cassandra_grant.grant"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCassandraGrant_invalidResourceForPrivilege(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCassandraGrantConfig("grant_invalid_role", `
    privilege     = "select"
    resource_type = "all roles"
`),
				ExpectError: regexp.MustCompile("all roles resource not applicable for privilege select"),
			},
		},
	})
}

// testAccCassandraGrantConfig creates a keyspace and a role named grantee and
// a cassandra_grant.grant to that role with the given grant arguments.
func testAccCassandraGrantConfig(grantee, grantArgs string) string {
	return fmt.Sprintf(`
resource "cassandra_keyspace" "ks" {
    name                 = "grant_test_ks"
    replication_strategy = "SimpleStrategy"
    strategy_options     = {
      replication_factor = 1
    }
}

resource "cassandra_role" "grantee" {
    name     = %q
    password = %q
}

resource "cassandra_grant" "grant" {
    grantee = cassandra_role.grantee.name
%s
}
`, grantee, testAccRolePassword, grantArgs)
}

// testAccGrantFromState rebuilds the Grant from state attributes, mirroring parseData.
func testAccGrantFromState(rs *terraform.ResourceState) *Grant {
	a := rs.Primary.Attributes
	resourceType := a[identifierResourceType]
	grant := &Grant{
		Privilege:    a[identifierPrivilege],
		ResourceType: resourceType,
		Grantee:      a[identifierGrantee],
	}
	for _, r := range resourcesThatRequireKeyspaceQualifier {
		if r == resourceType {
			grant.Keyspace = a[identifierKeyspaceName]
		}
	}
	if key := resourceTypeToIdentifier[resourceType]; key != "" {
		grant.Identifier = a[key]
	}
	return grant
}

// testAccGrantRows runs LIST ... OF grantee and returns the number of rows.
func testAccGrantRows(session *gocql.Session, grant *Grant) (int, error) {
	var buffer bytes.Buffer
	if err := templateRead.Execute(&buffer, grant); err != nil {
		return 0, err
	}
	iter := session.Query(buffer.String()).Iter()
	rows := iter.NumRows()
	return rows, iter.Close()
}

func testAccCassandraGrantExists(resourceKey string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceKey]
		if !ok {
			return fmt.Errorf("not found: %s", resourceKey)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("no ID is set")
		}

		session, err := testAccCluster().CreateSession()
		if err != nil {
			return err
		}
		defer session.Close()

		grant := testAccGrantFromState(rs)
		rows, err := testAccGrantRows(session, grant)
		if err != nil {
			return err
		}
		if rows == 0 {
			return fmt.Errorf("grant %+v not found in Cassandra", grant)
		}
		return nil
	}
}

func testAccCassandraGrantRevoke(resourceKey string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceKey]
		if !ok {
			return fmt.Errorf("not found: %s", resourceKey)
		}

		session, err := testAccCluster().CreateSession()
		if err != nil {
			return err
		}
		defer session.Close()

		var buffer bytes.Buffer
		if err := templateDelete.Execute(&buffer, testAccGrantFromState(rs)); err != nil {
			return err
		}
		return session.Query(buffer.String()).Exec()
	}
}

func testAccCassandraGrantDestroy(s *terraform.State) error {
	session, err := testAccCluster().CreateSession()
	if err != nil {
		return err
	}
	defer session.Close()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "cassandra_grant" {
			continue
		}

		grant := testAccGrantFromState(rs)
		rows, err := testAccGrantRows(session, grant)
		if err != nil {
			// The grantee role is destroyed with the grant, and listing the
			// permissions of a role that no longer exists is an error.
			if strings.Contains(err.Error(), "doesn't exist") {
				continue
			}
			return err
		}
		if rows > 0 {
			return fmt.Errorf("grant %+v still exists", grant)
		}
	}
	return nil
}
