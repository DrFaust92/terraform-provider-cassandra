package cassandra

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"golang.org/x/crypto/bcrypt"
)

func resourceCassandraRole() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a Cassandra role.",
		CreateContext: resourceRoleCreate,
		ReadContext:   resourceRoleRead,
		UpdateContext: resourceRoleUpdate,
		DeleteContext: resourceRoleDelete,
		Timeouts: &schema.ResourceTimeout{
			Default: schema.DefaultTimeout(1 * time.Minute),
		},
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				Description:  "Name of the role, 1 to 256 characters with no double quotes.",
				ValidateFunc: validation.StringMatch(regexp.MustCompile(`^[^"]{1,256}$`), "name must contain between 1 and 256 chars and must not contain double quote character"),
			},
			"super_user": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    false,
				Description: "Allow the role to create and manage other roles. Defaults to `false`.",
			},
			"login": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    false,
				Description: "Allow the role to log in. Defaults to `true`.",
			},
			"password": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     false,
				Description:  "Password for the role when using Cassandra internal authentication, 40 to 512 characters.",
				Sensitive:    true,
				ValidateFunc: validation.StringLenBetween(40, 512),
			},
		},
	}
}

func readRole(session *gocql.Session, name string) (string, bool, bool, string, error) {

	var (
		role        string
		canLogin    bool
		isSuperUser bool
		saltedHash  string
	)

	iter := session.Query(`select role, can_login, is_superuser, salted_hash from system_auth.roles where role = ?`, name).Iter()

	defer iter.Close()

	log.Printf("read role query returned %d", iter.NumRows())

	for iter.Scan(&role, &canLogin, &isSuperUser, &saltedHash) {
		return role, canLogin, isSuperUser, saltedHash, nil
	}

	if err := iter.Close(); err != nil {
		return "", false, false, "", err
	}

	return "", false, false, "", fmt.Errorf("cannot read role with name %s: %w", name, errRoleNotFound)
}

// errRoleNotFound is returned by readRole when the role does not exist.
var errRoleNotFound = errors.New("role not found")

func resourceRoleCreateOrUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}, createRole bool) diag.Diagnostics {
	name := d.Get("name").(string)
	superUser := d.Get("super_user").(bool)
	login := d.Get("login").(bool)
	password := d.Get("password").(string)
	var diags diag.Diagnostics

	cluster := meta.(*gocql.ClusterConfig)
	start := time.Now()
	session, sessionCreateError := cluster.CreateSession()
	elapsed := time.Since(start)

	log.Printf("Getting a session took %s", elapsed)

	if sessionCreateError != nil {
		return diag.FromErr(sessionCreateError)
	}

	defer session.Close()

	options := fmt.Sprintf(`LOGIN = %v AND SUPERUSER = %v`, login, superUser)
	// Only send the password when it is set or changed: Cassandra 5 rejects a
	// password change within credentials_update_interval of the previous one.
	if createRole || d.HasChange("password") {
		options = fmt.Sprintf(`PASSWORD = '%s' AND %s`, cqlEscape(password), options)
	}
	query := fmt.Sprintf(`%s ROLE '%s' WITH %s`, boolToAction[createRole], cqlEscape(name), options)

	createErr := retry.RetryContext(ctx, d.Timeout(schema.TimeoutDefault), func() *retry.RetryError {
		err := session.Query(query).Exec()
		if err != nil && strings.Contains(err.Error(), "can only be changed every") {
			log.Printf("[DEBUG] password change for role %s throttled, retrying: %s", name, err)
			return retry.RetryableError(err)
		}
		if err != nil {
			return retry.NonRetryableError(err)
		}
		return nil
	})
	if createErr != nil {
		return diag.FromErr(createErr)
	}

	d.SetId(name)
	d.Set("name", name)
	d.Set("super_user", superUser)
	d.Set("login", login)
	d.Set("password", password)

	diags = append(diags, resourceRoleRead(ctx, d, meta)...)

	return diags
}

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return resourceRoleCreateOrUpdate(ctx, d, meta, true)
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	name := d.Id()
	password := d.Get("password").(string)
	var diags diag.Diagnostics

	cluster := meta.(*gocql.ClusterConfig)
	start := time.Now()
	session, sessionCreateError := cluster.CreateSession()
	elapsed := time.Since(start)

	log.Printf("Getting a session took %s", elapsed)

	if sessionCreateError != nil {
		return diag.FromErr(sessionCreateError)
	}

	defer session.Close()
	_name, login, superUser, saltedHash, readRoleErr := readRole(session, name)

	if errors.Is(readRoleErr, errRoleNotFound) {
		log.Printf("[WARN] role %s no longer exists, removing it from state", name)
		d.SetId("")
		return diags
	}
	if readRoleErr != nil {
		return diag.FromErr(readRoleErr)
	}

	result := bcrypt.CompareHashAndPassword([]byte(saltedHash), []byte(password))

	d.SetId(_name)
	d.Set("name", _name)
	d.Set("super_user", superUser)
	d.Set("login", login)

	if result == nil {
		d.Set("password", password)
	} else {
		// password has changed between runs
		d.Set("password", saltedHash)
	}

	return diags
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	name := d.Get("name").(string)
	var diags diag.Diagnostics

	cluster := meta.(*gocql.ClusterConfig)
	start := time.Now()
	session, sessionCreateError := cluster.CreateSession()
	elapsed := time.Since(start)

	log.Printf("Getting a session took %s", elapsed)

	if sessionCreateError != nil {
		return diag.FromErr(sessionCreateError)
	}

	defer session.Close()

	err := session.Query(fmt.Sprintf(`DROP ROLE '%s'`, cqlEscape(name))).Exec()
	if err != nil {
		diag.FromErr(err)
	}

	return diags
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return resourceRoleCreateOrUpdate(ctx, d, meta, false)
}

// cqlEscape escapes a value for use inside a single-quoted CQL string literal.
func cqlEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
