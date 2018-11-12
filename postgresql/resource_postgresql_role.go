package postgresql

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/lib/pq"
	"github.com/pkg/errors"
)

const (
	roleBypassRLSAttr         = "bypass_row_level_security"
	roleConnLimitAttr         = "connection_limit"
	roleCreateDBAttr          = "create_database"
	roleCreateRoleAttr        = "create_role"
	roleEncryptedPassAttr     = "encrypted_password"
	roleInheritAttr           = "inherit"
	roleLoginAttr             = "login"
	roleNameAttr              = "name"
	rolePasswordAttr          = "password"
	roleReplicationAttr       = "replication"
	roleSkipDropRoleAttr      = "skip_drop_role"
	roleSkipReassignOwnedAttr = "skip_reassign_owned"
	roleSuperuserAttr         = "superuser"
	roleValidUntilAttr        = "valid_until"
	roleRolesAttr             = "roles"

	// Deprecated options
	roleDepEncryptedAttr = "encrypted"
)

func resourcePostgreSQLRole() *schema.Resource {
	return &schema.Resource{
		Create: resourcePostgreSQLRoleCreate,
		Read:   resourcePostgreSQLRoleRead,
		Update: resourcePostgreSQLRoleUpdate,
		Delete: resourcePostgreSQLRoleDelete,
		Exists: resourcePostgreSQLRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			roleNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the role",
			},
			rolePasswordAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("PGPASSWORD", nil),
				Description: "Sets the role's password",
			},
			roleDepEncryptedAttr: {
				Type:       schema.TypeString,
				Optional:   true,
				Deprecated: fmt.Sprintf("Rename PostgreSQL role resource attribute %q to %q", roleDepEncryptedAttr, roleEncryptedPassAttr),
			},
			roleRolesAttr: {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				MinItems:    0,
				Description: "Role(s) to grant to this new role",
			},
			roleEncryptedPassAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Control whether the password is stored encrypted in the system catalogs",
			},
			roleValidUntilAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "infinity",
				Description: "Sets a date and time after which the role's password is no longer valid",
			},
			roleConnLimitAttr: {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      -1,
				Description:  "How many concurrent connections can be made with this role",
				ValidateFunc: validateConnLimit,
			},
			roleSuperuserAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: `Determine whether the new role is a "superuser"`,
			},
			roleCreateDBAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Define a role's ability to create databases",
			},
			roleCreateRoleAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determine whether this role will be permitted to create new roles",
			},
			roleInheritAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: `Determine whether a role "inherits" the privileges of roles it is a member of`,
			},
			roleLoginAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determine whether a role is allowed to log in",
			},
			roleReplicationAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determine whether a role is allowed to initiate streaming replication or put the system in and out of backup mode",
			},
			roleBypassRLSAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determine whether a role bypasses every row-level security (RLS) policy",
			},
			roleSkipDropRoleAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Skip actually running the DROP ROLE command when removing a ROLE from PostgreSQL",
			},
			roleSkipReassignOwnedAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Skip actually running the REASSIGN OWNED command when removing a role from PostgreSQL",
			},
		},
	}
}

func resourcePostgreSQLRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)
	txn, err := startTransaction(client, "")
	if err != nil {
		return err
	}
	defer txn.Rollback()

	stringOpts := []struct {
		hclKey string
		sqlKey string
	}{
		{rolePasswordAttr, "PASSWORD"},
		{roleValidUntilAttr, "VALID UNTIL"},
	}
	intOpts := []struct {
		hclKey string
		sqlKey string
	}{
		{roleConnLimitAttr, "CONNECTION LIMIT"},
	}

	type boolOptType struct {
		hclKey        string
		sqlKeyEnable  string
		sqlKeyDisable string
	}
	boolOpts := []boolOptType{
		{roleSuperuserAttr, "CREATEDB", "NOCREATEDB"},
		{roleCreateRoleAttr, "CREATEROLE", "NOCREATEROLE"},
		{roleInheritAttr, "INHERIT", "NOINHERIT"},
		{roleLoginAttr, "LOGIN", "NOLOGIN"},
		{roleReplicationAttr, "REPLICATION", "NOREPLICATION"},

		// roleEncryptedPassAttr is used only when rolePasswordAttr is set.
		// {roleEncryptedPassAttr, "ENCRYPTED", "UNENCRYPTED"},
	}

	if client.featureSupported(featureRLS) {
		boolOpts = append(boolOpts, boolOptType{roleBypassRLSAttr, "BYPASSRLS", "NOBYPASSRLS"})
	}

	createOpts := make([]string, 0, len(stringOpts)+len(intOpts)+len(boolOpts))

	for _, opt := range stringOpts {
		v, ok := d.GetOk(opt.hclKey)
		if !ok {
			continue
		}

		val := v.(string)
		if val != "" {
			switch {
			case opt.hclKey == rolePasswordAttr:
				if strings.ToUpper(v.(string)) == "NULL" {
					createOpts = append(createOpts, "PASSWORD NULL")
				} else {
					if d.Get(roleEncryptedPassAttr).(bool) {
						createOpts = append(createOpts, "ENCRYPTED")
					} else {
						createOpts = append(createOpts, "UNENCRYPTED")
					}
					createOpts = append(createOpts, fmt.Sprintf("%s '%s'", opt.sqlKey, pqQuoteLiteral(val)))
				}
			case opt.hclKey == roleValidUntilAttr:
				switch {
				case v.(string) == "", strings.ToLower(v.(string)) == "infinity":
					createOpts = append(createOpts, fmt.Sprintf("%s '%s'", opt.sqlKey, "infinity"))
				default:
					createOpts = append(createOpts, fmt.Sprintf("%s %s", opt.sqlKey, pq.QuoteIdentifier(val)))
				}
			default:
				createOpts = append(createOpts, fmt.Sprintf("%s %s", opt.sqlKey, pq.QuoteIdentifier(val)))
			}
		}
	}

	for _, opt := range intOpts {
		val := d.Get(opt.hclKey).(int)
		createOpts = append(createOpts, fmt.Sprintf("%s %d", opt.sqlKey, val))
	}

	for _, opt := range boolOpts {
		if opt.hclKey == roleEncryptedPassAttr {
			// This attribute is handled above in the stringOpts
			// loop.
			continue
		}
		val := d.Get(opt.hclKey).(bool)
		valStr := opt.sqlKeyDisable
		if val {
			valStr = opt.sqlKeyEnable
		}
		createOpts = append(createOpts, valStr)
	}

	roleName := d.Get(roleNameAttr).(string)
	createStr := strings.Join(createOpts, " ")
	if len(createOpts) > 0 {
		if client.featureSupported(featureCreateRoleWith) {
			createStr = " WITH " + createStr
		} else {
			// NOTE(seanc@): Work around ParAccel/AWS RedShift's ancient fork of PostgreSQL
			createStr = " " + createStr
		}
	}

	sql := fmt.Sprintf("CREATE ROLE %s%s", pq.QuoteIdentifier(roleName), createStr)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrapf(err, "error creating role %s", roleName)
	}

	if err = grantRoles(txn, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return errors.Wrap(err, "could not commit transaction")
	}

	d.SetId(roleName)

	txn, err = startTransaction(client, "")
	if err != nil {
		return err
	}
	defer txn.Rollback()

	return resourcePostgreSQLRoleReadImpl(client, txn, d)
}

func resourcePostgreSQLRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)
	txn, err := startTransaction(client, "")
	if err != nil {
		return err
	}
	defer txn.Rollback()

	roleName := d.Get(roleNameAttr).(string)

	queries := make([]string, 0, 3)
	if !d.Get(roleSkipReassignOwnedAttr).(bool) {
		if client.featureSupported(featureReassignOwnedCurrentUser) {
			queries = append(queries, fmt.Sprintf(
				"REASSIGN OWNED BY %s TO CURRENT_USER", pq.QuoteIdentifier(roleName),
			))
		} else {
			queries = append(queries, fmt.Sprintf(
				"REASSIGN OWNED BY %s TO %s",
				pq.QuoteIdentifier(roleName), pq.QuoteIdentifier(client.config.Username),
			))
		}
		queries = append(queries, fmt.Sprintf("DROP OWNED BY %s", pq.QuoteIdentifier(roleName)))
	}

	if !d.Get(roleSkipDropRoleAttr).(bool) {
		queries = append(queries, fmt.Sprintf("DROP ROLE %s", pq.QuoteIdentifier(roleName)))
	}

	if len(queries) > 0 {
		for _, query := range queries {
			if _, err := txn.Exec(query); err != nil {
				return errors.Wrap(err, "Error deleting role")
			}
		}
		if err = txn.Commit(); err != nil {
			return errors.Wrap(err, "could not commit transaction")
		}
	}

	d.SetId("")

	return nil
}

func resourcePostgreSQLRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	txn, err := startTransaction(meta.(*Client), "")
	if err != nil {
		return false, err
	}
	defer txn.Rollback()

	return roleExists(txn, d.Id())
}

func resourcePostgreSQLRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)
	txn, err := startTransaction(client, "")
	if err != nil {
		return err
	}
	defer txn.Rollback()

	return resourcePostgreSQLRoleReadImpl(client, txn, d)
}

func resourcePostgreSQLRoleReadImpl(client *Client, txn *sql.Tx, d *schema.ResourceData) error {
	roleID := d.Id()

	var roleSuperuser, roleInherit, roleCreateRole, roleCreateDB, roleCanLogin, roleReplication bool
	var roleConnLimit int
	var roleName, roleValidUntil string
	var roleRoles pq.ByteaArray

	columns := []string{
		"rolname",
		"rolsuper",
		"rolinherit",
		"rolcreaterole",
		"rolcreatedb",
		"rolcanlogin",
		"rolreplication",
		"rolconnlimit",
		`COALESCE(rolvaliduntil::TEXT, 'infinity')`,
	}

	roleSQL := fmt.Sprintf(`SELECT %s, array_remove(array_agg(roles.role_name::text), NULL)
		FROM pg_catalog.pg_roles LEFT JOIN information_schema.applicable_roles roles ON rolname = roles.grantee
		WHERE rolname=$1
		GROUP BY %s`,
		// select columns
		strings.Join(columns, ", "),
		// group by columns
		strings.Join(columns, ", "),
	)
	err := txn.QueryRow(roleSQL, roleID).Scan(
		&roleName,
		&roleSuperuser,
		&roleInherit,
		&roleCreateRole,
		&roleCreateDB,
		&roleCanLogin,
		&roleReplication,
		&roleConnLimit,
		&roleValidUntil,
		&roleRoles,
	)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL ROLE (%s) not found", roleID)
		d.SetId("")
		return nil
	case err != nil:
		return errors.Wrap(err, "error reading ROLE")
	}

	d.Set(roleNameAttr, roleName)
	d.Set(roleConnLimitAttr, roleConnLimit)
	d.Set(roleCreateDBAttr, roleCreateDB)
	d.Set(roleCreateRoleAttr, roleCreateRole)
	d.Set(roleEncryptedPassAttr, true)
	d.Set(roleInheritAttr, roleInherit)
	d.Set(roleLoginAttr, roleCanLogin)
	d.Set(roleReplicationAttr, roleReplication)
	d.Set(roleSkipDropRoleAttr, d.Get(roleSkipDropRoleAttr).(bool))
	d.Set(roleSkipReassignOwnedAttr, d.Get(roleSkipReassignOwnedAttr).(bool))
	d.Set(roleSuperuserAttr, roleSuperuser)
	d.Set(roleValidUntilAttr, roleValidUntil)
	d.Set(roleRolesAttr, pgArrayToSet(roleRoles))

	if client.featureSupported(featureRLS) {
		var roleBypassRLS bool
		roleSQL := "SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=$1"
		err = txn.QueryRow(roleSQL, roleID).Scan(&roleBypassRLS)
		if err != nil {
			return errors.Wrap(err, "Error reading RLS properties for ROLE")
		}
		d.Set(roleBypassRLSAttr, roleBypassRLS)
	}

	d.SetId(roleName)

	if !roleSuperuser {
		// Return early if not superuser user
		return nil
	}

	var rolePassword string
	err = txn.QueryRow("SELECT COALESCE(passwd, '') FROM pg_catalog.pg_shadow AS s WHERE s.usename = $1", roleID).Scan(&rolePassword)
	switch {
	case err == sql.ErrNoRows:
		return errors.Wrapf(err, "PostgreSQL role (%s) not found in shadow database: {{err}}", roleID)
	case err != nil:
		return errors.Wrap(err, "Error reading role")
	}

	d.Set(rolePasswordAttr, rolePassword)
	return nil
}

func resourcePostgreSQLRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)

	txn, err := startTransaction(client, "")
	if err != nil {
		return err
	}
	defer txn.Rollback()

	if err := setRoleName(txn, d); err != nil {
		return err
	}

	if err := setRoleBypassRLS(client, txn, d); err != nil {
		return err
	}

	if err := setRoleConnLimit(txn, d); err != nil {
		return err
	}

	if err := setRoleCreateDB(txn, d); err != nil {
		return err
	}

	if err := setRoleCreateRole(txn, d); err != nil {
		return err
	}

	if err := setRoleInherit(txn, d); err != nil {
		return err
	}

	if err := setRoleLogin(txn, d); err != nil {
		return err
	}

	if err := setRoleReplication(txn, d); err != nil {
		return err
	}

	if err := setRoleSuperuser(txn, d); err != nil {
		return err
	}

	if err := setRoleValidUntil(txn, d); err != nil {
		return err
	}

	// applying roles: let's revoke all / granted right ones
	if err = revokeRoles(txn, d); err != nil {
		return err
	}

	if err = grantRoles(txn, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return errors.Wrap(err, "could not commit transaction")
	}

	txn, err = startTransaction(client, "")
	if err != nil {
		return err
	}
	defer txn.Rollback()

	return resourcePostgreSQLRoleReadImpl(client, txn, d)
}

func setRoleName(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleNameAttr) {
		return nil
	}

	oraw, nraw := d.GetChange(roleNameAttr)
	o := oraw.(string)
	n := nraw.(string)
	if n == "" {
		return errors.New("Error setting role name to an empty string")
	}

	sql := fmt.Sprintf("ALTER ROLE %s RENAME TO %s", pq.QuoteIdentifier(o), pq.QuoteIdentifier(n))
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role NAME")
	}

	d.SetId(n)

	return nil
}

func setRoleBypassRLS(c *Client, txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleBypassRLSAttr) {
		return nil
	}

	if !c.featureSupported(featureRLS) {
		return fmt.Errorf("PostgreSQL client is talking with a server (%q) that does not support PostgreSQL Row-Level Security", c.version.String())
	}

	bypassRLS := d.Get(roleBypassRLSAttr).(bool)
	tok := "NOBYPASSRLS"
	if bypassRLS {
		tok = "BYPASSRLS"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role BYPASSRLS")
	}

	return nil
}

func setRoleConnLimit(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleConnLimitAttr) {
		return nil
	}

	connLimit := d.Get(roleConnLimitAttr).(int)
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s CONNECTION LIMIT %d", pq.QuoteIdentifier(roleName), connLimit)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role CONNECTION LIMIT")
	}

	return nil
}

func setRoleCreateDB(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleCreateDBAttr) {
		return nil
	}

	createDB := d.Get(roleCreateDBAttr).(bool)
	tok := "NOCREATEDB"
	if createDB {
		tok = "CREATEDB"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role CREATEDB")
	}

	return nil
}

func setRoleCreateRole(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleCreateRoleAttr) {
		return nil
	}

	createRole := d.Get(roleCreateRoleAttr).(bool)
	tok := "NOCREATEROLE"
	if createRole {
		tok = "CREATEROLE"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role CREATEROLE")
	}

	return nil
}

func setRoleInherit(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleInheritAttr) {
		return nil
	}

	inherit := d.Get(roleInheritAttr).(bool)
	tok := "NOINHERIT"
	if inherit {
		tok = "INHERIT"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role INHERIT")
	}

	return nil
}

func setRoleLogin(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleLoginAttr) {
		return nil
	}

	login := d.Get(roleLoginAttr).(bool)
	tok := "NOLOGIN"
	if login {
		tok = "LOGIN"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role LOGIN")
	}

	return nil
}

func setRoleReplication(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleReplicationAttr) {
		return nil
	}

	replication := d.Get(roleReplicationAttr).(bool)
	tok := "NOREPLICATION"
	if replication {
		tok = "REPLICATION"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role REPLICATION")
	}

	return nil
}

func setRoleSuperuser(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleSuperuserAttr) {
		return nil
	}

	superuser := d.Get(roleSuperuserAttr).(bool)
	tok := "NOSUPERUSER"
	if superuser {
		tok = "SUPERUSER"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role SUPERUSER")
	}

	return nil
}

func setRoleValidUntil(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleValidUntilAttr) {
		return nil
	}

	validUntil := d.Get(roleValidUntilAttr).(string)
	if validUntil == "" {
		return nil
	} else if strings.ToLower(validUntil) == "infinity" {
		validUntil = "infinity"
	}

	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s VALID UNTIL '%s'", pq.QuoteIdentifier(roleName), pqQuoteLiteral(validUntil))
	if _, err := txn.Exec(sql); err != nil {
		return errors.Wrap(err, "Error updating role VALID UNTIL")
	}

	return nil
}

func revokeRoles(txn *sql.Tx, d *schema.ResourceData) error {
	role := d.Get(roleNameAttr).(string)

	query := `SELECT array_remove(array_agg(role_name::text), NULL)
FROM information_schema.applicable_roles
WHERE grantee = $1`

	var grantedRoles pq.ByteaArray
	if err := txn.QueryRow(query, role).Scan(&grantedRoles); err != nil {
		return errors.Wrapf(err, "could not get roles list for role %s", role)
	}

	for _, grantedRole := range grantedRoles {
		query = fmt.Sprintf(
			"REVOKE %s FROM %s", pq.QuoteIdentifier(string(grantedRole)), pq.QuoteIdentifier(role),
		)
		log.Printf("[DEBUG] revoking role %s from %s", string(grantedRole), role)
		if _, err := txn.Exec(query); err != nil {
			return errors.Wrapf(err, "could not revoke role %s from %s", string(grantedRole), role)
		}
	}

	return nil
}

func grantRoles(txn *sql.Tx, d *schema.ResourceData) error {
	role := d.Get(roleNameAttr).(string)

	for _, grantingRole := range d.Get("roles").(*schema.Set).List() {
		query := fmt.Sprintf(
			"GRANT %s TO %s", pq.QuoteIdentifier(grantingRole.(string)), pq.QuoteIdentifier(role),
		)
		if _, err := txn.Exec(query); err != nil {
			return errors.Wrapf(err, "could not grant role %s to %s", grantingRole, role)
		}
	}
	return nil
}
