package postgresql

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/pkg/errors"
	// Use Postgres as SQL driver
	"github.com/lib/pq"
)

// TODO: manage global default privileges (no schema)
func resourcePostgreSQLDefaultPrivileges() *schema.Resource {
	return &schema.Resource{
		Create: resourcePostgreSQLDefaultPrivilegesCreate,
		Update: resourcePostgreSQLDefaultPrivilegesCreate,
		Read:   resourcePostgreSQLDefaultPrivilegesRead,
		Delete: resourcePostgreSQLDefaultPrivilegesDelete,

		Schema: map[string]*schema.Schema{
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the role to which grant default privileges",
			},
			"database": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The database on which grant default privileges for this role",
			},
			"owner": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Role for which apply default privileges (You can change default privileges only for objects that will be created by yourself or by roles that you are a member of)",
			},
			"schema": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"object_type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"table",
					"sequence",
				}, false),
			},
			"privileges": &schema.Schema{
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
				MinItems: 1,
			},
		},
	}
}

func resourcePostgreSQLDefaultPrivilegesRead(d *schema.ResourceData, meta interface{}) error {

	client := meta.(*Client)
	exists, err := checkRoleDBSchemaExists(client, d)
	if err != nil {
		return err
	}
	if !exists {
		d.SetId("")
		return nil
	}

	txn, err := startTransaction(client, d.Get("database").(string))
	if err != nil {
		return err
	}
	defer txn.Rollback()

	return readRoleDefaultPrivileges(txn, d)
}

func resourcePostgreSQLDefaultPrivilegesCreate(d *schema.ResourceData, meta interface{}) error {
	if err := validatePrivileges(d.Get("object_type").(string), d.Get("privileges").(*schema.Set).List()); err != nil {
		return err
	}

	client := meta.(*Client)
	role := d.Get("role").(string)
	database := d.Get("database").(string)
	schema := d.Get("schema").(string)

	txn, err := startTransaction(client, database)
	if err != nil {
		return err
	}
	defer txn.Rollback()

	// Revoke all privileges before granting otherwise reducing privileges will not work.
	// We just have to revoke them in the same transaction so role will not lost his privileges between revoke and grant.
	if err = revokeRoleDefaultPrivileges(txn, d); err != nil {
		return err
	}

	if err = grantRoleDefaultPrivileges(txn, d); err != nil {
		return err
	}

	if err := txn.Commit(); err != nil {
		return err
	}

	d.SetId(fmt.Sprintf("%s-%s-%s", role, database, schema))

	txn, err = startTransaction(client, d.Get("database").(string))
	if err != nil {
		return err
	}
	defer txn.Rollback()

	return readRoleDefaultPrivileges(txn, d)
}

func resourcePostgreSQLDefaultPrivilegesDelete(d *schema.ResourceData, meta interface{}) error {
	txn, err := startTransaction(meta.(*Client), d.Get("database").(string))
	if err != nil {
		return err
	}
	defer txn.Rollback()

	revokeRoleDefaultPrivileges(txn, d)
	if err := txn.Commit(); err != nil {
		return err
	}

	return nil
}

func readRoleDefaultPrivileges(txn *sql.Tx, d *schema.ResourceData) error {
	role := d.Get("role").(string)
	pgSchema := d.Get("schema").(string)

	query := `SELECT array_agg(prtype) FROM (
		SELECT defaclnamespace, (aclexplode(defaclacl)).* FROM pg_default_acl
	) AS t (namespace, grantor_oid, grantee_oid, prtype, grantable)

	JOIN pg_roles ON grantee_oid = pg_roles.oid 
	JOIN pg_namespace ON pg_namespace.oid = namespace 

	WHERE rolname = $1 AND nspname = $2;
`
	var privileges pq.ByteaArray

	if err := txn.QueryRow(query, role, pgSchema).Scan(&privileges); err != nil {
		return errors.Wrap(err, "could not read default privileges")
	}

	// We consider no privileges as "not exists"
	if len(privileges) == 0 {
		log.Printf("[DEBUG] no default privileges for role %s in schema %s", role, pgSchema)
		d.SetId("")
		return nil
	}

	privilegesSet := pgArrayToSet(privileges)
	d.Set("privileges", privilegesSet)

	return nil
}

func grantRoleDefaultPrivileges(txn *sql.Tx, d *schema.ResourceData) error {
	role := d.Get("role").(string)
	database := d.Get("database").(string)
	pgSchema := d.Get("schema").(string)

	privileges := []string{}
	for _, priv := range d.Get("privileges").(*schema.Set).List() {
		privileges = append(privileges, priv.(string))
	}

	// TODO: We grant default privileges for the DB owner
	// For that we need to be either superuser or a member of the owner role.
	// For RDS it will not be the case so the solution may be to grant the owner role
	// to the connected user

	query := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s ON %sS TO %s",
		pq.QuoteIdentifier(d.Get("owner").(string)),
		pq.QuoteIdentifier(pgSchema),
		strings.Join(privileges, ","),
		strings.ToUpper(d.Get("object_type").(string)),
		pq.QuoteIdentifier(role),
	)

	_, err := txn.Exec(
		query,
	)
	if err != nil {
		return errors.Wrap(err, "could not alter default privileges")
	}

	d.SetId(role + "-" + database + "-" + pgSchema)
	return nil
}

func revokeRoleDefaultPrivileges(txn *sql.Tx, d *schema.ResourceData) error {
	query := fmt.Sprintf(
		"ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s REVOKE ALL ON %sS FROM %s",
		pq.QuoteIdentifier(d.Get("owner").(string)),
		pq.QuoteIdentifier(d.Get("schema").(string)),
		strings.ToUpper(d.Get("object_type").(string)),
		pq.QuoteIdentifier(d.Get("role").(string)),
	)

	_, err := txn.Exec(query)
	return err
}
