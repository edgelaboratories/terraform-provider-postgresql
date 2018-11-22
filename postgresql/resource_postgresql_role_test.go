package postgresql

import (
	"database/sql"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccPostgresqlRole_Basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPostgresqlRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPostgresqlRoleConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPostgresqlRoleExists("tf_tests_myrole2", nil),
					resource.TestCheckResourceAttr("postgresql_role.myrole2", "name", "tf_tests_myrole2"),
					resource.TestCheckResourceAttr("postgresql_role.myrole2", "login", "true"),
					resource.TestCheckResourceAttr("postgresql_role.myrole2", "roles.#", "0"),

					testAccCheckPostgresqlRoleExists("tf_tests_role_default", nil),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "name", "tf_tests_role_default"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "superuser", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "create_database", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "create_role", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "inherit", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "replication", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "bypass_row_level_security", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "connection_limit", "-1"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "encrypted_password", "true"),
					resource.TestCheckNoResourceAttr("postgresql_role.role_with_defaults", "password"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "valid_until", "infinity"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "skip_drop_role", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "skip_reassign_owned", "false"),
					resource.TestCheckResourceAttr("postgresql_role.role_with_defaults", "roles.#", "0"),

					testAccCheckPostgresqlRoleExists("tf_tests_sub_role", []string{"tf_tests_myrole2", "tf_tests_role_simple"}),
					resource.TestCheckResourceAttr("postgresql_role.sub_role", "name", "tf_tests_sub_role"),
					resource.TestCheckResourceAttr("postgresql_role.sub_role", "roles.#", "2"),

					// The int part in the attr name is the schema.HashString of the value.
					resource.TestCheckResourceAttr("postgresql_role.sub_role", "roles.1456111905", "tf_tests_myrole2"),
					resource.TestCheckResourceAttr("postgresql_role.sub_role", "roles.3803627293", "tf_tests_role_simple"),
				),
			},
		},
	})
}

func TestAccPostgresqlRole_Update(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPostgresqlRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPostgresqlRoleUpdate1Config,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPostgresqlRoleExists("tf_tests_update_role", []string{}),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "name", "tf_tests_update_role"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "login", "true"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "connection_limit", "-1"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "roles.#", "0"),
				),
			},
			{
				Config: testAccPostgresqlRoleUpdate2Config,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPostgresqlRoleExists("tf_tests_update_role2", []string{"tf_tests_group_role"}),
					resource.TestCheckResourceAttr(
						"postgresql_role.update_role", "name", "tf_tests_update_role2",
					),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "login", "true"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "connection_limit", "5"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "roles.#", "1"),
					// The int part in the attr name is the schema.HashString of the value.
					resource.TestCheckResourceAttr(
						"postgresql_role.update_role", "roles.2634717634", "tf_tests_group_role",
					),
				),
			},
			// apply again the first one to tests the granted role is correctly revoked
			{
				Config: testAccPostgresqlRoleUpdate1Config,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPostgresqlRoleExists("tf_tests_update_role", []string{}),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "name", "tf_tests_update_role"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "login", "true"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "connection_limit", "-1"),
					resource.TestCheckResourceAttr("postgresql_role.update_role", "roles.#", "0"),
				),
			},
		},
	})
}

func testAccCheckPostgresqlRoleDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "postgresql_role" {
			continue
		}

		exists, err := checkRoleExists(client, rs.Primary.ID)

		if err != nil {
			return fmt.Errorf("Error checking role %s", err)
		}

		if exists {
			return fmt.Errorf("Role still exists after destroy")
		}
	}

	return nil
}

func testAccCheckPostgresqlRoleExists(roleName string, grantedRoles []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testAccProvider.Meta().(*Client)

		exists, err := checkRoleExists(client, roleName)
		if err != nil {
			return fmt.Errorf("Error checking role %s", err)
		}

		if !exists {
			return fmt.Errorf("Role not found")
		}

		if grantedRoles != nil {
			return checkGrantedRoles(client, roleName, grantedRoles)
		}
		return nil
	}
}

func checkRoleExists(client *Client, roleName string) (bool, error) {
	var _rez int
	err := client.DB().QueryRow("SELECT 1 from pg_roles d WHERE rolname=$1", roleName).Scan(&_rez)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("Error reading info about role: %s", err)
	}

	return true, nil
}

func checkGrantedRoles(client *Client, roleName string, expectedRoles []string) error {
	rows, err := client.DB().Query(
		"SELECT role_name FROM information_schema.applicable_roles WHERE grantee=$1 ORDER BY role_name",
		roleName,
	)
	if err != nil {
		return fmt.Errorf("Error reading granted roles: %v", err)
	}
	defer rows.Close()

	grantedRoles := []string{}
	for rows.Next() {
		var grantedRole string
		if err := rows.Scan(&grantedRole); err != nil {
			return fmt.Errorf("Error scanning granted role: %v", err)
		}
		grantedRoles = append(grantedRoles, grantedRole)
	}

	sort.Strings(expectedRoles)
	if !reflect.DeepEqual(grantedRoles, expectedRoles) {
		return fmt.Errorf(
			"Role %s is not a members of the expected list of roles. expected %v - got %v",
			roleName, expectedRoles, grantedRoles,
		)
	}
	return nil
}

var testAccPostgresqlRoleConfig = `
resource "postgresql_role" "myrole2" {
  name = "tf_tests_myrole2"
  login = true
}

resource "postgresql_role" "role_with_pwd" {
  name = "tf_tests_role_with_pwd"
  login = true
  password = "mypass"
}

resource "postgresql_role" "role_with_pwd_encr" {
  name = "tf_tests_role_with_pwd_encr"
  login = true
  password = "mypass"
  encrypted = true
}

resource "postgresql_role" "role_with_pwd_no_login" {
  name = "tf_tests_role_with_pwd_no_login"
  password = "mypass"
}

resource "postgresql_role" "role_simple" {
  name = "tf_tests_role_simple"
}

resource "postgresql_role" "role_with_defaults" {
  name = "tf_tests_role_default"
  superuser = false
  create_database = false
  create_role = false
  inherit = false
  login = false
  replication = false
  bypass_row_level_security = false
  connection_limit = -1
  encrypted_password = true
  password = ""
  skip_drop_role = false
  skip_reassign_owned = false
  valid_until = "infinity"
}

resource "postgresql_role" "sub_role" {
	name = "tf_tests_sub_role"
	roles = [
		"${postgresql_role.myrole2.id}",
		"${postgresql_role.role_simple.id}",
	]
}
`

var testAccPostgresqlRoleUpdate1Config = `
resource "postgresql_role" "update_role" {
  name = "tf_tests_update_role"
  login = true
}
`

var testAccPostgresqlRoleUpdate2Config = `
resource "postgresql_role" "group_role" {
	name = "tf_tests_group_role"
}
resource "postgresql_role" "update_role" {
  name = "tf_tests_update_role2"
  login = true
  connection_limit = 5
  roles = ["${postgresql_role.group_role.name}"]
}
`
