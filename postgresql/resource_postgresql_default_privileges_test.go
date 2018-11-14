package postgresql

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccPostgresqlDefaultPrivileges(t *testing.T) {
	// We have to create the database outside of resource.Test
	// because we need to create a table to assert that grant are correctly applied
	// and we don't have this resource yet
	dbSuffix, teardown := setupTestDatabase(t, true, true, false)
	defer teardown()

	config := getTestConfig(t)
	dbName, roleName := getTestDBNames(dbSuffix)

	// We set PGUSER as owner as he will create the test table
	var testDPSelect = fmt.Sprintf(`
	resource "postgresql_default_privileges" "test_ro" {
		database    = "%s"
		owner       = "%s"
		role        = "%s"
		schema      = "public"
		object_type = "table"
		privileges   = ["SELECT"]
	}
	`, dbName, config.Username, roleName)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testDPSelect,
				Check: resource.ComposeTestCheckFunc(
					func(*terraform.State) error {
						return testCheckTablePrivileges(t, dbSuffix, []string{"SELECT"}, true)
					},
					resource.TestCheckResourceAttr("postgresql_default_privileges.test_ro", "object_type", "table"),
					resource.TestCheckResourceAttr("postgresql_default_privileges.test_ro", "privileges.#", "1"),
					resource.TestCheckResourceAttr("postgresql_default_privileges.test_ro", "privileges.3138006342", "SELECT"),
				),
			},
		},
	})
}
