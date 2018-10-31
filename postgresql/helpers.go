package postgresql

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/lib/pq"
	"github.com/pkg/errors"
)

// pqQuoteLiteral returns a string literal safe for inclusion in a PostgreSQL
// query as a parameter.  The resulting string still needs to be wrapped in
// single quotes in SQL (i.e. fmt.Sprintf(`'%s'`, pqQuoteLiteral("str"))).  See
// quote_literal_internal() in postgresql/backend/utils/adt/quote.c:77.
func pqQuoteLiteral(in string) string {
	in = strings.Replace(in, `\`, `\\`, -1)
	in = strings.Replace(in, `'`, `''`, -1)
	return in
}

func validateConnLimit(v interface{}, key string) (warnings []string, errors []error) {
	value := v.(int)
	if value < -1 {
		errors = append(errors, fmt.Errorf("%s can not be less than -1", key))
	}
	return
}

func sliceContainsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

var allowedPrivileges = map[string][]string{
	"table":    []string{"ALL", "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"},
	"sequence": []string{"ALL", "USAGE", "SELECT", "UPDATE"},
}

func validatePrivileges(objectType string, privileges []interface{}) error {
	allowed, ok := allowedPrivileges[objectType]
	if !ok {
		return fmt.Errorf("unknown object type %s", objectType)
	}

	for _, priv := range privileges {
		if !sliceContainsStr(allowed, priv.(string)) {
			return fmt.Errorf("%s is not an allowed privilege for object type %s", priv, objectType)
		}
	}
	return nil
}

func pgArrayToSet(arr pq.ByteaArray) *schema.Set {
	s := make([]interface{}, len(arr))
	for i, v := range arr {
		s[i] = string(v)
	}
	return schema.NewSet(schema.HashString, s)
}

func startTransaction(client *Client, database string) (*sql.Tx, error) {
	// TODO: Think about serialization level

	if database != "" && database != client.databaseName {
		var err error
		client, err = client.config.NewClient(database)
		if err != nil {
			return nil, err
		}
	}
	db := client.DB()
	txn, err := db.Begin()
	if err != nil {
		return nil, errors.Wrap(err, "could not start transaction")
	}

	return txn, nil
}

func dbExists(txn *sql.Tx, dbname string) (bool, error) {
	err := txn.QueryRow("SELECT datname from pg_database WHERE datname=$1", dbname).Scan(&dbname)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, errors.Wrap(err, "could not check if database exists")
	}

	return true, nil
}

func roleExists(txn *sql.Tx, rolname string) (bool, error) {
	err := txn.QueryRow("SELECT 1 FROM pg_roles WHERE rolname=$1", rolname).Scan(&rolname)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, errors.Wrap(err, "could not check if role exists")
	}

	return true, nil
}

func schemaExists(txn *sql.Tx, schemaname string) (bool, error) {
	err := txn.QueryRow("SELECT 1 FROM pg_namespace WHERE nspname=$1", schemaname).Scan(&schemaname)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, errors.Wrap(err, "could not check if schema exists")
	}

	return true, nil
}
