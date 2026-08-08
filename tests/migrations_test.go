package tests

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ulas96/luima/luimaerr"

	"github.com/ulas96/kal/migrations"
)

// TestMigrationFiles @notice The embed carries the files in run order. No database needed.
//
// @param t the test handle
func TestMigrationFiles(t *testing.T) {
	files := migrations.Files()
	if len(files) == 0 {
		t.Fatal("no migration files embedded")
	}
	if files[0] != "0001_core.sql" {
		t.Errorf("first migration = %q, want 0001_core.sql", files[0])
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".sql") {
			t.Errorf("non-sql file embedded: %s", f)
		}
	}
}

// TestMigrationsTablesMatchSQL @notice Tables() lists exactly what the .sql files create.
//
// @dev The whole anti-drift mechanism, and the reason a hand-written list is acceptable: a new
// migration that adds a table fails here until the list is updated. What that protects is a
// consumer sharing a schema with kal and generating CRUD from information_schema — a table
// missing from this list is one their generator will happily expose, and auth_user_roles is a
// mutation that grants its caller any role.
//
// @param t the test handle
func TestMigrationsTablesMatchSQL(t *testing.T) {
	declared := map[string]bool{}
	for _, name := range migrations.Tables() {
		if declared[name] {
			t.Errorf("Tables() lists %s twice", name)
		}
		declared[name] = true
	}

	created := map[string]bool{}
	re := regexp.MustCompile(`(?mi)^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?"?(\w+)"?`)
	for _, file := range migrations.Files() {
		raw, err := migrations.FS.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
			created[m[1]] = true
		}
	}
	if len(created) == 0 {
		t.Fatal("the regex matched no create table statement — the test is asserting nothing")
	}

	for name := range created {
		if !declared[name] {
			t.Errorf("%s is created by a migration and missing from Tables()", name)
		}
	}
	for name := range declared {
		if !created[name] {
			t.Errorf("Tables() lists %s, which no migration creates", name)
		}
	}
}

// TestDBMigrations @notice The schema applies cleanly and the email index enforces what it
// claims: one live account per address, case-insensitively, with re-registration after a soft
// delete allowed.
//
// @dev The three-step dance below is the whole reason the index is partial. A plain unique
// index passes the first assertion and fails the second; the backwards two-column variant
// passes the second and fails the first.
//
// @param t the test handle
func TestDBMigrations(t *testing.T) {
	db := testDB(t)

	if _, err := db.Exec(`insert into auth_users (email) values ('Alice@Example.com')`); err != nil {
		t.Fatal(err)
	}

	// Same address, different case: the lower() index must reject it while the row is live.
	_, err := db.Exec(`insert into auth_users (email) values ('alice@example.com')`)
	if luimaerr.SQLState(err) != "23505" {
		t.Fatalf("duplicate live email: err = %v, want unique_violation", err)
	}

	// Soft-deleting frees the address...
	if _, err := db.Exec(`update auth_users set deleted_at = now()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into auth_users (email) values ('alice@example.com')`); err != nil {
		t.Fatalf("re-register after soft delete: %v", err)
	}

	// ...for exactly one new live row.
	_, err = db.Exec(`insert into auth_users (email) values ('ALICE@example.com')`)
	if luimaerr.SQLState(err) != "23505" {
		t.Fatalf("second live row after re-register: err = %v, want unique_violation", err)
	}
}
