package tests

import (
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
