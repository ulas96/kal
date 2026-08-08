package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal"
)

// TestDBMigrateSchemaTargetsNamedSchema @notice Two provisioning calls land in two schemas, and
// neither can see the other's rows.
//
// @dev Step four is the test. Migrating into two schemas and finding auth_users in both passes
// with or without MigrateSchema on a connection whose search_path happens to be right — that is
// precisely the shape of the bug (gotcha 80), where a provisioning loop writes one tenant's auth
// tables into another tenant's schema and nothing errors. So the assertion is the thing that goes
// wrong: a row inserted into one schema must not be visible in the other, and public must have no
// auth_users at all. The pool's search_path points at kal_test throughout, so if MigrateSchema
// leaked its search_path the tables would land there and the isolation check would catch it.
//
// @param t the test handle
func TestDBMigrateSchemaTargetsNamedSchema(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	auth, err := kal.New(newTestConfig(db))
	if err != nil {
		t.Fatal(err)
	}

	const schemaA, schemaB = "kal_test_a", "kal_test_b"
	// The harness only owns kal_test, so these two are this test's to clean up.
	t.Cleanup(func() {
		for _, s := range []string{schemaA, schemaB} {
			_, _ = db.Exec("drop schema if exists ? cascade", pg.Ident(s))
		}
		_, _ = db.Exec("drop table if exists public.auth_users cascade")
	})

	for _, s := range []string{schemaA, schemaB} {
		if err := auth.MigrateSchema(ctx, s); err != nil {
			t.Fatalf("MigrateSchema(%s): %v", s, err)
		}
	}

	tableExists := func(schema, table string) bool {
		t.Helper()
		var n int
		if _, err := db.QueryOne(pg.Scan(&n),
			`select count(*) from information_schema.tables
			  where table_schema = ? and table_name = ?`, schema, table); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	for _, s := range []string{schemaA, schemaB} {
		if !tableExists(s, "auth_users") {
			t.Errorf("auth_users missing from %s", s)
		}
	}
	// The loud half of gotcha 80: DDL that ran on the wrong search_path lands here.
	if tableExists("public", "auth_users") {
		t.Error("MigrateSchema created auth_users in public — the DDL ran on the connection's search_path")
	}

	if _, err := db.Exec(`insert into kal_test_a.auth_users (email) values ('a@example.test')`); err != nil {
		t.Fatal(err)
	}

	// The silent half, and the whole point of the test: two tenants provisioned in one loop must
	// not be sharing a table.
	var inB int
	if _, err := db.QueryOne(pg.Scan(&inB), `select count(*) from kal_test_b.auth_users`); err != nil {
		t.Fatal(err)
	}
	if inB != 0 {
		t.Errorf("kal_test_b.auth_users holds %d rows after inserting into kal_test_a — the two schemas share a table", inB)
	}

	// Idempotent: a provisioning loop that retries must not fail on "schema already exists".
	// The migrations themselves are not idempotent, so this is expected to error on the tables —
	// what must not happen is a failure to create the schema.
	if err := auth.MigrateSchema(ctx, schemaA); err == nil {
		t.Error("a second MigrateSchema succeeded — the migrations are not idempotent and must fail loudly")
	} else if strings.Contains(err.Error(), "creating schema") {
		t.Errorf("create schema is not idempotent: %v", err)
	}
}

// TestMigrateSchemaRejectsBadName @notice The one string that reaches DDL text is validated.
//
// @dev CREATE SCHEMA cannot bind its name as a parameter, so identRe is the only thing between a
// caller's string and executed SQL. No database needed: the rejection must happen before any
// statement is built, which is also why a Config pointing at an unreachable address is enough.
//
// @param t the test handle
func TestMigrateSchemaRejectsBadName(t *testing.T) {
	db := pg.Connect(&pg.Options{Addr: "127.0.0.1:1", User: "nobody"}) // never dialled
	t.Cleanup(func() { _ = db.Close() })

	auth, err := kal.New(newTestConfig(db))
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"acme-corp",           // hyphen
		"a; drop table users", // the injection this guard exists for
		"Acme",                // uppercase
		"1tenant",             // leading digit
		"",                    // empty
		`tenant"; --`,         // quote-escape attempt
		"tenant schema",       // space
	} {
		t.Run(name, func(t *testing.T) {
			if err := auth.MigrateSchema(context.Background(), name); err == nil {
				t.Errorf("MigrateSchema accepted %q", name)
			}
		})
	}
}
