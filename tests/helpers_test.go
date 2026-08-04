// Package tests @notice Holds every test and runnable example in the module.
//
// @dev The tests live here rather than beside their packages, so each one exercises kal across
// a real package boundary — exactly as a consumer does. Nothing in this directory can reach an
// unexported symbol, which means a test passing here proves the exported surface is sufficient.
// For an auth library that rule has teeth: if a security property cannot be asserted from out
// here, a consumer cannot rely on it either, and the exported surface — not the test — is what
// has to change.
//
// The cost, stated plainly: Example functions do not render on pkg.go.dev under the symbols
// they demonstrate, because godoc binds an example to a symbol by directory. They still compile
// and their Output blocks still run, so they cannot rot — they are simply not published.
package tests

import (
	"context"
	"os"
	"testing"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal/migrations"
)

// testSchema @notice The scratch Postgres schema every DB-backed test runs in.
//
// @dev A dedicated schema rather than the connection's default: dropping and recreating it
// wholesale gives each test a clean slate without touching anything else in the database. And
// because the harness applies the migrations through search_path, it exercises the same
// mechanism a consumer isolating kal's tables uses — the harness is itself a test of that path.
const testSchema = "kal_test"

// testDB @notice Connects to DATABASE_URL, rebuilds the scratch schema, applies every migration
// and returns the pool — or skips the calling test when no database is configured.
//
// @dev Skipping rather than failing keeps `go test ./...` green on a machine without Postgres.
// That mercy is why CI greps the -v output for `--- PASS: TestDB`: a skip still reports ok, and
// in an auth library that silence would swallow every property the schema enforces — the unique
// index, token single-use, session revocation.
//
// search_path is set in OnConnect, not with a one-off Exec: go-pg is a pool, and an Exec lands
// the setting on one arbitrary connection while later queries run on others. OnConnect is the
// only hook that reaches every connection.
//
// @param t the test handle
// @return *pg.DB a pool whose every connection resolves unqualified names to the scratch schema
func testDB(t *testing.T) *pg.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set — see .env.example")
	}
	opt, err := pg.ParseURL(url)
	if err != nil {
		t.Fatalf("DATABASE_URL: %v", err)
	}
	opt.OnConnect = func(_ context.Context, cn *pg.Conn) error {
		_, err := cn.Exec("set search_path to ?", pg.Ident(testSchema))
		return err
	}
	db := pg.Connect(opt)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec("drop schema if exists ? cascade", pg.Ident(testSchema)); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := db.Exec("create schema ?", pg.Ident(testSchema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	for _, name := range migrations.Files() {
		sql, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := db.Exec(string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec("drop schema if exists ? cascade", pg.Ident(testSchema))
	})
	return db
}
