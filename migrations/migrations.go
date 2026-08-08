// Package migrations @notice The auth schema, as plain SQL behind an embed.FS.
//
// @dev No migration framework, deliberately: running SQL files in filename order is not a
// problem that needs a dependency, and every application already has an opinion about how it
// migrates. Feed [FS] (or [Files]) to whatever the application uses — goose, migrate, atlas, a
// psql loop — or execute the files in order at startup.
//
// The files create unqualified table names. To keep kal's tables in their own Postgres schema,
// execute them with search_path set to that schema and hand the same name to Config.TableSchema
// so kal's queries qualify correctly.
package migrations

import (
	"embed"
	"io/fs"
	"sort"
)

// FS @notice The embedded *.sql files.
//
//go:embed *.sql
var FS embed.FS

// Files @notice The migration filenames in the order they must run.
//
// @dev Lexicographic order of the NNNN_ prefix is the contract. embed.FS.ReadDir already
// returns sorted entries, but sorting again here keeps the guarantee in one greppable place
// rather than in embed's documentation.
//
// @return []string filenames such as "0001_core.sql", each readable through [FS]
func Files() []string {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		// The FS is embedded at compile time, so an error here means the binary itself is
		// broken — there is nothing for a caller to handle.
		panic(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// Tables @notice Every table the migrations create, unqualified.
//
// @dev For a consumer that shares a Postgres schema between kal's tables and its own, and
// generates anything from information_schema. Several of these carry a user_id column, so a
// generator applying the usual owner-column convention will emit CRUD over auth_user_roles —
// which is a mutation that grants its caller any role — and over auth_sessions, which is one that
// clears revoked_at. Exclude these before generating, not after.
//
// A hand-written list rather than a parse of the SQL: a parser is more code and more ways to be
// wrong, and the test asserting set equality against the .sql files is what stops this drifting.
//
// @return []string table names in migration order
func Tables() []string {
	return []string{
		// 0001_core.sql
		"auth_users", "auth_sessions", "auth_tokens",
		"auth_roles", "auth_user_roles", "auth_login_attempts",
		// 0002_zk.sql
		"auth_zk_commitments", "auth_zk_challenges", "auth_zk_nodes", "auth_zk_credentials",
		"auth_zk_roots", "auth_zk_nullifiers", "auth_zk_claims", "auth_zk_session_claims",
		// 0003_e2ee.sql
		"auth_e2ee_vaults",
	}
}
