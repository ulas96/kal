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
