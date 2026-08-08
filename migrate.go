package kal

import (
	"context"
	"fmt"
	"regexp"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/go-pg/pg/v10/types"

	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/migrations"
)

// identRe @notice What a schema qualifier may look like; same rule as every other package.
//
// @dev Duplicated rather than exported, matching session, authz, authn, e2ee, zkauthn and
// zkauthz. CREATE SCHEMA cannot take a bound parameter, so this is the only thing standing
// between a caller's string and the DDL.
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// migrate @notice Executes every embedded migration in filename order.
//
// @dev Deliberately not a migration framework — no version table, no down migrations, no
// advisory lock. It is the two-line convenience for an application that has no tooling yet;
// anything with real deployment needs should feed migrations.FS to the tool it already uses.
// Each statement runs on the connection's search_path, which is how Config.TableSchema is
// honoured without qualifying the DDL.
func migrate(ctx context.Context, db orm.DB) error {
	for _, name := range migrations.Files() {
		sql, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("kal: reading migration %s: %w", name, err)
		}
		if _, err := db.ExecContext(ctx, string(sql)); err != nil {
			return fmt.Errorf("kal: applying migration %s: %w", name, err)
		}
	}
	return nil
}

// migrateSchema @notice Creates the schema if needed and applies every migration into it.
//
// @dev Three things are load-bearing and each has broken a deployment elsewhere in this tree:
//
//  1. Everything is inside one transaction. set_config lands on one pooled connection; without
//     the transaction the DDL runs on another and the tables appear wherever that connection's
//     search_path pointed — which is the failure this function exists to remove (gotcha 80).
//  2. search_path travels as a bound parameter through set_config, transaction-local, exactly as
//     authz.WithRLS does it. SET LOCAL is not parameterizable, so the string form would mean
//     concatenating a caller's value into SQL.
//  3. CREATE SCHEMA is the one statement whose name cannot be bound, so the name is validated
//     against identRe and then quoted with go-pg's ident writer — the same two steps NewSessions
//     takes for the same reason.
//
// search_path is set to the named schema alone, with no public fallback, so an unqualified name
// in the DDL can only resolve to the target. Nothing in migrations/ needs an extension:
// gen_random_uuid() is pg_catalog since Postgres 13.
func migrateSchema(ctx context.Context, db *pg.DB, schema string) error {
	if !identRe.MatchString(schema) {
		return &kalerr.Error{Code: kalerr.CodeInvalidInput,
			Message: "table schema must match ^[a-z_][a-z0-9_]*$"}
	}
	quoted := string(types.AppendIdent(nil, schema, 1))
	return db.RunInTransaction(ctx, func(tx *pg.Tx) error {
		if _, err := tx.ExecContext(ctx, "create schema if not exists "+quoted); err != nil {
			return fmt.Errorf("kal: creating schema %s: %w", schema, err)
		}
		if _, err := tx.ExecContext(ctx,
			`select set_config('search_path', ?, true)`, schema); err != nil {
			return fmt.Errorf("kal: setting search_path to %s: %w", schema, err)
		}
		return migrate(ctx, tx)
	})
}
