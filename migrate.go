package kal

import (
	"context"
	"fmt"

	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal/migrations"
)

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
