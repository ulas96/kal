package authz

import (
	"context"
	"regexp"

	"github.com/go-pg/pg/v10/orm"
	"github.com/go-pg/pg/v10/types"

	"github.com/ulas96/kal/kalerr"
)

// identRe @notice What a schema qualifier may look like; same rule as the other packages.
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Roles @notice Grants and revokes role membership.
//
// @dev A deliberately small surface: kal models roles as names on users and nothing more. There
// is no permission table, no hierarchy and no inheritance, because the moment a library ships
// those it has shipped a policy DSL — and the answer to "owner_id = me OR role = admin" is one
// WHERE clause, not an engine. Anything richer belongs in the consumer's own schema, reachable
// from a Scope closure.
type Roles struct {
	sql roleStatements
}

type roleStatements struct {
	ensure, grant, revoke, forUser string
}

// NewRoles @notice Prepares the statements, optionally schema-qualified.
//
// @param schema optional Postgres schema holding the auth_* tables
// @return *Roles ready for concurrent use
// @return error  an invalid schema name
func NewRoles(schema string) (*Roles, error) {
	prefix := ""
	if schema != "" {
		if !identRe.MatchString(schema) {
			return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput,
				Message: "table schema must match ^[a-z_][a-z0-9_]*$"}
		}
		prefix = string(types.AppendIdent(nil, schema, 1)) + "."
	}
	return &Roles{sql: renderRoles(prefix)}, nil
}

// Ensure @notice Creates the role if it does not exist. Idempotent, so it is safe to call at
// startup for every role an application knows about.
//
// @param name        the role name
// @param description free text for an administration UI
// @return error any driver error
func (r *Roles) Ensure(ctx context.Context, db orm.DB, name, description string) error {
	_, err := db.ExecContext(ctx, r.sql.ensure, name, description)
	return err
}

// Grant @notice Gives userID the role. Idempotent.
//
// @dev The role must exist: the foreign key is what stops a typo from creating a role nobody
// holds and a check nobody passes. That error surfaces as a driver error rather than a
// client-visible one, because granting roles is an administrative path, not a public one.
//
// @return error any driver error, including a foreign-key violation for an unknown role
func (r *Roles) Grant(ctx context.Context, db orm.DB, userID, role string) error {
	_, err := db.ExecContext(ctx, r.sql.grant, userID, role)
	return err
}

// Revoke @notice Takes the role away. Idempotent, and effective on the holder's next request —
// session lookup reads roles fresh rather than trusting what login recorded.
//
// @return error any driver error
func (r *Roles) Revoke(ctx context.Context, db orm.DB, userID, role string) error {
	_, err := db.ExecContext(ctx, r.sql.revoke, userID, role)
	return err
}

// ForUser @notice The roles userID holds, sorted.
//
// @return []string the role names; empty, never nil
// @return error    any driver error
func (r *Roles) ForUser(ctx context.Context, db orm.DB, userID string) ([]string, error) {
	var out []string
	if _, err := db.QueryContext(ctx, &out, r.sql.forUser, userID); err != nil {
		return nil, err
	}
	if out == nil {
		return []string{}, nil
	}
	return out, nil
}
