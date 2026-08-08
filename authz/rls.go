package authz

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal/kalerr"
)

// WithRLS @notice Runs fn in a transaction whose Postgres session variables carry the caller,
// for policies written against current_setting.
//
// @dev The third layer of authorization, and the point of it is that it survives a forgotten
// check in the two above. Four things about this function are load-bearing, and each of them
// has silently broken a production deployment:
//
//  1. Everything happens inside RunInTransaction. SET LOCAL outside a transaction is a no-op —
//     Postgres warns and moves on — and with a connection pool the setting would land on one
//     pooled connection while the query ran on another.
//  2. set_config's third argument is true, which is what makes the setting transaction-local.
//     A plain session-scoped SET outlives the transaction and leaks to whichever request
//     borrows that connection next: a cross-tenant data leak that only appears under
//     concurrency. It is also what keeps this compatible with PgBouncer in transaction pooling
//     mode, precisely because it dies at COMMIT.
//  3. set_config with bound parameters, not "SET LOCAL app.user_id = …". SET is not a
//     parameterizable statement, so the string form forces concatenation, which is SQL
//     injection in the one function whose job is authorization.
//  4. An anonymous caller sets empty strings rather than skipping the settings. A policy must
//     then fail closed — see the warning below.
//
// Two more, on the SQL side, that this function cannot enforce for you:
//
//   - ALTER TABLE … FORCE ROW LEVEL SECURITY, or the table owner bypasses every policy. Most
//     migration setups connect as the owner, which means RLS silently does nothing. This is
//     the single most common way an RLS deployment is quietly broken.
//
//   - Never write a policy where a NULL or empty setting is permissive.
//     current_setting('app.user_id', true) returns NULL when unset — the true is mandatory or
//     it raises — so a policy reading "current_setting(...) is null or owner_id = ..." fails
//     open on every unconfigured connection.
//
// A policy with both of those right looks like this. nullif turns the anonymous caller's empty
// string into NULL, and NULL never equals anything, so the predicate matches no rows:
//
//	alter table docs enable row level security;
//	alter table docs force  row level security;
//	create policy docs_owner on docs
//	  to app_user
//	  using      (owner_id = nullif(current_setting('app.user_id', true), '')::uuid)
//	  with check (owner_id = nullif(current_setting('app.user_id', true), '')::uuid);
//
// Prefer this GUC approach over SET ROLE: a client with any SQL-injection foothold can issue
// RESET ROLE and escape back to the authenticator role, whereas a GUC hands out no
// role-switching primitive.
//
// @param ctx the resolver context, read for the caller
// @param db  the pool; a transaction is opened on it
// @param fn  runs with the tx, which it must use for every query the policies should see
// @return error fn's error, or the transaction's
func WithRLS(ctx context.Context, db *pg.DB, fn func(orm.DB) error) error {
	return WithRLSSettings(ctx, db, nil, fn)
}

// settingKeyRe @notice What an extra RLS setting may be named.
//
// @dev The app. prefix is required rather than merely conventional: an unprefixed name can
// collide with a real Postgres GUC, and set_config on one of those either errors or changes
// backend behaviour for the rest of the transaction.
var settingKeyRe = regexp.MustCompile(`^app\.[a-z_][a-z0-9_]*$`)

// WithRLSSettings @notice [WithRLS], plus consumer settings on the same transaction.
//
// @dev Read WithRLS's doc comment first; all four of its traps apply here unchanged. This exists
// because a consumer whose tenancy is not a single owner column — an org, a project, a region —
// otherwise has to copy that function into their own repository and re-derive all four.
//
// The one thing this adds: extra keys are validated against ^app\.[a-z_][a-z0-9_]*$ even though
// set_config takes its name as a bound parameter and needs no such check. The validation is not
// load-bearing against injection — it is there so a typo becomes an error instead of a setting no
// policy reads, which is a policy that silently matches nothing or, worse, silently matches
// everything.
//
// Keys are applied in sorted order and in one statement, so the query log shows a stable
// statement rather than one shape per map iteration.
//
// @param ctx   the resolver context, read for the caller
// @param db    the pool; a transaction is opened on it
// @param extra settings to set transaction-locally; keys must be app.-prefixed. Nil is WithRLS.
// @param fn    runs with the tx, which it must use for every query the policies should see
// @return error a rejected key, fn's error, or the transaction's
func WithRLSSettings(ctx context.Context, db *pg.DB, extra map[string]string,
	fn func(orm.DB) error) error {
	var userID, roles string
	if p, ok := From(ctx); ok {
		userID = p.UserID
		roles = strings.Join(p.Roles, ",")
	}

	keys := make([]string, 0, len(extra))
	for k := range extra {
		if !settingKeyRe.MatchString(k) {
			return &kalerr.Error{Code: kalerr.CodeInvalidInput,
				Message: "RLS setting names must match ^app\\.[a-z_][a-z0-9_]*$"}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// One round trip for every setting. The caller's names and values are bound like the two
	// built-in ones; nothing here is concatenated into SQL text.
	stmt := `select set_config('app.user_id', ?, true), set_config('app.roles', ?, true)`
	args := []any{userID, roles}
	for _, k := range keys {
		stmt += `, set_config(?, ?, true)`
		args = append(args, k, extra[k])
	}

	return db.RunInTransaction(ctx, func(tx *pg.Tx) error {
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return err
		}
		return fn(tx)
	})
}
