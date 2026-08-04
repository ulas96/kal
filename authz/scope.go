package authz

import (
	"context"
	"strings"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
)

// Scope @notice The caller's ownership predicate, as a luima crud option.
//
// @dev This is the real enforcement, and it is the thing a policy engine structurally cannot
// give you. A boolean answers "may Alice read document 7"; it does not stop a list query from
// returning every document, and it cannot be applied to a DELETE without a read-then-check
// round trip that has a TOCTOU window. Composing the predicate into the statement has neither
// problem, and the database enforces it.
//
//	func (r *mutationResolver) DeleteDoc(ctx context.Context, id string) (bool, error) {
//	    return luima.Delete(ctx, r.DB, &model.Doc{ID: id}, authz.Scope(ctx, "owner_id"))
//	}
//
// What falls out for free: a row that exists but is not yours matches nothing, so
// RowsAffected() is 0, so crud.Delete returns false and crud.Update reports "not found".
// "Not yours" and "does not exist" become indistinguishable to the caller — which is the
// correct answer to give an unauthorized one anyway.
//
// An anonymous caller yields a predicate matching nothing, never an open query. Failing closed
// matters most exactly where the middleware did not run.
//
// The column name is not user input: it comes from the resolver, at compile time. It is still
// written through pg.Ident, because a variant that ever took it from a request must not be one
// edit away from SQL injection.
//
// Escape hatch by function type, not interface: anyone whose authorization genuinely needs an
// external engine calls it inside their own closure and returns
// q.Where("id = any(?)", pg.Array(ids)). No Authorizer abstraction that exists to be
// overridden once.
//
// TOCTOU: every crud helper takes orm.DB, so db.RunInTransaction plus passing the *pg.Tx
// closes the window between a check and a write, and SELECT … FOR UPDATE is expressible
// through these same options.
//
// @param ctx    the resolver context
// @param column the owning column on the model's table
// @return func  a query option: the ownership predicate, a no-op for a bypass-role caller, or
// a predicate matching nothing when the caller is anonymous
func Scope(ctx context.Context, column string) func(*orm.Query) *orm.Query {
	p, ok := From(ctx)
	if !ok {
		return func(q *orm.Query) *orm.Query { return q.Where("false") }
	}
	if bypass, hasBypass := bypassFrom(ctx); hasBypass && hasRole(p.Roles, bypass) {
		return func(q *orm.Query) *orm.Query { return q }
	}
	return func(q *orm.Query) *orm.Query {
		return q.Where("? = ?", pg.Ident(column), p.UserID)
	}
}

// bypassKey @notice Context key for the configured bypass role.
type bypassKey struct{}

// WithBypassRole @notice Names the role for which Scope is a no-op — the admin path, as one
// explicit branch rather than a second set of queries.
//
// @dev Carried on the context rather than read from a package-level var, because a package
// var would let any consumer in the binary redefine every other consumer's admin role. kal's
// middleware installs this from Config; a test can install it directly.
//
// @param ctx  the parent context
// @param role the bypass role name; empty installs nothing
// @return context.Context ctx with the bypass role attached
func WithBypassRole(ctx context.Context, role string) context.Context {
	if role == "" {
		return ctx
	}
	return context.WithValue(ctx, bypassKey{}, role)
}

func bypassFrom(ctx context.Context) (string, bool) {
	r, ok := ctx.Value(bypassKey{}).(string)
	return r, ok
}

// hasRole @notice Whether roles contains want, case-insensitively.
//
// @dev Case-insensitive because "Admin" in a schema literal and "admin" in a database row is a
// difference nobody intends, and the failure mode is silent: the check simply never matches
// and the field is never visible.
func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// HasRole @notice Whether the caller holds the named role, case-insensitively.
//
// @param ctx  the resolver context
// @param role the role to look for
// @return bool false for an anonymous caller
func HasRole(ctx context.Context, role string) bool {
	p, ok := From(ctx)
	return ok && hasRole(p.Roles, role)
}
