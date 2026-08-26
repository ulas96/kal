package kal

import (
	"context"

	"github.com/go-pg/pg/v10/orm"
	"github.com/ulas96/luima"
)

// The scoped crud four: luima's read and write helpers with [Scope] already folded in.
//
// @dev This is the second of kal's three authorization layers — @auth directive, Scope, RLS — and
// until these methods existed it was the only one enforced by nothing but discipline.
// [AssertAuthCoverage] walks the schema for a missing directive and Postgres enforces RLS, but a
// resolver calling luima.List[T](ctx, db) with the Scope argument left off compiles, passes review
// and returns every row in the table. The reasoning in AssertAuthCoverage's own comment applies
// here unchanged: the failure mode of resolver-level authorization is a forgotten check, and a
// forgotten check is invisible. Taking the column as an ordinary parameter is what makes it
// unforgettable — there is no arity that omits it.
//
// These do not replace calling luima directly with [Scope]; that form stays supported and is the
// answer whenever the predicate is not a single owning column. What it stops being is the only
// form, and therefore the only thing standing between a typo and a cross-tenant read.
//
// The ownership predicate goes on first and the caller's opts are then wrapped in a WhereGroup,
// so the SQL is `owner_id = ? AND (whatever the caller asked for)`. Ordering alone is not enough
// and assuming otherwise is the trap: go-pg's WhereOr appends ` OR `, so a caller option holding
// a single q.WhereOr turns an ungrouped `owner_id = ?` into `owner_id = ? OR owner_id = ?` and
// reads another tenant's rows through a method whose whole purpose is preventing that. The
// parentheses are what make an opt able to narrow the result and unable to widen it. See gotcha
// 84, which is the same hole in the ungrouped form these methods wrap.
//
// Anonymous and bypass-role callers need no branch here: [Scope] already answers the first with a
// predicate matching nothing and the second with a no-op, so both behave identically to a direct
// call and there is one implementation of that decision rather than two.
//
// There is no scoped Create, and its absence is deliberate. An INSERT has no WHERE for a
// predicate to land in — luima.Create takes no query options at all — so "scoping" a create means
// *setting* the owning column rather than filtering on it. Doing that generically needs either
// reflection over T or a field name kal cannot verify at compile time, and both fail the way this
// package refuses to fail: silently, when the model does not match. Set the column from
// [Require]'s principal in the resolver, and let the foreign key and RLS catch what that misses.

// This file is formatted by hand. gofmt (1.27.0) rejects a generic method — it refuses the file on
// stderr and lists nothing on stdout, so the Makefile gate, CI and `make fmt` all pass over it
// without a word (gotcha 85). Check `gofmt -l . >/dev/null; echo $?` after editing, not its output.

// scoped @notice One query option: the ownership predicate, then the caller's options in
// parentheses.
//
// @dev A single composed option rather than a slice, because the grouping is the security
// property and handing luima two siblings would let the second one reach the same WHERE at the
// same precedence as the first. [orm.Query.WhereGroup] saves and restores only q.where, so a
// caller option calling Column, Order, Limit or a join still applies to the outer query exactly
// as it would unscoped — the parentheses close over the caller's WHERE clauses and nothing else.
//
// The empty case is not special-cased for tidiness: WhereGroup with no clauses added inside
// restores the saved WHERE and appends nothing, so `owner_id = ?` never grows an empty `AND ()`.
// It is skipped anyway to keep the generated SQL identical to the direct luima call.
//
// A bypass-role caller gets `(caller clauses)` alone, because [Scope] returned a no-op — the
// group is still correct, it simply has nothing to be ANDed onto.
//
// @param ctx    the resolver context, carrying the principal and any bypass role
// @param column the owning column on the model's table
// @param opts   the caller's query options, grouped and ANDed after the predicate
// @return func(*orm.Query) *orm.Query the composed option
func (a *Auth) scoped(ctx context.Context, column string,
	opts []func(*orm.Query) *orm.Query) func(*orm.Query) *orm.Query {
	return func(q *orm.Query) *orm.Query {
		q = Scope(ctx, column)(q)
		if len(opts) == 0 {
			return q
		}
		return q.WhereGroup(func(q *orm.Query) (*orm.Query, error) {
			for _, opt := range opts {
				q = opt(q)
			}
			return q, nil
		})
	}
}

// List @notice Selects the caller's rows, and only the caller's. See [luima.List].
//
// @dev The read that leaks the most when its predicate is forgotten: one missing option and the
// resolver answers with every tenant's rows, with no error and a passing test.
//
// @param ctx    the resolver context
// @param db     orm.DB — *pg.DB, *pg.Conn and *pg.Tx all satisfy it
// @param column the owning column on T's table
// @param opts   further query modifiers, applied after the ownership predicate
// @return []*T  the caller's rows, never nil; empty for an anonymous caller
// @return error any driver error
func (a *Auth) List[T any](ctx context.Context, db orm.DB, column string,
	opts ...func(*orm.Query) *orm.Query) ([]*T, error) {
	return luima.List[T](ctx, db, a.scoped(ctx, column, opts))
}

// Get @notice Selects one row by primary key, if the caller owns it. See [luima.Get].
//
// @dev A row the caller does not own is (nil, nil) — the same answer as a row that does not
// exist, which is the correct thing to tell an unauthorized caller and the reason this does not
// return a NOT_FOUND the caller could use to probe for the existence of other people's rows.
//
// @param ctx    the resolver context
// @param db     orm.DB — *pg.DB, *pg.Conn and *pg.Tx all satisfy it
// @param column the owning column on T's table
// @param key    a model with only its primary key populated
// @param opts   further query modifiers, applied after the ownership predicate
// @return *T    the stored row, or nil when no row matched or the caller does not own it
// @return error any driver error other than pg.ErrNoRows
func (a *Auth) Get[T any](ctx context.Context, db orm.DB, column string, key *T,
	opts ...func(*orm.Query) *orm.Query) (*T, error) {
	return luima.Get[T](ctx, db, key, a.scoped(ctx, column, opts))
}

// Update @notice Replaces every column of the caller's row. See [luima.Update].
//
// @param ctx    the resolver context
// @param db     orm.DB — *pg.DB, *pg.Conn and *pg.Tx all satisfy it
// @param column the owning column on T's table
// @param m      the complete model, primary key included; every column is written
// @param label  names the thing in the not-found message
// @param opts   further query modifiers, applied after the ownership predicate; q.Column(...)
// narrows the SET clause
// @return *T    the stored row
// @return error a *kalerr-presentable not-found when no row matched or the caller does not own
// it, the bare driver error otherwise
func (a *Auth) Update[T any](ctx context.Context, db orm.DB, column string, m *T, label string,
	opts ...func(*orm.Query) *orm.Query) (*T, error) {
	return luima.Update[T](ctx, db, m, label, a.scoped(ctx, column, opts))
}

// Delete @notice Removes the caller's row, reporting whether one was there. See [luima.Delete].
//
// @dev False for someone else's row, and the row stays in the table. That pair is the property
// worth testing: a delete that reports nothing while the row quietly disappears passes any test
// that only checks the return value.
//
// @param ctx    the resolver context
// @param db     orm.DB — *pg.DB, *pg.Conn and *pg.Tx all satisfy it
// @param column the owning column on T's table
// @param key    a model with only its primary key populated
// @param opts   further query modifiers, applied after the ownership predicate
// @return bool  true when a row was deleted, false when none matched or the caller does not own it
// @return error any driver error
func (a *Auth) Delete[T any](ctx context.Context, db orm.DB, column string, key *T,
	opts ...func(*orm.Query) *orm.Query) (bool, error) {
	return luima.Delete[T](ctx, db, key, a.scoped(ctx, column, opts))
}
