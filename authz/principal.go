// Package authz @notice Who the caller is: the Principal, carried in the request context.
//
// @dev The package is deliberately database-free on its hot path. Everything a check needs is
// resolved once per request by the session middleware and read here from the context — because
// authorization runs per field, per row, and a check that costs a query is an N+1 that only
// appears under production load.
package authz

import (
	"context"
	"time"

	"github.com/ulas96/kal/kalerr"
)

// Principal @notice The authenticated caller, as a resolver sees it.
//
// @dev Everything on it is resolved once per request by the session middleware, so a directive
// or a resolver can check it without touching the database. That is deliberate: a directive on
// a field of a list type runs once per row, and an authorization check that costs a query is an
// N+1 invisible until production load.
type Principal struct {
	UserID    string    // never empty for an authenticated principal
	SessionID string    // the session this request authenticated with
	Roles     []string  // read fresh from auth_user_roles by the session lookup
	AuthAt    time.Time // when the session was established — for absolute-age policies
	MFAAt     time.Time // zero if MFA was never satisfied on this session; drives step-up
	Email     string
	Verified  bool
}

// ctxKey @notice The context key for the Principal.
//
// @dev An unexported struct type — not an exported type and not a string. Any package in the
// binary could otherwise write its own value under the same key and forge a caller; with this
// key, WithPrincipal below is the only door in.
type ctxKey struct{}

// WithPrincipal @notice Returns a context carrying p. The session middleware's seam — and a
// test's.
//
// @dev Exported because the middleware lives in another package and tests need to fabricate
// callers. That does not weaken the unexported-key property: the key prevents *accidental*
// collision and overwrite; code that imports authz and calls this does it on purpose, in plain
// sight.
//
// @param ctx the parent context
// @param p   the caller; nil stores nothing and returns ctx unchanged
// @return context.Context ctx with p reachable through From and Require
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, p)
}

// From @notice Returns the caller, and whether there is one.
//
// @dev Anonymous is not an error: one GraphQL endpoint serves public and private fields in the
// same document, so "no principal" is an ordinary state a resolver branches on, not a fault.
//
// @param ctx the resolver context
// @return *Principal the caller, or nil
// @return bool       whether a caller is present
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// Require @notice Returns the caller, or a typed UNAUTHENTICATED error for the resolver to
// return.
//
// @dev Two accessors and no MustFrom: a panicking accessor in an auth library turns a missing
// middleware into a 500 with a stack trace, where Require turns it into the UNAUTHENTICATED
// error that is both correct and what the client needs to react to.
//
// @param ctx the resolver context
// @return *Principal the caller; nil exactly when error is non-nil
// @return error      a *kalerr.Error with CodeUnauthenticated when there is no caller
func Require(ctx context.Context) (*Principal, error) {
	p, ok := From(ctx)
	if !ok {
		return nil, &kalerr.Error{Code: kalerr.CodeUnauthenticated, Message: "authentication required"}
	}
	return p, nil
}
