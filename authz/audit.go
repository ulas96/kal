package authz

import (
	"context"
	"time"
)

// Event @notice One security-relevant thing kal did.
//
// @dev A struct rather than an interface, and a flat one: every field is something a consumer
// writes to an audit row, and an event nobody can serialise without a type switch is an event
// nobody logs.
//
// The vocabulary is open on purpose — Kind is a string, not an enum — because a closed set would
// make every new event a breaking change for a consumer switching on it exhaustively. The kinds
// kal emits today:
//
//	login.ok             a password login succeeded
//	login.fail           a password login was refused; UserID is empty, the account may not exist
//	backoff.open         the per-account or per-address window rejected an attempt before hashing
//	password.rehash      rehash-on-login failed; the stored hash is still the weaker one
//	mail.fail            the Mailer refused a message kal wanted sent
//	session.lookup.fail  the session lookup failed on the driver; the request proceeded anonymous
//	session.revoked      one session, or every session of one user, was terminated
//
// Three of those — password.rehash, mail.fail and session.lookup.fail — are emitted only on
// failure, because the sites they sit at are best-effort paths that log and continue. Their
// absence means nothing went wrong, not that nothing happened.
type Event struct {
	// Kind @notice What happened; see the list above.
	Kind string
	// UserID @notice The account, when there is one. Empty on a failed login: the address may not
	// belong to an account at all, and resolving it to say so would be the enumeration channel the
	// rest of authn is built to close.
	UserID string
	// Email @notice The address the caller supplied, already lowercased.
	Email string
	// IP @notice The client address as Config.ClientIP attributed it. Empty when unknown.
	IP string
	// At @notice When kal observed it, filled by [Audit.Emit] when zero.
	At time.Time
	// Detail @notice Event-specific context. May be nil; treat every key as optional.
	Detail map[string]string
}

// Audit @notice Called for every security-relevant event. Nil discards them.
//
// @dev Same shape as authn.Mailer, and the same reasoning: kal ships no sink, because a sink is a
// dependency and every deployment already has one. Called synchronously, so an implementation
// that talks to the network must queue internally — kal will not grow a worker pool for it, the
// same note authn's notify carries.
//
// Deliberately not a table in kal's migrations: a consumer's audit table needs a tenant column
// and kal has no tenants. A hook composes; a table does not, and the hook can close over the
// tenant id so every event is attributed for free.
//
// The hook must not panic and must not block: it runs inside the request, and on the login path
// it runs inside the credential flow.
type Audit func(context.Context, Event)

// Emit @notice Delivers e, doing nothing when the hook is nil.
//
// @dev Exported because the emitters are other packages — authn and session — and an unexported
// method would be reachable only from here. The nil check lives in one place so no emit site
// carries one; a nil hook must be free rather than a branch each site remembered.
//
// At is defaulted here rather than at each site, which is what stops half the events arriving
// with a zero time. This is the *application* clock, unlike session.RecordMFA where now() is the
// database's — there the timestamp is a security decision several replicas must agree on, here it
// is a label on a record the consumer is about to store anyway.
//
// @param ctx the request context, passed through untouched
// @param e   the event; At is filled when zero
func (a Audit) Emit(ctx context.Context, e Event) {
	if a == nil {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	a(ctx, e)
}
