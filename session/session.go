// Package session @notice Opaque server-side sessions in Postgres — kal's primary credential.
//
// @dev Sessions in the application's own database is the design position of the whole library:
// revocation is an UPDATE, "log out everywhere" is one statement, a user can see their own
// devices, and because the session cookie is the long-lived credential there is no
// refresh-token subsystem — no rotating families, no reuse detection, no two-tab race. The
// honest cost is one indexed SELECT per authenticated request, and it is worth paying; if it
// ever measurably is not, the upgrade is a short-TTL in-process cache keyed on the token hash,
// at which point the cache TTL becomes the revocation SLA. Measure first.
//
// There is deliberately no Store interface. Postgres is the premise — the lookup JOINs the
// users and roles tables, which is exactly what an abstraction over "some backend" would
// forbid. All SQL sits in sql.go; that file is the seam if a driver swap ever becomes real.
package session

import (
	"context"
	"errors"
	"net"
	"regexp"
	"sort"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/go-pg/pg/v10/types"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
)

// Defaults for the two expiries. Both are enforced on every lookup (ASVS 7.3.1, 7.3.2): idle
// alone lets an active session live forever; absolute alone logs a working user out mid-task.
const (
	// DefaultIdle @notice The rolling window a session survives without a request.
	DefaultIdle = 12 * time.Hour
	// DefaultAbsolute @notice The hard lifetime, anchored at authentication, never extended.
	DefaultAbsolute = 14 * 24 * time.Hour
)

// identRe @notice What a schema qualifier may look like. Anything else is rejected at
// construction — the qualifier is the one string that ends up inside SQL text.
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Options @notice Configuration for NewSessions. The zero value is the production posture.
type Options struct {
	// Idle @notice Rolling inactivity timeout. Zero means DefaultIdle.
	Idle time.Duration
	// Absolute @notice Hard session lifetime. Zero means DefaultAbsolute. Must not be shorter
	// than Idle.
	Absolute time.Duration
	// Schema @notice Optional Postgres schema holding the auth_* tables. Empty means the
	// connection's search_path decides, which is the default install.
	Schema string
}

// Sessions @notice Issues, resolves, rotates and revokes sessions.
//
// @dev Carries no *pg.DB: every method takes orm.DB, so *pg.DB, *pg.Conn and *pg.Tx all work
// and a caller can put session changes inside the same transaction as the change that
// motivated them — "create user and issue session" or "reset password and revoke everything"
// commit or roll back as one.
type Sessions struct {
	idle     time.Duration
	absolute time.Duration
	sql      statements
}

// statements @notice The SQL from sql.go with the schema qualifier rendered in, once.
type statements struct {
	issue, lookup, rotate, revoke, revokeAll, list string
}

// NewSessions @notice Validates opts and prepares the statements.
//
// @dev The schema name is validated against identRe and then quoted with go-pg's own ident
// writer — belt and braces, because it is the single string interpolated into SQL text rather
// than bound as a parameter. An absolute lifetime shorter than the idle timeout is a
// configuration that silently disables the idle refresh, so it is rejected loudly instead.
//
// @param opts     zero-value fields take the defaults above
// @return *Sessions ready for concurrent use
// @return error     an invalid schema name, or Absolute < Idle
func NewSessions(opts Options) (*Sessions, error) {
	s := &Sessions{idle: opts.Idle, absolute: opts.Absolute}
	if s.idle == 0 {
		s.idle = DefaultIdle
	}
	if s.absolute == 0 {
		s.absolute = DefaultAbsolute
	}
	if s.absolute < s.idle {
		return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput,
			Message: "session absolute lifetime must not be shorter than the idle timeout"}
	}
	prefix := ""
	if opts.Schema != "" {
		if !identRe.MatchString(opts.Schema) {
			return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput,
				Message: "table schema must match ^[a-z_][a-z0-9_]*$"}
		}
		prefix = string(types.AppendIdent(nil, opts.Schema, 1)) + "."
	}
	s.sql = render(prefix)
	return s, nil
}

// Meta @notice What Issue records about the request that created the session — the raw
// material of a "your devices" page and of suspicious-login notices.
type Meta struct {
	UserAgent string
	// IP @notice Best-effort client address. Parsed here; anything net.ParseIP rejects is
	// stored as NULL rather than failing the login over a mangled forwarding header.
	IP string
}

// Info @notice One row of List: a live session as shown to its owner.
//
// @dev The pg tags are explicit rather than left to name inference, because go-pg's
// camel-to-snake guess for initialisms (MFAAt) is exactly the kind of silent mismatch that
// scans a column into nothing.
type Info struct {
	ID         string    `pg:"id"`
	CreatedAt  time.Time `pg:"created_at"`
	LastSeenAt time.Time `pg:"last_seen_at"`
	UserAgent  string    `pg:"user_agent"`
	IP         string    `pg:"ip"`
	MFAAt      time.Time `pg:"mfa_at"` // zero when MFA was never satisfied on this session
}

// Issue @notice Creates a session for userID and returns the raw token — the only moment it
// exists outside the client.
//
// @param userID the auth_users id
// @param meta   request attribution; zero value is fine
// @return token the credential to put in the cookie; only its hash is stored
// @return err   any driver error
func (s *Sessions) Issue(ctx context.Context, db orm.DB, userID string, meta Meta) (string, error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", err
	}
	var ip any
	if parsed := net.ParseIP(meta.IP); parsed != nil {
		ip = parsed.String()
	}
	var ua any
	if meta.UserAgent != "" {
		ua = meta.UserAgent
	}
	var id string
	if _, err := db.QueryOneContext(ctx, pg.Scan(&id), s.sql.issue,
		hash, userID, s.idle.Seconds(), s.absolute.Seconds(), ua, ip); err != nil {
		return "", err
	}
	return token, nil
}

// Lookup @notice Resolves a wire token to the caller, or to anonymous — never to an error for
// a merely bad token.
//
// @dev One statement, one round trip: session liveness, the user (dropped the moment
// deleted_at is set), and the roles — read fresh here rather than frozen at login, so revoking
// a role takes effect on the holder's next request at no extra cost. The same statement
// refreshes the idle window, at most once per 60 seconds (see lookupSQL).
//
// @param token the cookie value; arbitrary bytes are safe
// @return *authz.Principal the caller, or nil for unknown, expired, revoked or disabled
// @return error            only a driver failure — absence is (nil, nil)
func (s *Sessions) Lookup(ctx context.Context, db orm.DB, token string) (*authz.Principal, error) {
	p := &authz.Principal{}
	var roles []string
	_, err := db.QueryOneContext(ctx,
		pg.Scan(&p.SessionID, &p.UserID, &p.AuthAt, &p.MFAAt, &p.Email, &p.Verified, pg.Array(&roles)),
		s.sql.lookup, HashToken(token), s.idle.Seconds())
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	sort.Strings(roles) // array_agg order is unspecified; make it deterministic for callers
	p.Roles = roles
	return p, nil
}

// Rotate @notice Swaps the session's credential and returns the new token. Call it on every
// privilege change: login over an existing cookie, password change, MFA satisfaction,
// impersonation start or stop.
//
// @dev This is the session-fixation fix (ASVS 7.2.4): a token an attacker planted or observed
// before the privilege change must not survive it. Identity, created_at and the absolute
// deadline stay — rotation refreshes the credential, not the session's age.
//
// @param sessionID the id from the caller's Principal
// @return token    the replacement credential
// @return err      UNAUTHENTICATED when the session is no longer live, or a driver error
func (s *Sessions) Rotate(ctx context.Context, db orm.DB, sessionID string) (string, error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", err
	}
	var userID string
	if _, err := db.QueryOneContext(ctx, pg.Scan(&userID), s.sql.rotate,
		hash, s.idle.Seconds(), sessionID); err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return "", &kalerr.Error{Code: kalerr.CodeUnauthenticated,
				Message: "session is no longer valid", Internal: err}
		}
		return "", err
	}
	return token, nil
}

// Revoke @notice Terminates one session. Idempotent.
//
// @param sessionID the session to kill; unknown or already-revoked is not an error
// @return error    any driver error
func (s *Sessions) Revoke(ctx context.Context, db orm.DB, sessionID string) error {
	_, err := db.ExecContext(ctx, s.sql.revoke, sessionID)
	return err
}

// RevokeAllForUser @notice Terminates every live session of one user — password reset, account
// disable, "log out everywhere" (ASVS 7.4.2).
//
// @param userID the auth_users id
// @return error any driver error
func (s *Sessions) RevokeAllForUser(ctx context.Context, db orm.DB, userID string) error {
	_, err := db.ExecContext(ctx, s.sql.revokeAll, userID)
	return err
}

// List @notice The user's live sessions, most recently active first.
//
// @param userID the auth_users id
// @return []Info one row per live session; empty, never nil
// @return error  any driver error
func (s *Sessions) List(ctx context.Context, db orm.DB, userID string) ([]Info, error) {
	var out []Info
	res, err := db.QueryContext(ctx, &out, s.sql.list, userID)
	if err != nil {
		return nil, err
	}
	if res.RowsReturned() == 0 {
		return []Info{}, nil
	}
	return out, nil
}
