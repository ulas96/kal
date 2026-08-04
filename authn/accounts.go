package authn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/go-pg/pg/v10/types"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// scope values for auth_login_attempts.
const (
	scopeUser = "user"
	scopeIP   = "ip"
)

// identRe @notice Same rule as session's: the schema qualifier is the one string that lands in
// SQL text, so it is validated here too rather than trusted to have been validated elsewhere.
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// AccountsOptions @notice Configuration for NewAccounts. Hasher, Sessions and Mailer are
// required; the zero value of everything else is the production posture.
type AccountsOptions struct {
	Hasher   *Hasher
	Sessions *session.Sessions
	Mailer   Mailer

	// BaseURL @notice The origin every emailed link is built under, e.g.
	// "https://app.example.com". Required, and required to be configuration.
	//
	// @dev There is deliberately no way to derive this from the request. A link origin taken
	// from the Host header is Host-header injection: an attacker who can set that header turns
	// your password-reset email into a link to their own server.
	BaseURL string

	// CookieName @notice The session cookie Login and Logout manage. Default
	// session.DefaultCookieName.
	CookieName string

	// Schema @notice Optional Postgres schema holding the auth_* tables.
	Schema string

	// AllowUnverifiedLogin @notice Lets an account log in before its email is verified. Off by
	// default: the zero configuration requires verification, and turning this on is a visible,
	// named decision rather than a mode.
	AllowUnverifiedLogin bool
}

// Accounts @notice The credential flows: Login, Logout, ChangePassword — and, with the token
// flows, registration and recovery.
//
// @dev Methods take orm.DB like everything else in kal. Login is expected to run inside the
// session middleware (it reads request attribution and sets the cookie through the context);
// calling it without the middleware fails loudly rather than issuing a session no client will
// ever hold.
type Accounts struct {
	hasher          *Hasher
	sessions        *session.Sessions
	mailer          Mailer
	baseURL         string
	cookieName      string
	allowUnverified bool
	sql             statements
}

// NewAccounts @notice Validates opts and prepares the statements.
//
// @param opts    Hasher, Sessions and Mailer are required
// @return *Accounts ready for concurrent use
// @return error     a missing requirement or an invalid schema name
func NewAccounts(opts AccountsOptions) (*Accounts, error) {
	if opts.Hasher == nil || opts.Sessions == nil || opts.Mailer == nil {
		return nil, errors.New("authn: Hasher, Sessions and Mailer are all required — there is no default for any of them")
	}
	if err := ValidateBaseURL(opts.BaseURL); err != nil {
		return nil, err
	}
	a := &Accounts{
		hasher:          opts.Hasher,
		sessions:        opts.Sessions,
		mailer:          opts.Mailer,
		baseURL:         strings.TrimRight(opts.BaseURL, "/"),
		cookieName:      opts.CookieName,
		allowUnverified: opts.AllowUnverifiedLogin,
	}
	if a.cookieName == "" {
		a.cookieName = session.DefaultCookieName
	}
	prefix := ""
	if opts.Schema != "" {
		if !identRe.MatchString(opts.Schema) {
			return nil, errors.New("authn: table schema must match ^[a-z_][a-z0-9_]*$")
		}
		prefix = string(types.AppendIdent(nil, opts.Schema, 1)) + "."
	}
	a.sql = render(prefix)
	return a, nil
}

// ValidateBaseURL @notice Checks the origin emailed links are built under: absolute, https,
// and no path, query or fragment.
//
// @dev Required with no default, because the alternative — deriving it from the request Host
// header — is Host-header injection, and a password-reset link is the last place to accept
// attacker-controlled input. http:// is permitted only for loopback, so local development
// works without a flag that would eventually be set in production.
//
// @param raw the configured origin
// @return error a description of what is wrong with it, or nil
func ValidateBaseURL(raw string) error {
	if raw == "" {
		return errors.New("authn: BaseURL is required — emailed links have no origin without it, and taking one from the request Host header is Host-header injection")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("authn: BaseURL is not a URL: %w", err)
	}
	if u.Host == "" {
		return errors.New("authn: BaseURL must be absolute, e.g. https://app.example.com")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("authn: BaseURL must not carry a query or fragment")
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return errors.New("authn: BaseURL must be https outside localhost")
	}
	return nil
}

// isLoopback @notice Whether a hostname is the local machine, for the https exemption.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// invalidCredentials @notice The one authentication failure. The message is a package-level
// constant precisely so every failing path is byte-identical on the wire (ASVS 6.3.8) — the
// cause parameter goes only to the log.
func invalidCredentials(cause error) error {
	return &kalerr.Error{Code: kalerr.CodeInvalidCredentials, Message: "invalid email or password", Internal: cause}
}

// Login @notice Verifies the credential and, on success, issues a session and sets the cookie.
//
// @dev The order of operations is the design:
//
//  1. Backoff check, before any hashing — otherwise the throttle still costs 19 MiB and a CPU
//     slice per rejected attempt, and the defence is the DoS.
//  2. Account select; an unknown, deleted or password-less account burns a real dummy
//     verification so its timing matches a wrong password (see Hasher.VerifyDummy).
//  3. Argon2 verify inside the concurrency bound; a weaker-than-configured stored hash is
//     re-hashed on the spot — the only moment the cleartext exists to do it with.
//  4. Unknown user, wrong password, unverified and disabled all return the identical
//     INVALID_CREDENTIALS; the real reason goes to the log via Internal.
//  5. Success resets the counters, notifies on a many-failures-then-success pattern, revokes
//     any session the request arrived with (it is being replaced), issues a fresh one and sets
//     the cookie — issuing-new-on-login is the fixation defence at this layer.
//
// @param email    matched case-insensitively; stored form decides the mailbox
// @param password verified exactly as received
// @return *authz.Principal the caller as the next request will see them
// @return error   INVALID_CREDENTIALS, RATE_LIMITED, or a driver/mailer failure
func (a *Accounts) Login(ctx context.Context, db orm.DB, email, password string) (*authz.Principal, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	meta := session.MetaFromContext(ctx)

	priorFailures, err := a.checkBackoff(ctx, db, email, meta.IP)
	if err != nil {
		return nil, err
	}

	var userID, storedHash string
	var verified bool
	_, err = db.QueryOneContext(ctx, pg.Scan(&userID, &storedHash, &verified), a.sql.loginSelect, email)
	switch {
	case errors.Is(err, pg.ErrNoRows), err == nil && storedHash == "":
		if derr := a.hasher.VerifyDummy(ctx, password); derr != nil {
			return nil, derr // the bound said no; RATE_LIMITED, not a credential verdict
		}
		a.recordFailure(ctx, db, email, meta.IP)
		return nil, invalidCredentials(nil)
	case err != nil:
		return nil, err
	}

	ok, rehash, err := a.hasher.Verify(ctx, password, storedHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		a.recordFailure(ctx, db, email, meta.IP)
		return nil, invalidCredentials(nil)
	}
	if !verified && !a.allowUnverified {
		return nil, invalidCredentials(errors.New("email not verified"))
	}

	if rehash {
		a.rehashStored(ctx, db, userID, password, storedHash)
	}
	if priorFailures >= suspiciousFailures {
		a.notify(ctx, email, Message{
			Kind:    KindSuspiciousLogin,
			Subject: "New sign-in to your account",
			Text:    "Your account just signed in successfully after several failed attempts. If this was not you, change your password now.",
		})
	}
	a.resetBackoff(ctx, db, email, meta.IP)

	if prior, ok := authz.From(ctx); ok {
		// The request arrived already holding a session; it is being replaced, so it dies.
		if err := a.sessions.Revoke(ctx, db, prior.SessionID); err != nil {
			return nil, err
		}
	}
	token, err := a.sessions.Issue(ctx, db, userID, meta)
	if err != nil {
		return nil, err
	}
	p, err := a.sessions.Lookup(ctx, db, token)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("authn: freshly issued session did not resolve")
	}
	if err := session.SetCookie(ctx, session.Cookie(a.cookieName, token)); err != nil {
		return nil, err
	}
	return p, nil
}

// Logout @notice Revokes the caller's session and clears the cookie. Anonymous callers just
// get the cookie cleared — logging out twice is not an error.
//
// @return error a driver failure, or the missing-middleware error from SetCookie
func (a *Accounts) Logout(ctx context.Context, db orm.DB) error {
	if p, ok := authz.From(ctx); ok {
		if err := a.sessions.Revoke(ctx, db, p.SessionID); err != nil {
			return err
		}
	}
	return session.SetCookie(ctx, session.ClearCookie(a.cookieName))
}

// ChangePassword @notice Re-verifies the current password, stores the new one, and rotates the
// caller's session — a privilege change never rides on the old credential (ASVS 7.2.4).
//
// @dev Rotate, not RevokeAllForUser: a routine change keeps other devices signed in. The
// recovery path (password reset) is the one that kills everything, because there the password
// is presumed compromised. The hash write is compare-and-swap on the verified hash, so two
// concurrent changes cannot silently clobber each other.
//
// @param current the password being replaced; a mismatch counts as a login failure
// @param next    the replacement; policy-checked here
// @return error  UNAUTHENTICATED, INVALID_CREDENTIALS, INVALID_INPUT, RATE_LIMITED, or driver
func (a *Accounts) ChangePassword(ctx context.Context, db orm.DB, current, next string) error {
	p, err := authz.Require(ctx)
	if err != nil {
		return err
	}
	if err := ValidatePassword(next); err != nil {
		return err
	}

	var storedHash, email string
	_, err = db.QueryOneContext(ctx, pg.Scan(&storedHash, &email), a.sql.hashByID, p.UserID)
	if errors.Is(err, pg.ErrNoRows) {
		return &kalerr.Error{Code: kalerr.CodeUnauthenticated, Message: "authentication required", Internal: err}
	}
	if err != nil {
		return err
	}
	if storedHash == "" {
		return invalidCredentials(errors.New("account has no password"))
	}

	ok, _, err := a.hasher.Verify(ctx, current, storedHash)
	if err != nil {
		return err
	}
	if !ok {
		meta := session.MetaFromContext(ctx)
		a.recordFailure(ctx, db, strings.ToLower(email), meta.IP)
		return invalidCredentials(nil)
	}

	newHash, err := a.hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	res, err := db.ExecContext(ctx, a.sql.updatePassword, newHash, p.UserID, storedHash)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return invalidCredentials(errors.New("password changed concurrently"))
	}

	token, err := a.sessions.Rotate(ctx, db, p.SessionID)
	if err != nil {
		return err
	}
	if err := session.SetCookie(ctx, session.Cookie(a.cookieName, token)); err != nil {
		return err
	}
	a.notify(ctx, email, Message{
		Kind:    KindPasswordChanged,
		Subject: "Your password was changed",
		Text:    "Your account password was just changed. If this was not you, reset it immediately and review your sessions.",
	})
	return nil
}

// checkBackoff @notice Both counters in one round trip; returns the account's current failure
// count for the suspicious-login notice, or RATE_LIMITED while a window is open.
func (a *Accounts) checkBackoff(ctx context.Context, db orm.DB, emailKey, ip string) (int, error) {
	var rows []struct {
		Scope    string  `pg:"scope"`
		Failures int     `pg:"failures"`
		Age      float64 `pg:"age"`
	}
	if _, err := db.QueryContext(ctx, &rows, a.sql.attempts, emailKey, ip); err != nil {
		return 0, err
	}
	userFailures := 0
	for _, r := range rows {
		if r.Scope == scopeUser {
			userFailures = r.Failures
		}
		if wait := delayFor(r.Scope, r.Failures); wait > 0 && r.Age < wait.Seconds() {
			return userFailures, &kalerr.Error{
				Code:    kalerr.CodeRateLimited,
				Message: "too many attempts, try again shortly",
			}
		}
	}
	return userFailures, nil
}

// recordFailure / resetBackoff @notice Best-effort counter writes: a failure to record a
// failure is logged, never allowed to change the login verdict.
func (a *Accounts) recordFailure(ctx context.Context, db orm.DB, emailKey, ip string) {
	var err error
	if ip == "" {
		_, err = db.ExecContext(ctx, a.sql.recordUser, emailKey)
	} else {
		_, err = db.ExecContext(ctx, a.sql.recordBoth, emailKey, ip)
	}
	if err != nil {
		log.Printf("kal/authn: recording login failure: %v", err)
	}
}

func (a *Accounts) resetBackoff(ctx context.Context, db orm.DB, emailKey, ip string) {
	if _, err := db.ExecContext(ctx, a.sql.resetAttempts, emailKey, ip); err != nil {
		log.Printf("kal/authn: resetting login counters: %v", err)
	}
}

// rehashStored @notice Upgrades a weaker-than-configured hash while the cleartext is in hand.
// Best-effort and compare-and-swap: losing the race to a concurrent change just means skipping
// the upgrade until the next login.
func (a *Accounts) rehashStored(ctx context.Context, db orm.DB, userID, password, oldHash string) {
	newHash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		log.Printf("kal/authn: rehash-on-login: %v", err)
		return
	}
	if _, err := db.ExecContext(ctx, a.sql.updatePassword, newHash, userID, oldHash); err != nil {
		log.Printf("kal/authn: rehash-on-login: %v", err)
	}
}

// notify @notice Best-effort mail. ponytail: synchronous — a consumer whose Mailer talks to a
// slow SMTP relay should queue inside their Send; kal will not grow a worker pool for it.
func (a *Accounts) notify(ctx context.Context, to string, msg Message) {
	if err := a.mailer.Send(ctx, to, msg); err != nil {
		log.Printf("kal/authn: sending %s mail: %v", msg.Kind, err)
	}
}
