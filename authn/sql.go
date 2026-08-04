package authn

import "fmt"

// Every SQL statement the package runs lives in this file (kal-wide rule; see session/sql.go
// for the reasoning). %[1]s is the optional schema qualifier rendered once by NewAccounts.

// render @notice Bakes the schema qualifier into every statement, once, at construction.
func render(prefix string) statements {
	return statements{
		loginSelect:    fmt.Sprintf(loginSelectSQL, prefix),
		hashByID:       fmt.Sprintf(hashByIDSQL, prefix),
		updatePassword: fmt.Sprintf(updatePasswordSQL, prefix),
		attempts:       fmt.Sprintf(attemptsSQL, prefix),
		recordBoth:     fmt.Sprintf(recordBothSQL, prefix),
		recordUser:     fmt.Sprintf(recordUserSQL, prefix),
		resetAttempts:  fmt.Sprintf(resetAttemptsSQL, prefix),
		insertUser:     fmt.Sprintf(insertUserSQL, prefix),
		insertInvitee:  fmt.Sprintf(insertInviteeSQL, prefix),
		userIDByEmail:  fmt.Sprintf(userIDByEmailSQL, prefix),
		emailByID:      fmt.Sprintf(emailByIDSQL, prefix),
		insertToken:    fmt.Sprintf(insertTokenSQL, prefix),
		consumeToken:   fmt.Sprintf(consumeTokenSQL, prefix),
		setPassword:    fmt.Sprintf(setPasswordSQL, prefix),
		markVerified:   fmt.Sprintf(markVerifiedSQL, prefix),
	}
}

type statements struct {
	loginSelect    string
	hashByID       string
	updatePassword string
	attempts       string
	recordBoth     string
	recordUser     string
	resetAttempts  string
	insertUser     string
	insertInvitee  string
	userIDByEmail  string
	emailByID      string
	insertToken    string
	consumeToken   string
	setPassword    string
	markVerified   string
}

// loginSelectSQL @notice The account as the login path sees it. deleted_at gates here, so a
// disabled account and an absent one are the same row count — and therefore the same error and
// the same dummy-verify timing.
const loginSelectSQL = `
select id, coalesce(password_hash, '') as password_hash, email_verified
  from %[1]sauth_users
 where lower(email) = ? and deleted_at is null`

// hashByIDSQL @notice The stored hash for an authenticated flow (password change).
const hashByIDSQL = `
select coalesce(password_hash, '') as password_hash, email
  from %[1]sauth_users
 where id = ? and deleted_at is null`

// updatePasswordSQL @notice Writes a new hash, compare-and-swap on the old one.
//
// @dev The third parameter is the hash this flow verified against. If a concurrent request
// changed it in between, zero rows match and the caller reports a conflict instead of silently
// clobbering the other change — the same absent-row discipline crud.Update documents.
// #nosec G101 -- SQL text with bound parameters, not a credential
const updatePasswordSQL = `
update %[1]sauth_users
   set password_hash = ?, updated_at = now()
 where id = ? and password_hash = ?`

// attemptsSQL @notice Both counters and their age in one round trip.
//
// @dev The age is computed on the database clock (now() - last_fail) rather than compared
// against the application's — last_fail was written with the database's now(), and two clocks
// that never meet cannot drift.
const attemptsSQL = `
select scope, failures, extract(epoch from now() - last_fail)::float8 as age
  from %[1]sauth_login_attempts
 where (scope, key) in (('user', ?), ('ip', ?))`

// recordBothSQL / recordUserSQL @notice One failure, upserted; the ip row only when there is
// an address to charge it to.
const recordBothSQL = `
insert into %[1]sauth_login_attempts (scope, key, failures, last_fail)
values ('user', ?, 1, now()), ('ip', ?, 1, now())
on conflict (scope, key)
do update set failures = auth_login_attempts.failures + 1, last_fail = now()`

const recordUserSQL = `
insert into %[1]sauth_login_attempts (scope, key, failures, last_fail)
values ('user', ?, 1, now())
on conflict (scope, key)
do update set failures = auth_login_attempts.failures + 1, last_fail = now()`

// resetAttemptsSQL @notice A successful login clears both counters — the backoff punishes
// streaks, not history.
const resetAttemptsSQL = `
delete from %[1]sauth_login_attempts
 where (scope, key) in (('user', ?), ('ip', ?))`

// insertUserSQL @notice Registration's insert. Zero rows returned means the address is already
// a live account.
//
// @dev ON CONFLICT DO NOTHING rather than letting 23505 surface, because the caller must not be
// able to tell the two outcomes apart and an error is a difference. The conflict target names
// the partial index by predicate — a bare `(lower(email))` does not match a partial index, and
// Postgres rejects the statement rather than silently ignoring the clause.
const insertUserSQL = `
insert into %[1]sauth_users (email, password_hash)
values (?, ?)
on conflict (lower(email)) where deleted_at is null do nothing
returning id`

// insertInviteeSQL @notice The same insert with no password: an invited account has none until
// the invitation is accepted, which is what the nullable password_hash column is for.
const insertInviteeSQL = `
insert into %[1]sauth_users (email)
values (?)
on conflict (lower(email)) where deleted_at is null do nothing
returning id`

const userIDByEmailSQL = `
select id from %[1]sauth_users where lower(email) = ? and deleted_at is null`

const emailByIDSQL = `
select email from %[1]sauth_users where id = ? and deleted_at is null`

// insertTokenSQL @notice One row per emailed token, storing only the SHA-256 and computing the
// expiry on the database clock.
//
// @dev ON CONFLICT DO UPDATE on the hash is unreachable in practice — the input is 256 bits of
// CSPRNG — but a primary-key collision must not surface as an error the caller can distinguish.
// #nosec G101 -- SQL text with bound parameters, not a credential
const insertTokenSQL = `
insert into %[1]sauth_tokens (token_sha256, user_id, purpose, expires_at)
values (?, ?, ?, now() + make_interval(secs => ?))
on conflict (token_sha256) do update
   set user_id = excluded.user_id,
       purpose = excluded.purpose,
       expires_at = excluded.expires_at,
       consumed_at = null`

// consumeTokenSQL @notice The whole single-use design, in one statement.
//
// @dev Never a read-then-write: that shape leaves a window in which a double-submitted link is
// consumed twice, and a double-clicked email link — or a mail client prefetching URLs — is an
// ordinary event. Zero rows means invalid, expired, already used or wrong purpose, and the
// caller cannot tell which.
// #nosec G101 -- SQL text with bound parameters, not a credential
const consumeTokenSQL = `
update %[1]sauth_tokens
   set consumed_at = now()
 where token_sha256 = ?
   and purpose = ?
   and consumed_at is null
   and expires_at > now()
returning user_id`

// #nosec G101 -- SQL text with bound parameters, not a credential
const setPasswordSQL = `
update %[1]sauth_users set password_hash = ?, updated_at = now() where id = ?`

const markVerifiedSQL = `
update %[1]sauth_users set email_verified = true, updated_at = now() where id = ?`
