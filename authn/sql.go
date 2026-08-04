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
