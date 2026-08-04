package session

import "fmt"

// Every SQL statement the package runs lives in this file (kal-wide rule): go-pg is in
// maintenance mode, and confining the SQL to one greppable file per package is the migration
// plan — a future driver swap rewrites a bounded surface instead of an archaeology project.
//
// %[1]s is the optional schema qualifier rendered once by NewSessions; every other value is a
// bound parameter.

// render @notice Bakes the schema qualifier into every statement, once, at construction.
func render(prefix string) statements {
	return statements{
		issue:     fmt.Sprintf(issueSQL, prefix),
		lookup:    fmt.Sprintf(lookupSQL, prefix),
		rotate:    fmt.Sprintf(rotateSQL, prefix),
		revoke:    fmt.Sprintf(revokeSQL, prefix),
		revokeAll: fmt.Sprintf(revokeAllSQL, prefix),
		list:      fmt.Sprintf(listSQL, prefix),
	}
}

// issueSQL @notice Creates the row. Expiries are computed on the database clock — one time
// authority, so N app replicas with drifting clocks cannot disagree about liveness.
const issueSQL = `
insert into %[1]sauth_sessions (token_sha256, user_id, idle_expires_at, expires_at, user_agent, ip)
values (?, ?, now() + make_interval(secs => ?), now() + make_interval(secs => ?), ?, ?)
returning id`

// lookupSQL @notice The one round trip per authenticated request: resolve the token to a live
// session, its user, and the user's roles, and refresh the idle window — all in a single
// statement.
//
// @dev The join on u.deleted_at is what terminates every session the moment an account is
// disabled, whether or not anyone remembered to call RevokeAllForUser. Roles ride the same
// round trip via array_agg, so a role revocation takes effect on the holder's very next
// request — no waiting for their session to rotate.
//
// The touched CTE refreshes last_seen_at and the idle window at most once per 60 seconds.
// ponytail: idle expiry has 60s granularity, because refreshing it on literally every request
// turns one read into one write. Tighten the interval if your idle timeout is measured in
// minutes.
const lookupSQL = `
with live as (
    select s.id, s.user_id, s.created_at, s.mfa_at
      from %[1]sauth_sessions s
     where s.token_sha256 = ?
       and s.revoked_at is null
       and s.idle_expires_at > now()
       and s.expires_at > now()
),
touched as (
    update %[1]sauth_sessions s
       set last_seen_at = now(), idle_expires_at = now() + make_interval(secs => ?)
      from live
     where s.id = live.id
       and s.last_seen_at < now() - interval '60 seconds'
)
select live.id, live.user_id, live.created_at, live.mfa_at,
       u.email, u.email_verified,
       coalesce(array_agg(r.role) filter (where r.role is not null), '{}')
  from live
  join %[1]sauth_users u on u.id = live.user_id and u.deleted_at is null
  left join %[1]sauth_user_roles r on r.user_id = live.user_id
 group by live.id, live.user_id, live.created_at, live.mfa_at, u.email, u.email_verified`

// rotateSQL @notice Swaps the credential under a live session, keeping identity, creation time
// and the absolute deadline.
//
// @dev The WHERE repeats the full liveness predicate: a revoked or expired session must not be
// resurrectable by rotation. expires_at is deliberately not touched — the absolute lifetime is
// anchored at authentication and never extended, or it would not be absolute.
const rotateSQL = `
update %[1]sauth_sessions
   set token_sha256 = ?, last_seen_at = now(),
       idle_expires_at = now() + make_interval(secs => ?)
 where id = ?
   and revoked_at is null
   and idle_expires_at > now()
   and expires_at > now()
returning user_id`

// revokeSQL @notice Terminates one session. Idempotent: revoking twice is not an error.
const revokeSQL = `
update %[1]sauth_sessions set revoked_at = now()
 where id = ? and revoked_at is null`

// revokeAllSQL @notice Terminates every live session of one user — password reset, account
// disable, "log out everywhere".
const revokeAllSQL = `
update %[1]sauth_sessions set revoked_at = now()
 where user_id = ? and revoked_at is null`

// listSQL @notice The user's live sessions, most recently seen first — what a "your devices"
// page renders (ASVS 7.4: users see and revoke their own sessions).
const listSQL = `
select id, created_at, last_seen_at,
       coalesce(user_agent, '') as user_agent,
       coalesce(host(ip), '')   as ip,  -- host(), not ::text — the cast drags a /32 along
       mfa_at
  from %[1]sauth_sessions
 where user_id = ?
   and revoked_at is null
   and idle_expires_at > now()
   and expires_at > now()
 order by last_seen_at desc`
