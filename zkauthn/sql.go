package zkauthn

import "fmt"

type statements struct {
	issueChallenge, peekChallenge, consumeChallenge, upsertCommitment, commitmentByUser, setMFA string
	passwordHashByUser                                                                          string
	lockTree, nextLeaf, insertCredential, credentialByIndex, credentialsByUser                  string
	nodeByPosition, upsertNode, deleteNode, retireRoot, insertRoot, currentRoot, rootAccepted   string
	markRevoked, upsertClaim, claimByName, bindRecurringNullifier, oneShotNullifier             string
	resolveNullifier, createNullifier, storeSessionClaim                                        string
}

func render(prefix string) statements {
	return statements{
		issueChallenge:         fmt.Sprintf(issueChallengeSQL, prefix),
		peekChallenge:          fmt.Sprintf(peekChallengeSQL, prefix),
		consumeChallenge:       fmt.Sprintf(consumeChallengeSQL, prefix),
		upsertCommitment:       fmt.Sprintf(upsertCommitmentSQL, prefix),
		commitmentByUser:       fmt.Sprintf(commitmentByUserSQL, prefix),
		passwordHashByUser:     fmt.Sprintf(passwordHashByUserSQL, prefix),
		setMFA:                 fmt.Sprintf(setMFASQL, prefix),
		lockTree:               lockTreeSQL,
		nextLeaf:               fmt.Sprintf(nextLeafSQL, prefix),
		insertCredential:       fmt.Sprintf(insertCredentialSQL, prefix),
		credentialByIndex:      fmt.Sprintf(credentialByIndexSQL, prefix),
		credentialsByUser:      fmt.Sprintf(credentialsByUserSQL, prefix),
		nodeByPosition:         fmt.Sprintf(nodeByPositionSQL, prefix),
		upsertNode:             fmt.Sprintf(upsertNodeSQL, prefix),
		deleteNode:             fmt.Sprintf(deleteNodeSQL, prefix),
		retireRoot:             fmt.Sprintf(retireRootSQL, prefix),
		insertRoot:             fmt.Sprintf(insertRootSQL, prefix),
		currentRoot:            fmt.Sprintf(currentRootSQL, prefix),
		rootAccepted:           fmt.Sprintf(rootAcceptedSQL, prefix),
		markRevoked:            fmt.Sprintf(markRevokedSQL, prefix),
		upsertClaim:            fmt.Sprintf(upsertClaimSQL, prefix),
		claimByName:            fmt.Sprintf(claimByNameSQL, prefix),
		resolveNullifier:       fmt.Sprintf(resolveNullifierSQL, prefix),
		createNullifier:        fmt.Sprintf(createNullifierSQL, prefix),
		bindRecurringNullifier: fmt.Sprintf(bindRecurringNullifierSQL, prefix),
		oneShotNullifier:       fmt.Sprintf(oneShotNullifierSQL, prefix),
		storeSessionClaim:      fmt.Sprintf(storeSessionClaimSQL, prefix),
	}
}

const issueChallengeSQL = `
with deleted as (
    delete from %[1]sauth_zk_challenges where expires_at < now()
)
insert into %[1]sauth_zk_challenges
       (challenge, session_id, purpose, field, expires_at)
values (?, ?, ?, ?, now() + interval '60 seconds')`

// peekChallengeSQL fetches the field a proof was built against so verification can run outside any
// transaction. It decides nothing: freshness is consumeChallengeSQL's single-use UPDATE and only
// that. Never promote this SELECT into the authorization decision — read-then-write leaves a window
// two concurrent submissions both pass through (gotcha 36).
const peekChallengeSQL = `
select field from %[1]sauth_zk_challenges
 where challenge = ?
   and purpose = ?
   and session_id is not distinct from ?
   and consumed_at is null
   and expires_at > now()`

// consumeChallengeSQL binds purpose and session in the same single-use update. IS NOT
// DISTINCT FROM is what makes a null session an explicit anonymous-login challenge rather
// than a wildcard that could elevate an existing session.
const consumeChallengeSQL = `
update %[1]sauth_zk_challenges
   set consumed_at = now()
 where challenge = ?
   and purpose = ?
   and session_id is not distinct from ?
   and consumed_at is null
   and expires_at > now()
returning field`

const upsertCommitmentSQL = `
insert into %[1]sauth_zk_commitments (user_id, commitment)
values (?, ?)
on conflict (user_id) do update
set commitment = excluded.commitment, created_at = now()`

const commitmentByUserSQL = `
select commitment from %[1]sauth_zk_commitments where user_id = ?`

// Declared here rather than reached for in authn: all SQL for a package lives in that package's
// one sql.go, so a schema change has one place per package to be found. coalesce keeps the scan
// on a string — a null password_hash is an account that has none, not a driver error.
// #nosec G101 -- SQL text with bound parameters, not a credential
const passwordHashByUserSQL = `
select coalesce(password_hash, '') from %[1]sauth_users where id = ? and deleted_at is null`

const setMFASQL = `
update %[1]sauth_sessions
   set mfa_at = now()
 where id = ? and user_id = ? and revoked_at is null
   and idle_expires_at > now() and expires_at > now()
returning id`

// One lock for one root. The numeric key is stable and package-specific.
const lockTreeSQL = `select pg_advisory_xact_lock(715056534291)`

const nextLeafSQL = `
select coalesce(max(leaf_index) + 1, 0) from %[1]sauth_zk_credentials`

// #nosec G101 -- SQL text with bound parameters, not a credential
const insertCredentialSQL = `
insert into %[1]sauth_zk_credentials (leaf_index, commitment, issued_to)
values (?, ?, nullif(?, '')::uuid)`

const credentialByIndexSQL = `
select commitment, revoked_at is not null
  from %[1]sauth_zk_credentials where leaf_index = ?`

// #nosec G101 -- SQL text with bound parameters, not a credential
const credentialsByUserSQL = `
select leaf_index from %[1]sauth_zk_credentials
 where issued_to = ? and revoked_at is null order by leaf_index`

const nodeByPositionSQL = `
select hash from %[1]sauth_zk_nodes where level = ? and idx = ?`

const upsertNodeSQL = `
insert into %[1]sauth_zk_nodes (level, idx, hash) values (?, ?, ?)
on conflict (level, idx) do update set hash = excluded.hash`

const deleteNodeSQL = `delete from %[1]sauth_zk_nodes where level = ? and idx = ?`

const retireRootSQL = `
update %[1]sauth_zk_roots set retired_at = now() where retired_at is null`

// A sparse root is a pure function of the leaf set, so any mutation returning the tree to a set it
// has published before recomputes a root already in the table — revoking the highest live leaf does
// it. Bare, the insert raised 23505, aborted the transaction and rolled markRevoked back with it,
// leaving revoked_at null and the leaf still proving membership. Republishing is not a collision to
// work around; it is what the tree means. Safe because retireRoot ran immediately before in the
// same transaction, so no other row has retired_at null and auth_zk_roots_current_key still admits
// exactly one current root. created_at stays put: rootAccepted keys off retired_at, and
// first-published-at is the more useful timestamp.
const insertRootSQL = `
insert into %[1]sauth_zk_roots (root) values (?)
on conflict (root) do update set retired_at = null`

const currentRootSQL = `
select root from %[1]sauth_zk_roots where retired_at is null`

const rootAcceptedSQL = `
select exists (
    select 1 from %[1]sauth_zk_roots
     where root = ?
       and (retired_at is null or (? > 0 and retired_at > now() - make_interval(secs => ?)))
)`

const markRevokedSQL = `
update %[1]sauth_zk_credentials set revoked_at = now()
 where leaf_index = ? and revoked_at is null
returning commitment`

const upsertClaimSQL = `
insert into %[1]sauth_zk_claims (claim, audience, threshold, kind, allows_login)
values (?, ?, ?, ?, ?)
on conflict (claim) do update
set audience = excluded.audience, threshold = excluded.threshold, kind = excluded.kind,
    allows_login = excluded.allows_login`

const claimByNameSQL = `
select audience, threshold, kind, allows_login from %[1]sauth_zk_claims where claim = ?`

// resolveNullifierSQL reads only. The u.email predicate is what confines a recurring login to the
// pseudonym its own nullifier derives: without it, a nullifier that ProveClaim had bound to a real
// password-holding account resolves to that account and Login mints it a full session with no
// password, no email_verified, no backoff and no MFA. `password_hash is null` would not do — an
// invited-but-unaccepted account also has a null hash.
const resolveNullifierSQL = `
select n.user_id
  from %[1]sauth_zk_nullifiers n
  join %[1]sauth_users u on u.id = n.user_id
 where n.nullifier = ?
   and n.audience  = ?
   and n.consumed_at is null
   and u.deleted_at is null
   and u.email = ?`

// createNullifierSQL runs only when the resolve found nothing, which is what keeps a login from
// writing auth_users on every request: a data-modifying CTE executes whether or not the outer
// query reads it, so the old combined statement inserted a user per login attempt.
//
// `do nothing` on both inserts rather than `do update`. On the user insert it means a concurrent
// first login yields no row here, and the caller's single bounded re-resolve picks up the row that
// transaction committed. On the nullifier insert it covers the soft-deleted pseudonym: the partial
// email index does not cover deleted rows, so the user insert succeeds and would then collide with
// the live nullifier's primary key — a raw 23505 on a path that must be indistinguishable from
// every other refusal.
const createNullifierSQL = `
with new_user as (
    insert into %[1]sauth_users (email, password_hash, email_verified)
    values (?, null, false)
    on conflict (lower(email)) where deleted_at is null do nothing
    returning id
)
insert into %[1]sauth_zk_nullifiers (nullifier, audience, user_id)
select ?, ?, id from new_user
on conflict (nullifier) do nothing
returning user_id`

const oneShotNullifierSQL = `
insert into %[1]sauth_zk_nullifiers (nullifier, audience, consumed_at)
values (?, ?, now())
on conflict (nullifier) do nothing
returning nullifier`

const bindRecurringNullifierSQL = `
insert into %[1]sauth_zk_nullifiers (nullifier, audience, user_id)
values (?, ?, ?)
on conflict (nullifier) do update
   set audience = auth_zk_nullifiers.audience
 where auth_zk_nullifiers.audience = excluded.audience
   and auth_zk_nullifiers.user_id = excluded.user_id
returning user_id`

const storeSessionClaimSQL = `
insert into %[1]sauth_zk_session_claims (session_id, claim)
values (?, ?)
on conflict (session_id, claim) do update set proven_at = now()`
