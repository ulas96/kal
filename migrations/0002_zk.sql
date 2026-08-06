-- 0002_zk.sql — optional Groth16 authentication, sparse membership tree and proven claims.
-- Names are unqualified for the same search_path contract as 0001_core.sql.

create table auth_zk_commitments (
    user_id     uuid        primary key references auth_users(id) on delete cascade,
    commitment bytea       not null check (octet_length(commitment) = 32),
    created_at timestamptz not null default now()
);

create table auth_zk_challenges (
    challenge  bytea       primary key check (octet_length(challenge) = 32),
    session_id uuid        references auth_sessions(id) on delete cascade,
    purpose    text        not null check (purpose in ('knowledge', 'login', 'claim')),
    field      bytea       not null check (octet_length(field) = 32),
    expires_at timestamptz not null,
    consumed_at timestamptz
);
create index auth_zk_challenges_expiry_idx on auth_zk_challenges (expires_at);

create table auth_zk_nodes (
    level smallint not null check (level >= 0 and level < 32),
    idx   bigint   not null check (idx >= 0),
    hash  bytea    not null check (octet_length(hash) = 32),
    primary key (level, idx)
);

create table auth_zk_credentials (
    leaf_index bigint      primary key check (leaf_index >= 0 and leaf_index < 4294967296),
    commitment bytea       not null unique check (octet_length(commitment) = 32),
    issued_to  uuid        references auth_users(id) on delete set null,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);
create index auth_zk_credentials_issued_idx on auth_zk_credentials (issued_to)
    where issued_to is not null and revoked_at is null;

create table auth_zk_roots (
    root       bytea       primary key check (octet_length(root) = 32),
    created_at timestamptz not null default now(),
    retired_at timestamptz
);
create unique index auth_zk_roots_current_key on auth_zk_roots ((retired_at is null))
    where retired_at is null;

create table auth_zk_nullifiers (
    nullifier   bytea       primary key check (octet_length(nullifier) = 32),
    audience    bytea       not null check (octet_length(audience) = 32),
    user_id     uuid        references auth_users(id) on delete cascade,
    first_seen_at timestamptz not null default now(),
    consumed_at timestamptz
);

-- allows_login defaults false because the zero value of a policy row is the production posture. The
-- recurring/one_shot column distinguishes nullifier lifetime, not what a proof is good for: without
-- this, a claim written for an @auth(proves: ["age_over_18"]) step-up also mints sessions, and every
-- recurring claim row is implicitly a login endpoint.
create table auth_zk_claims (
    claim        text    primary key check (claim <> '' and length(claim) <= 128),
    audience     bytea   not null unique check (octet_length(audience) = 32),
    threshold    bigint  not null check (threshold >= 0),
    kind         text    not null check (kind in ('recurring', 'one_shot')),
    allows_login boolean not null default false
);

-- Recurring claims live for one ordinary session. One-shot claims never enter this table:
-- they are burned and carried only in the request that supplied their proof.
create table auth_zk_session_claims (
    session_id uuid        not null references auth_sessions(id) on delete cascade,
    claim      text        not null references auth_zk_claims(claim) on delete cascade,
    proven_at  timestamptz not null default now(),
    primary key (session_id, claim)
);
