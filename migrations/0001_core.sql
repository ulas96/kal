-- 0001_core.sql — the tables kal's core needs: users, sessions, emailed tokens, RBAC and the
-- failed-login counters.
--
-- Table names are unqualified on purpose. To keep them in their own Postgres schema, execute
-- this with search_path set to that schema, and hand kal the same name through Config.TableSchema
-- so its queries qualify correctly.
--
-- gen_random_uuid() is built in since Postgres 13 — no pgcrypto, no UUID library.

create table auth_users (
    id             uuid        primary key default gen_random_uuid(),
    email          text        not null,
    password_hash  text,                        -- null for accounts with no password yet (invited)
    email_verified boolean     not null default false,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    deleted_at     timestamptz                  -- soft delete, and the "account disabled" switch
);

-- Case-insensitive uniqueness over LIVE rows only.
--
-- Partial, because a plain unique index would block a user from ever re-registering an address
-- that belongs to a soft-deleted account. And NOT `unique (lower(email), deleted_at)` — that is
-- backwards: NULLs are distinct in a unique constraint, so it would permit unlimited *active*
-- duplicates while forbidding exactly the re-registration we want.
--
-- lower() rather than citext: citext's own documentation warns that its operators silently fall
-- back to case-sensitive text comparison when the extension's schema is not on search_path,
-- which would split Admin@x.com and admin@x.com into two accounts with no error anywhere. An
-- expression index has no extension dependency (which also matters on managed Postgres) and no
-- search_path hazard. kal lowercases in Go on write as well, so this index is belt and braces
-- rather than the only line of defence.
create unique index auth_users_email_live_key
    on auth_users (lower(email)) where deleted_at is null;

create table auth_sessions (
    id              uuid        primary key default gen_random_uuid(),
    token_sha256    bytea       not null unique,  -- only the hash: a dump yields no live sessions
    user_id         uuid        not null references auth_users(id) on delete cascade,
    created_at      timestamptz not null default now(),
    last_seen_at    timestamptz not null default now(),
    idle_expires_at timestamptz not null,
    expires_at      timestamptz not null,         -- absolute lifetime; never extended
    mfa_at          timestamptz,                  -- when MFA was last satisfied; drives step-up
    user_agent      text,
    ip              inet,
    revoked_at      timestamptz
);
create index auth_sessions_user_live_idx
    on auth_sessions (user_id) where revoked_at is null;

-- One design for every emailed token: verification, password reset, invite. Only the SHA-256 of
-- the token is stored, and consumption is a single UPDATE … WHERE consumed_at IS NULL, so a
-- double-submitted link burns exactly once with no read-then-write window.
create table auth_tokens (
    token_sha256 bytea       primary key,
    user_id      uuid        not null references auth_users(id) on delete cascade,
    purpose      text        not null,   -- 'verify' | 'reset' | 'invite'
    expires_at   timestamptz not null,
    consumed_at  timestamptz,
    created_at   timestamptz not null default now()
);
create index auth_tokens_user_idx on auth_tokens (user_id, purpose);

create table auth_roles (
    name        text primary key,
    description text not null default ''
);

create table auth_user_roles (
    user_id uuid not null references auth_users(id) on delete cascade,
    role    text not null references auth_roles(name) on delete cascade,
    primary key (user_id, role)
);

-- Failed-login counters for the exponential backoff, per account and per client address.
--
-- ponytail: per-key counters in Postgres, transactional with the login itself and correct
-- behind N replicas where an in-memory limiter silently multiplies the allowance. Every failed
-- login writes one row, so a targeted attack on one account is a hot row — fine to a few
-- hundred attempts a second; past that the upgrade is Redis or a probabilistic counter.
create table auth_login_attempts (
    scope     text        not null,    -- 'user' | 'ip'
    key       text        not null,    -- the user id, or the client address
    failures  int         not null default 0,
    last_fail timestamptz not null default now(),
    primary key (scope, key)
);
