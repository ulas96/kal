-- 0003_e2ee.sql — the one table client-side encryption needs: a wrapped root key per user, and
-- the client KDF parameters that produced it.
-- Names are unqualified for the same search_path contract as 0001_core.sql.
--
-- Every bytea here is opaque to kal. There is no key material in this table that kal can use,
-- which is the entire point of the feature: a dump of this schema yields ciphertext and a
-- password-wrapped key, and nothing that opens either.

create table auth_e2ee_vaults (
    user_id     uuid primary key references auth_users(id) on delete cascade,

    -- The client KDF, stored per user and never read from config at derive time. Raise a default
    -- in application configuration and every existing vault becomes unopenable — with a working
    -- login, a client that reports a corrupt vault, and no error on this side.
    --
    -- Named columns rather than a jsonb blob so the parameters stay greppable and the one
    -- genuinely invariant constraint can live here. Argon2's parallelism changes the output, so a
    -- browser that picks it from the thread pool derives a different key on a laptop than on a
    -- phone; this check is the only floor the schema enforces. Memory and iterations are checked
    -- against Options.Floor in Go, because a floor expected to rise over time should not be a
    -- migration.
    kdf         text     not null,
    salt        bytea    not null,   -- 16 bytes, written once by the first Put, never rotated
    memory      int      not null,
    iterations  int      not null,
    parallelism smallint not null check (parallelism = 1),

    wrapped_key          bytea,      -- null until enrolment
    -- The same vault key under a one-shot recovery code. One nullable column rather than a second
    -- table, because a recovery code is just a second wrapping. Nothing here verifies the code:
    -- the wrapped key *is* the verifier, so there is no hash of it to steal.
    recovery_wrapped_key bytea,
    -- sha256(auth_users.password_hash) as it stood when the key was written. A password reset
    -- changes the hash, so the vault reads as stale on the next Get with no hook into authn and no
    -- ordering requirement between two writes. Without it the client receives a key it has no
    -- possible way to open, and fails somewhere far from the cause.
    wrapped_for          bytea,

    key_version int         not null default 1,
    updated_at  timestamptz not null default now()
);
