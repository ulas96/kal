-- 0004_zk_hardening.sql — make the recurring and one-shot nullifier row shapes exclusive.
--
-- Preflight before applying this migration to an existing database:
--
--   select encode(nullifier, 'hex'), user_id, consumed_at
--     from auth_zk_nullifiers
--    where (user_id is null) = (consumed_at is null);
--
-- The query must return no rows. A recurring nullifier has user_id and no consumed_at; a one-shot
-- nullifier has consumed_at and no user_id. Repair or remove any legacy rows deliberately before
-- adding the constraint rather than allowing the migration to guess which security meaning won.

alter table auth_zk_nullifiers
    add constraint auth_zk_nullifiers_shape_check
    check ((user_id is null) <> (consumed_at is null));
