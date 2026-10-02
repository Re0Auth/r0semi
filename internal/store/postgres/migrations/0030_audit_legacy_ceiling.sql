-- +goose Up
--
-- A ceiling for the pre-chain audit rows.
--
-- Migration 0013 added the chain columns to audit_events. Rows that predate it
-- carry NULL hashes and are counted as "legacy" by Verify rather than pretended
-- to be covered. The problem is that "NULL hash" was the ONLY thing separating a
-- migration-era row from a forged one: a caller with DB write access could insert
-- unsigned rows before the chain began and Verify reported the log intact
-- (Z10-2).
--
-- The ids are the missing bound. `id` is a serial, so no new row can take an id
-- at or below the highest id that existed when this migration ran. Recording
-- that high-water mark lets verification answer the question the schema could not
-- before: a NULL-hash row with `id > legacy_ceiling_id` was inserted after the
-- seal, so it is not a pre-chain row and the walk fails on it.
--
-- The ceiling is a fact about the rows present at migration time, so it is
-- computed once and never raised by a re-run: `WHERE legacy_ceiling_id = 0` keeps
-- the original seal if the Up is applied again against a schema that already has
-- the column (the same re-run hazard 0013's header describes).
--
-- What this does NOT buy, stated plainly: an attacker who can rewrite this row
-- (or re-apply this migration after deleting the column) can move the ceiling,
-- exactly as they can rewrite the chain head. The external anchor remains the
-- only answer to a writer with full control of the database.

ALTER TABLE audit_chain ADD COLUMN IF NOT EXISTS legacy_ceiling_id bigint NOT NULL DEFAULT 0;

UPDATE audit_chain
   SET legacy_ceiling_id = COALESCE((SELECT max(id) FROM audit_events WHERE row_hash IS NULL), 0)
 WHERE only_row AND legacy_ceiling_id = 0;

-- +goose Down
--
-- Dropping the column loses the seal, and re-applying Up would recompute it from
-- whatever unchained rows exist then — which is exactly the state this migration
-- exists to detect. It is still a plain additive column, and refusing every
-- rollback of it would break `-migrate-down` on databases that never had a
-- pre-chain row, so it is left reversible; the tamper-evidence refusal covers the
-- chain itself (refuseAuditChainRollback in postgres.go).
ALTER TABLE audit_chain DROP COLUMN IF EXISTS legacy_ceiling_id;
