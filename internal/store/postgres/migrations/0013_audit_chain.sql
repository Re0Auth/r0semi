-- +goose Up
--
-- Tamper-evidence for the audit log.
--
-- The audit table is append-only by convention, but convention is not a
-- control: nothing in the schema stopped a role with the table grant from
-- rewriting or deleting rows. These columns make a rewrite detectable.
--
-- Each row commits to the row before it, and is signed with a key that is not in
-- the database:
--
--     row_hash  = SHA-256(prev_hash || canonical(row))
--     signature = HMAC-SHA256(key, row_hash)
--
-- What this catches, and what it does not, stated plainly because an
-- over-claimed integrity control is worse than none:
--
--   * editing a row            -> row_hash no longer recomputes
--   * deleting a row mid-chain -> the next row's prev_hash points at nothing
--   * reordering rows          -> same, the linkage breaks
--   * rewriting the whole chain -> the signatures cannot be forged without the key
--   * deleting rows from the END -> NOT caught. Truncation is invisible without
--     an external anchor (shipping the head to a separate system). Noted in
--     docs/architecture.md §4.16.
--
-- Rows written before this migration have NULL hashes and are outside the chain;
-- they are counted as "legacy" by verification rather than pretended to be
-- covered.

-- Every statement below is idempotent, and that is load-bearing, not style:
-- 0013's Down is a no-op, and goose still deletes the version row for a Down
-- section that executes nothing. The next Open() therefore runs this Up again
-- against a schema that already has these objects, and a bare `ADD COLUMN`
-- would abort the migration with "column already exists" and hold the advisory
-- lock until an operator intervened.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash bytea;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS row_hash  bytea;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS signature bytea;

-- A row_hash is unique in practice; the index makes a duplicated hash detectable
-- and keeps the verification scan ordered by the column it walks.
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_row_hash_idx
    ON audit_events (row_hash) WHERE row_hash IS NOT NULL;

-- The chain head. A single row, locked for the duration of every append, which
-- is what serialises the chain: without it two concurrent inserts could each
-- read the same predecessor and the linkage would fork.
CREATE TABLE IF NOT EXISTS audit_chain (
    only_row  boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    head_hash bytea   NOT NULL
);

-- The empty hash is the chain's genesis: the first chained row points at it.
-- DO NOTHING, not an unconditional insert, so a re-run after the no-op Down
-- keeps the real head instead of rewinding it to genesis: overwriting the head
-- would make the next row chain from genesis and fork it away from every
-- historical row, which is precisely the silent loss this migration prevents.
INSERT INTO audit_chain (only_row, head_hash) VALUES (true, '\x'::bytea)
ON CONFLICT (only_row) DO NOTHING;

-- +goose Down
--
-- This step is NOT reversible, and deliberately executes nothing.
--
-- It used to DROP audit_chain, DROP audit_events_row_hash_idx and drop the
-- prev_hash / row_hash / signature columns from audit_events. Its Up then
-- re-adds the columns (NULL for every surviving row) and re-seeds audit_chain
-- to the genesis hash. One `-migrate-down` followed by the next startup's
-- Open() therefore turned every historical row's hash into NULL and reset the
-- head, after which Verify counts all of them Legacy and returns OK=true: a
-- silently destroyed audit chain that still reports healthy. Rollback is
-- restore-from-backup (docs/migration-decision.md, ADR-0008 §5); a migration
-- step that "undoes" a tamper-evidence column set cannot preserve the evidence
-- it was added to create.
--
-- postgres.MigrateDown calls refuseAuditChainRollback before provider.Down and
-- refuses version 13 outright while any row in audit_events has a non-NULL
-- row_hash. With no chained rows left to lose (a fresh or never-chained
-- database) the rollback is allowed to proceed, so `-migrate-down` still works
-- on a database that has nothing to destroy.
--
-- Keeping the section empty also protects the operator who bypasses
-- postgres.MigrateDown and drives goose directly (`goose down`, `goose down-to`):
-- where the CLI has no refusal hook, the no-op is the control.
--
-- If you are editing this file: do not add DDL between here and the end of the
-- file. `TestAuditIntegrityMigrationsCannotBeRolledBack` fails on any executed
-- statement in this section, on purpose.
