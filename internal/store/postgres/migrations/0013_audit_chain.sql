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

ALTER TABLE audit_events ADD COLUMN prev_hash bytea;
ALTER TABLE audit_events ADD COLUMN row_hash  bytea;
ALTER TABLE audit_events ADD COLUMN signature bytea;

-- A row_hash is unique in practice; the index makes a duplicated hash detectable
-- and keeps the verification scan ordered by the column it walks.
CREATE UNIQUE INDEX audit_events_row_hash_idx
    ON audit_events (row_hash) WHERE row_hash IS NOT NULL;

-- The chain head. A single row, locked for the duration of every append, which
-- is what serialises the chain: without it two concurrent inserts could each
-- read the same predecessor and the linkage would fork.
CREATE TABLE audit_chain (
    only_row  boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    head_hash bytea   NOT NULL
);

-- The empty hash is the chain's genesis: the first chained row points at it.
INSERT INTO audit_chain (only_row, head_hash) VALUES (true, '\x'::bytea);

-- +goose Down
DROP TABLE IF EXISTS audit_chain;
DROP INDEX IF EXISTS audit_events_row_hash_idx;
ALTER TABLE audit_events DROP COLUMN IF EXISTS signature;
ALTER TABLE audit_events DROP COLUMN IF EXISTS row_hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS prev_hash;
