-- +goose Up
--
-- RFC 9700 §4.14.2: when a refresh token that was already rotated is presented
-- again, the authorization server SHOULD revoke the whole token family, because
-- the replay is itself the theft signal. The store had rotation (the DELETE that
-- claims the presented row) but no family: every generation was an independent
-- row, so a replay could only be refused, never traced to the chain the thief
-- was holding.
--
-- This migration adds the two pieces that make the rule implementable.
--
--   - `family_id` names the chain. A first issuance mints a fresh id; every
--     rotation copies the spent row's id onto its replacement, so all the
--     generations descended from one authorization share it. Existing rows are
--     given their own token_hash, which is exactly "each is its own family" —
--     the behaviour they already had, made explicit rather than guessed.
--   - `oidc_refresh_token_tombstones` is what a spent row leaves behind. The
--     live row is DELETEd at rotation, so by the time a replay arrives the only
--     surviving pointer to the family is this record, keyed by the spent token's
--     hash. It carries the family id, the paired access token's id hash, and the
--     client/subject the lifecycle paths revoke by.
--
-- The tombstone is not a credential: it stores no token value, only the SHA-256
-- the row was already keyed by, and it expires on the spent token's own deadline.

ALTER TABLE oidc_refresh_tokens ADD COLUMN family_id text NOT NULL DEFAULT '';

-- Backfill before the column is relied on: an empty family id would make a
-- replay's family lookup match nothing (or, worse, every unfilled row).
UPDATE oidc_refresh_tokens SET family_id = token_hash WHERE family_id = '';

CREATE INDEX oidc_refresh_tokens_family_id_idx ON oidc_refresh_tokens (family_id);

CREATE TABLE oidc_refresh_token_tombstones (
    token_hash text PRIMARY KEY,
    family_id  text NOT NULL,
    id_hash    text NOT NULL,
    client_id  text NOT NULL,
    subject    text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL
);

-- family_id: the revocation's own predicate (DELETE ... WHERE family_id = $1).
CREATE INDEX oidc_refresh_token_tombstones_family_id_idx ON oidc_refresh_token_tombstones (family_id);
-- expires_at: SweepExpired's deadline column (sweep.go).
CREATE INDEX oidc_refresh_token_tombstones_expires_at_idx ON oidc_refresh_token_tombstones (expires_at);
-- id_hash: RevokeToken's id-hash lookups (RFC 7009 §2.1 pairs).
CREATE INDEX oidc_refresh_token_tombstones_id_hash_idx ON oidc_refresh_token_tombstones (id_hash);

-- +goose Down
DROP TABLE IF EXISTS oidc_refresh_token_tombstones;
DROP INDEX IF EXISTS oidc_refresh_tokens_family_id_idx;
ALTER TABLE oidc_refresh_tokens DROP COLUMN IF EXISTS family_id;
