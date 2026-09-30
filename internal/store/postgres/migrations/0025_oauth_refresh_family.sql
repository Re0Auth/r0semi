-- +goose Up
--
-- RFC 9700 §4.14.2 on the PUBLIC oauth.Store contract: when a refresh token that
-- was already rotated is presented again, the authorization server SHOULD revoke
-- the whole token family, because the replay is itself the theft signal.
--
-- This is the same standard migration 0024 applied to the OP store, applied to
-- the retired hand-rolled engine's tables (oauth_access_tokens /
-- oauth_refresh_tokens), which are on the production path as the legacy token
-- purger. The store had rotation (the DELETE that claims the presented row) but no
-- family: every generation was an independent row, so a replay could only be
-- refused, never traced to the chain the thief was holding.
--
--   - `family_id` names the chain. A first issuance mints a fresh id; every
--     rotation copies the spent row's id onto its replacement, so all generations
--     descended from one authorization share it. Existing rows are given their own
--     token_hash, which is exactly "each is its own family" — the behaviour they
--     already had, made explicit rather than guessed. The access table carries the
--     same id, because the access token is minted with the refresh token and must
--     die with the family.
--   - `oauth_refresh_tombstones` is what a spent row leaves behind. The live row is
--     DELETEd at rotation, so by the time a replay arrives the only surviving
--     pointer to the family is this record, keyed by the spent token's hash. It
--     carries the client/subject the lifecycle paths revoke by, and expires on the
--     spent token's own deadline.
--
-- The tombstone is not a credential: it stores no token value, only the SHA-256
-- the row was already keyed by.

ALTER TABLE oauth_access_tokens ADD COLUMN family_id text NOT NULL DEFAULT '';
ALTER TABLE oauth_refresh_tokens ADD COLUMN family_id text NOT NULL DEFAULT '';

-- Backfill before the column is relied on: an empty family id would make a
-- replay's family lookup match nothing (or, worse, every unfilled row).
UPDATE oauth_access_tokens SET family_id = token_hash WHERE family_id = '';
UPDATE oauth_refresh_tokens SET family_id = token_hash WHERE family_id = '';

-- family_id: the family revocation's own predicate (DELETE ... WHERE family_id = $1).
CREATE INDEX oauth_access_tokens_family_id_idx ON oauth_access_tokens (family_id);
CREATE INDEX oauth_refresh_tokens_family_id_idx ON oauth_refresh_tokens (family_id);

CREATE TABLE oauth_refresh_tombstones (
    token_hash text PRIMARY KEY,
    family_id  text NOT NULL,
    client_id  text NOT NULL,
    subject    text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL
);

-- family_id: RevokeRefreshFamily's predicate.
CREATE INDEX oauth_refresh_tombstones_family_id_idx ON oauth_refresh_tombstones (family_id);
-- expires_at: SweepExpired's deadline column (sweep.go).
CREATE INDEX oauth_refresh_tombstones_expires_at_idx ON oauth_refresh_tombstones (expires_at);
-- client_id and subject: the owner-scoped lifecycle deletes (DeleteBySubjectClient,
-- RevokeTokens filter) match on them.
CREATE INDEX oauth_refresh_tombstones_client_id_idx ON oauth_refresh_tombstones (client_id);
CREATE INDEX oauth_refresh_tombstones_subject_idx ON oauth_refresh_tombstones (subject);

-- +goose Down
DROP TABLE IF EXISTS oauth_refresh_tombstones;
DROP INDEX IF EXISTS oauth_access_tokens_family_id_idx;
DROP INDEX IF EXISTS oauth_refresh_tokens_family_id_idx;
ALTER TABLE oauth_access_tokens DROP COLUMN IF EXISTS family_id;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS family_id;
