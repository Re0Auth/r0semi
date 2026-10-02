-- +goose Up
--
-- The eighth client-only bulk-revocation table.
--
-- OIDCStore.RevokeTokens (oidc.go) runs revokeMatching over
-- oidc_refresh_token_tombstones with the same oauth.TokenFilter the operator's
-- suspend / delete-client action and the `client` Kill Switch target use. That
-- filter can name client_id alone, and 0024's indexes on family_id / expires_at /
-- id_hash do not help a predicate on client_id by itself.
--
-- Migration 0022 indexed the first six tables a client-only filter deletes from
-- and 0029 the seventh (oidc_devices); 0025 gave the legacy twin
-- oauth_refresh_tombstones its client_id index. This is the same reasoning on the
-- table the derived probe in audit6 found (G-14's second half). revokePredicate
-- drops empty filter fields rather than emitting `($1 = '' OR client_id = $1)`,
-- so the predicate is sargable and the planner can use this index.

CREATE INDEX oidc_refresh_token_tombstones_client_idx ON oidc_refresh_token_tombstones (client_id);

-- +goose Down
DROP INDEX IF EXISTS oidc_refresh_token_tombstones_client_idx;
