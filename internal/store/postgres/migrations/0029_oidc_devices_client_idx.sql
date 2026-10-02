-- +goose Up
--
-- The seventh client-only bulk-revocation table.
--
-- OIDCStore.RevokeTokens (oidc.go) runs revokeMatching over oidc_devices with the
-- same oauth.TokenFilter the operator's suspend / delete-client action and the
-- `client` Kill Switch target use. That filter can name client_id alone, and the
-- (subject, client_id) indexes do not help a predicate on client_id by itself.
--
-- Migration 0022 indexed the other six tables a client-only filter deletes from
-- (the three legacy oauth_* tables via revokeMatching, and oidc_auth_requests via
-- revokePendingAuthorizations), and its guard enumerated them by hand — the list
-- never contained oidc_devices, so the delete scanned while the guard stayed
-- green (G-14). This is the same reasoning on the missing table.

CREATE INDEX oidc_devices_client_idx ON oidc_devices (client_id);

-- +goose Down
DROP INDEX IF EXISTS oidc_devices_client_idx;
