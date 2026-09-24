-- +goose Up
--
-- Backing indexes for delete paths that were scanning.
--
-- Every index here serves a statement that filters on a column which had no
-- index. The tables are small today, but each of these runs on a hot or
-- security-relevant path -- redeeming an authorization code, ending a session,
-- erasing an account -- so the scan would show up first exactly when the table
-- is largest.

-- DeleteAuthRequest and PurgeSubject both locate codes by the request they were
-- minted from; this runs on every authorization-code redemption.
CREATE INDEX oidc_codes_request_idx ON oidc_codes (request_id);

-- TerminateSession, RevokeGrant and RevokeTokens all filter (subject, client_id).
-- The access table already has this index; refresh is queried the same way.
CREATE INDEX oidc_refresh_tokens_subject_client_idx ON oidc_refresh_tokens (subject, client_id);

-- PurgeSubject deletes a subject's pending consent requests and device
-- authorizations by subject, which had no index on either table.
CREATE INDEX oidc_auth_requests_subject_idx ON oidc_auth_requests (subject);
CREATE INDEX oidc_devices_subject_idx ON oidc_devices (subject);

-- PurgeUserFlows removes one account's pending bind flows by user.
CREATE INDEX federation_bind_flows_user_idx ON federation_bind_flows (user_id);

-- PurgeLegacySubject clears the retired engine's code and device rows by
-- subject.
CREATE INDEX oauth_codes_subject_idx ON oauth_codes (subject);
CREATE INDEX oauth_device_authorizations_subject_idx ON oauth_device_authorizations (subject);

-- The expiry sweep (postgres.DB.SweepExpired) deletes by deadline; every other
-- dated table already has this index, but these two did not.
CREATE INDEX oauth_codes_expires_idx ON oauth_codes (expires_at);
CREATE INDEX oauth_device_authorizations_expires_idx ON oauth_device_authorizations (expires_at);

-- +goose Down
DROP INDEX IF EXISTS oauth_device_authorizations_expires_idx;
DROP INDEX IF EXISTS oauth_codes_expires_idx;
DROP INDEX IF EXISTS oauth_device_authorizations_subject_idx;
DROP INDEX IF EXISTS oauth_codes_subject_idx;
DROP INDEX IF EXISTS federation_bind_flows_user_idx;
DROP INDEX IF EXISTS oidc_devices_subject_idx;
DROP INDEX IF EXISTS oidc_auth_requests_subject_idx;
DROP INDEX IF EXISTS oidc_refresh_tokens_subject_client_idx;
DROP INDEX IF EXISTS oidc_codes_request_idx;
