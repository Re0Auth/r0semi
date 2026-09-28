-- +goose Up
--
-- Bulk revocation filters by client_id alone in two places 0021 did not cover:
--
--   - revokeMatching (oauth.go) deletes from the legacy oauth_access_tokens /
--     oauth_refresh_tokens / oauth_codes tables. The operator's suspend /
--     delete-client actions and the `client` Kill Switch target reach them, and
--     the (subject, client_id) indexes do not help a predicate on client_id by
--     itself.
--   - revokePendingAuthorizations (oidc.go) deletes pending oidc_auth_requests by
--     client_id. That is the CURRENT engine's table, so a fresh deployment grows
--     it on every authorization request and needs the index too.
--
-- 0021 added the symmetric indexes for the OIDC token tables; these are the same
-- reasoning on the remaining predicates. The predicates are sargable
-- (revokePredicate drops empty filter fields rather than emitting
-- `($1 = '' OR client_id = $1)`), so the planner can use these.

CREATE INDEX oauth_access_tokens_client_idx ON oauth_access_tokens (client_id);
CREATE INDEX oauth_refresh_tokens_client_idx ON oauth_refresh_tokens (client_id);
CREATE INDEX oauth_codes_client_idx ON oauth_codes (client_id);
CREATE INDEX oidc_auth_requests_client_idx ON oidc_auth_requests (client_id);

-- +goose Down
DROP INDEX IF EXISTS oauth_access_tokens_client_idx;
DROP INDEX IF EXISTS oauth_refresh_tokens_client_idx;
DROP INDEX IF EXISTS oauth_codes_client_idx;
DROP INDEX IF EXISTS oidc_auth_requests_client_idx;
