-- +goose Up
--
-- Bulk revocation (revokeMatching in oauth.go) filters by client_id alone for the
-- operator's suspend / delete-client actions and the `client` Kill Switch target.
-- The token tables carry (subject, client_id) indexes for the other direction, but
-- client_id is not a leading column of any of them, so `DELETE ... WHERE
-- client_id = $1` had nothing to scan on. These are the matching indexes for that
-- direction — the same reasoning as 0018's id_hash index, on the operator path
-- rather than the RFC 7009 one.
--
-- The predicate is now sargable (revokePredicate drops empty filter fields rather
-- than emitting `($1 = '' OR client_id = $1)`), so the planner can use these.

CREATE INDEX oidc_access_tokens_client_idx ON oidc_access_tokens (client_id);
CREATE INDEX oidc_refresh_tokens_client_idx ON oidc_refresh_tokens (client_id);

-- +goose Down
DROP INDEX IF EXISTS oidc_access_tokens_client_idx;
DROP INDEX IF EXISTS oidc_refresh_tokens_client_idx;
