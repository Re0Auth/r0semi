-- +goose Up
--
-- The authorization request's freshness requirement (`prompt=login`,
-- `max_age=N`) was parsed by the library and then dropped at this boundary:
-- op.AuthRequest exposes no accessor for either, so once the pending request
-- was stored the login hook could only record the session's existing auth_time
-- and the id_token carried it back to a client that had asked for step-up
-- authentication.
--
--   - `prompt` is the normalized prompt list. Only `login` forces a fresh
--     authentication, but the list is recorded verbatim so the decision does
--     not re-parse the wire parameters.
--   - `max_age_seconds` is the library's normalized max_age (prompt=login is
--     normalized to 0). NULL means the request asked for no freshness bound.
--
-- Neither column is a credential: they describe what the client asked for.

ALTER TABLE oidc_auth_requests
    ADD COLUMN prompt text[] NOT NULL DEFAULT '{}',
    ADD COLUMN max_age_seconds integer;

-- +goose Down
ALTER TABLE oidc_auth_requests
    DROP COLUMN IF EXISTS max_age_seconds,
    DROP COLUMN IF EXISTS prompt;
