-- +goose Up
--
-- Indexes for the grants view.
--
-- A grant is not a stored entity: it is derived from the tokens a subject still
-- holds, and revoking one is deleting them. Both halves of that need to find rows
-- by (subject, client_id):
--
--   * listing, which scans a subject's tokens and groups them by client;
--   * revoking, which deletes one client's rows for one subject.
--
-- The existing expires_at indexes serve the expiry sweep, which is a different
-- question (what has become useless) and cannot answer this one without reading
-- every row.
--
-- Deliberately kept as one loopback of truth: if a revoked grant had a row of its
-- own, the next request would have to remember to consult it. It does not exist,
-- so it cannot be forgotten.

CREATE INDEX oauth_access_tokens_subject_idx ON oauth_access_tokens (subject, client_id);
CREATE INDEX oauth_refresh_tokens_subject_idx ON oauth_refresh_tokens (subject, client_id);

-- +goose Down
DROP INDEX IF EXISTS oauth_refresh_tokens_subject_idx;
DROP INDEX IF EXISTS oauth_access_tokens_subject_idx;
