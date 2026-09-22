-- +goose Up
-- The grants view aggregates tokens by client and shows when access started,
-- so the OP token tables need an issued_at. Existing rows predate the column;
-- now() is the honest fallback (we cannot recover the real time).
ALTER TABLE oidc_access_tokens  ADD COLUMN issued_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE oidc_refresh_tokens ADD COLUMN issued_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX oidc_access_tokens_subject_issued_idx
    ON oidc_access_tokens (subject, issued_at);
CREATE INDEX oidc_refresh_tokens_subject_issued_idx
    ON oidc_refresh_tokens (subject, issued_at);

-- +goose Down
DROP INDEX IF EXISTS oidc_refresh_tokens_subject_issued_idx;
DROP INDEX IF EXISTS oidc_access_tokens_subject_issued_idx;
ALTER TABLE oidc_refresh_tokens DROP COLUMN IF EXISTS issued_at;
ALTER TABLE oidc_access_tokens  DROP COLUMN IF EXISTS issued_at;
