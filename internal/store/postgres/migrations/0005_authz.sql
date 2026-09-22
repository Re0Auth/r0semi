-- +goose Up
--
-- Pending authorization requests: the server-side handle between
-- /oauth/authorize and the consent screen.
--
-- This table holds no credential. The handle id is deliberately NOT hashed: it
-- appears in browser URLs and server logs by design, and the HTTP layer
-- additionally binds it to the session that created it, so a stolen handle is
-- useless from anywhere else. It is short-lived (bounded by the authz TTL,
-- default 10 minutes) and single-use.
--
-- The captured request parameters (redirect_uri, PKCE challenge, scopes, state)
-- live here so the browser is never trusted with them again.

CREATE TABLE authz_requests (
    id                    text PRIMARY KEY,
    client_id             text        NOT NULL,
    client_name           text        NOT NULL DEFAULT '',
    redirect_uri          text        NOT NULL,
    scopes                text[]      NOT NULL DEFAULT '{}',
    state                 text        NOT NULL DEFAULT '',
    code_challenge        text        NOT NULL,
    code_challenge_method text        NOT NULL,
    created_at            timestamptz NOT NULL,
    expires_at            timestamptz NOT NULL
);

CREATE INDEX authz_requests_expires_idx ON authz_requests (expires_at);

-- +goose Down
DROP TABLE IF EXISTS authz_requests;
