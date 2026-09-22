-- +goose Up
--
-- Federation: source bindings and pending bind flows.
--
-- Bindings hold METADATA ONLY. The upstream token lives in the vault, encrypted
-- under Identity{Subject: usr_, Provider: "<game>.<source>"}. There is
-- deliberately no column here that could hold a credential -- the Go struct has
-- no field for one either, and a test asserts that this stays true.

CREATE TABLE federation_bindings (
    user_id     text        NOT NULL,
    game        text        NOT NULL,
    source      text        NOT NULL,
    token_type  text        NOT NULL DEFAULT '',
    expiry      timestamptz,
    -- Whether a refresh token exists, so refresh decisions do not need to open
    -- the vault.
    has_refresh boolean     NOT NULL DEFAULT false,
    -- Incremented on every refresh. It is how a concurrent refresh notices that
    -- another request already rotated the token.
    version     bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, game, source)
);

-- Pending bind flows. Single-use: CompleteBind consumes one with a
-- DELETE ... RETURNING, so two concurrent callbacks cannot both win.
CREATE TABLE federation_bind_flows (
    state       text PRIMARY KEY,
    id          text        NOT NULL,
    user_id     text        NOT NULL,
    game        text        NOT NULL,
    source      text        NOT NULL,
    -- The PKCE verifier is needed to complete the token exchange, so unlike an
    -- access token it CANNOT be stored as a hash. It is short-lived (bounded by
    -- the bind TTL), single-use, and useless on its own: completing the exchange
    -- also requires the authorization code, which is delivered only to the
    -- registered redirect URI. See docs/threat-model.md §6.1.
    pkce_verifier text      NOT NULL,
    return_to   text        NOT NULL DEFAULT '',
    expires_at  timestamptz NOT NULL
);

CREATE INDEX federation_bind_flows_expires_idx ON federation_bind_flows (expires_at);

-- +goose Down
DROP TABLE IF EXISTS federation_bind_flows;
DROP TABLE IF EXISTS federation_bindings;
