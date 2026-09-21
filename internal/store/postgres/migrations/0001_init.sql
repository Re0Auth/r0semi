-- Initial schema for the persistent stores.
--
-- Two conventions run through these tables:
--
--   1. Opaque bearer values (authorization codes, access/refresh tokens, device
--      codes) are NEVER stored. Only their SHA-256 hex digest is, so a dump of
--      the database is not a set of usable credentials.
--   2. Upstream credentials are not here at all: they live in the vault, and
--      the binding table holds metadata only.

-- Accounts -------------------------------------------------------------------

CREATE TABLE accounts_users (
    id               text PRIMARY KEY,
    -- Display-only pointer to the identity shown as the account's origin. It
    -- grants nothing (invariant I-1) and is intentionally not a foreign key,
    -- because it is set before the first identity row exists.
    primary_identity text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL
);

CREATE TABLE accounts_identities (
    id            text PRIMARY KEY,
    user_id       text        NOT NULL REFERENCES accounts_users (id) ON DELETE CASCADE,
    provider      text        NOT NULL,
    subject       text        NOT NULL,
    display_name  text        NOT NULL DEFAULT '',
    email         text        NOT NULL DEFAULT '',
    avatar_url    text        NOT NULL DEFAULT '',
    linked_at     timestamptz NOT NULL,
    last_login_at timestamptz,
    -- Invariant I-3: an identity belongs to exactly one account.
    UNIQUE (provider, subject)
);

CREATE INDEX accounts_identities_user_idx
    ON accounts_identities (user_id, linked_at, id);

-- OAuth tokens ---------------------------------------------------------------
--
-- Every table here is keyed by token_hash = sha256(opaque value), hex encoded.

CREATE TABLE oauth_codes (
    token_hash            text PRIMARY KEY,
    client_id             text        NOT NULL,
    subject               text        NOT NULL,
    scopes                text[]      NOT NULL DEFAULT '{}',
    redirect_uri          text        NOT NULL,
    code_challenge        text        NOT NULL,
    code_challenge_method text        NOT NULL,
    expires_at            timestamptz NOT NULL
);

CREATE TABLE oauth_access_tokens (
    token_hash text PRIMARY KEY,
    client_id  text        NOT NULL,
    subject    text        NOT NULL,
    scopes     text[]      NOT NULL DEFAULT '{}',
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX oauth_access_tokens_expires_idx ON oauth_access_tokens (expires_at);

CREATE TABLE oauth_refresh_tokens (
    token_hash text PRIMARY KEY,
    client_id  text        NOT NULL,
    subject    text        NOT NULL,
    scopes     text[]      NOT NULL DEFAULT '{}',
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX oauth_refresh_tokens_expires_idx ON oauth_refresh_tokens (expires_at);

-- RFC 8628 device authorizations. The device code is a bearer secret and is
-- hashed like any other token; the user code is displayed to the human, so it is
-- stored as-is plus an expression index that makes lookups separator- and
-- case-insensitive.
CREATE TABLE oauth_device_authorizations (
    device_code_hash text PRIMARY KEY,
    user_code        text        NOT NULL,
    client_id        text        NOT NULL,
    scopes           text[]      NOT NULL DEFAULT '{}',
    status           text        NOT NULL,
    subject          text        NOT NULL DEFAULT '',
    explicit_scopes  text[]      NOT NULL DEFAULT '{}',
    expires_at       timestamptz NOT NULL,
    last_poll        timestamptz
);

CREATE INDEX oauth_device_user_code_idx
    ON oauth_device_authorizations (upper(replace(user_code, '-', '')));

-- Registered downstream clients. The secret is stored only as its SHA-256
-- digest (bytea), never in the clear.
CREATE TABLE oauth_clients (
    id             text PRIMARY KEY,
    name           text        NOT NULL,
    type           text        NOT NULL,
    secret_hash    bytea,
    redirect_uris  text[]      NOT NULL,
    allowed_scopes text[]      NOT NULL DEFAULT '{}',
    created_at     timestamptz NOT NULL
);
