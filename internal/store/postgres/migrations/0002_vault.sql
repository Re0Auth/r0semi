-- +goose Up
--
-- Vault credential records.
--
-- This table holds only opaque crypto material: the wrapped DEK, the nonce and
-- the ciphertext. A plaintext secret never reaches the database, and without the
-- KEK (which is not in this database) a dump of this table cannot be decrypted.
--
-- (subject, provider) is the credential identity, and it is also the AAD bound
-- into the ciphertext, so a row cannot be moved between credentials.

CREATE TABLE vault_credentials (
    subject     text        NOT NULL,
    provider    text        NOT NULL,
    version     smallint    NOT NULL,
    wrapped_dek bytea       NOT NULL,
    kek_id      text        NOT NULL,
    nonce       bytea       NOT NULL,
    ciphertext  bytea       NOT NULL,
    -- Non-secret metadata (upstream openid/unionid, objectId). PII at rest, not
    -- a secret, and deliberately kept readable so an operator can inspect which
    -- credential a row belongs to without holding the KEK.
    meta        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (subject, provider)
);

-- +goose Down
DROP TABLE IF EXISTS vault_credentials;
