-- +goose Up
--
-- HTTP sessions (alexedwards/scs).
--
-- Keyed by sha256(cookie value), not the cookie value itself: a dumped table
-- must not be a set of usable session cookies. Same reasoning as oauth tokens --
-- the cookie value is 32 bytes of crypto/rand, so a plain SHA-256 is the right
-- tool and no slow KDF is needed.

CREATE TABLE sessions (
    token_hash text        PRIMARY KEY,
    data       bytea       NOT NULL,
    expiry     timestamptz NOT NULL
);

CREATE INDEX sessions_expiry_idx ON sessions (expiry);

-- +goose Down
DROP TABLE IF EXISTS sessions;
