-- +goose Up
--
-- OIDC Core §12.2: an id_token returned by a refresh MUST NOT carry a nonce
-- claim unless that nonce is identical to the one in the original authorization
-- request. The OP was re-minting the refreshed id_token without any nonce,
-- because the library reads the nonce only from a live op.AuthRequest and a
-- refresh grant has none.
--
-- The nonce therefore travels with the refresh-token row: it is copied from the
-- authorization request when the family is first minted, and every rotation
-- carries it forward, so the claim can be repeated on each refreshed id_token.
--
-- The column defaults to '' so existing rows — and the device-code grant, which
-- has no authorization request and so no nonce — read as "no nonce". An empty
-- value is not a nonce: the claim is written only when the value is non-empty,
-- so pre-0026 and device rows simply omit it, which is what §12.2 requires.

ALTER TABLE oidc_refresh_tokens ADD COLUMN nonce text NOT NULL DEFAULT '';

-- +goose Down
--
-- An ordinary reversible Down: the nonce is a claim, not integrity metadata, so
-- dropping it does not invalidate any credential (unlike the hash-chain Downs of
-- 0013/0014, which must fail closed).
ALTER TABLE oidc_refresh_tokens DROP COLUMN IF EXISTS nonce;
