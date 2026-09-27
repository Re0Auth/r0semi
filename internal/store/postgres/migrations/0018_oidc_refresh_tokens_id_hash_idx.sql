-- +goose Up
--
-- RevokeToken (internal/store/postgres/oidc.go) resolves a presented token by
-- id_hash on oidc_refresh_tokens in three places on the RFC 7009 path: the
-- lookup that recovers the owner when the access row is already gone (:456),
-- and the two DELETE statements that revoke the pair (:442/:461, plus the
-- subselect at :477). token_hash is the primary key; id_hash had no index, so
-- each of those was a sequential scan over a table that grows with every token
-- pair. The cost lands on revocation and emergency response, not on issuance.

CREATE INDEX oidc_refresh_tokens_id_hash_idx ON oidc_refresh_tokens (id_hash);

-- +goose Down
DROP INDEX IF EXISTS oidc_refresh_tokens_id_hash_idx;
