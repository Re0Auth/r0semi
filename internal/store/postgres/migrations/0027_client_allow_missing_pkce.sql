-- +goose Up
--
-- The per-client exemption from the mandatory-PKCE rule. Existing rows predate
-- the concept, and false — PKCE required — is both the safe value and the
-- behaviour they already have, so the migration exempts nobody implicitly.
--
-- A client is exempt only when an operator sets `[client] allow_missing_pkce =
-- true`; seedClient refuses to start when an existing row disagrees with the
-- configured value, so the column cannot drift from the file.

ALTER TABLE oauth_clients
    ADD COLUMN allow_missing_pkce boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS allow_missing_pkce;
