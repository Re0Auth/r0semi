-- +goose Up
--
-- User-code uniqueness parity for the two device tables.
--
-- A user code is the handle a human types to approve an RFC 8628 device flow, so
-- two live rows sharing one is the ambiguity that makes an approval land on the
-- wrong flow. oidc_devices.user_code already carries a UNIQUE expression index
-- (0008), and oidc.go turns the resulting 23505 into op.ErrDuplicateUserCode.
--
-- oauth_device_authorizations — the legacy engine's table — only had the
-- NON-unique lookup index 0001 created, so the legacy engine compensated in Go
-- with a check-then-insert (freeUserCode, oauth/device.go): the lookup and the
-- INSERT are separate statements with no uniqueness constraint between them, so
-- two concurrent device flows can both be told a code is free, and a human typing
-- it resolves (GetDeviceByUserCode, postgres/oauth.go) to whichever row the scan
-- reaches first.
--
-- The key is the same canonicalised expression the lookup uses,
-- upper(replace(user_code, '-', '')), not the raw column: codes are case- and
-- separator-insensitive, so uniqueness on the raw text would still let ABC-D and
-- abcd collide. The unique index supersedes the non-unique lookup index, which is
-- dropped here rather than left as a second copy of the same key.
--
-- A deployment whose data already contains duplicate canonical user codes (the
-- race this closes) will fail this migration rather than be silently mutated: the
-- duplicates are live device flows and choosing one to delete is a destructive
-- decision an operator has to make.

CREATE UNIQUE INDEX oauth_device_authorizations_user_code_uniq
    ON oauth_device_authorizations (upper(replace(user_code, '-', '')));
DROP INDEX IF EXISTS oauth_device_user_code_idx;

-- +goose Down
--
-- Restore the non-unique lookup index 0001 created, then remove the unique one:
-- an ordinary reversible step, table data untouched.
CREATE INDEX IF NOT EXISTS oauth_device_user_code_idx
    ON oauth_device_authorizations (upper(replace(user_code, '-', '')));
DROP INDEX IF EXISTS oauth_device_authorizations_user_code_uniq;
