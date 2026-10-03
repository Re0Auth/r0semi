-- +goose Up
--
-- R10-59: RevokeTokens and CreateAccessAndRefreshTokens run in separate
-- transactions, and the resolve step has already consumed the source row (a code,
-- a device record, a rotated refresh value) before the mint runs. A Kill Switch
-- that commits in that window has nothing left to delete, so it reports success
-- and then a live pair is minted behind it.
--
-- The epochs are the ordering the two transactions lacked. A revocation advances
-- the scope it names before it deletes; the mint reads the epoch with FOR SHARE
-- as its first statement (which blocks a concurrent revocation until the mint
-- commits, so the revocation's deletes then see the new rows) and refuses the
-- pair if the epoch moved since the request resolved its credential.
--
-- scope_key is "*" (every grant), "client:<id>" or "subject:<id>". The "*" row is
-- seeded and always present: it is the lock anchor, so a mint never locks a row
-- that a concurrent revocation could insert after the mint read it.
CREATE TABLE IF NOT EXISTS oidc_revocation_epochs (
	scope_key  text PRIMARY KEY,
	epoch      bigint NOT NULL DEFAULT 0,
	revoked_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO oidc_revocation_epochs (scope_key, epoch, revoked_at)
VALUES ('*', 0, now())
ON CONFLICT (scope_key) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS oidc_revocation_epochs;
