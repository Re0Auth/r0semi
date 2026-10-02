package postgres

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestLegacyRevokeTokensIsAtomicWhenACodeDeleteFails pins the transaction the
// legacy Tokens.RevokeTokens documents but (before S09-2) did not open.
//
// The method deletes from four tables: the access and refresh tokens through
// revokeMatching, then oauth_codes and oauth_refresh_tombstones. Without a
// transaction each statement autocommits, so a failure on the third — the codes
// delete — leaves the tokens already gone while the method reports an error and a
// partial (in fact, pre-fix, the full token) count. A Kill Switch retry then has
// nothing to distinguish "revoked the tokens, failed on the codes" from "revoked
// everything", which is exactly the partial application OIDCStore.RevokeTokens
// avoids.
//
// The failure is forced with a BEFORE DELETE trigger on oauth_codes. Only a real
// database can show the rollback, so this runs wherever TEST_DATABASE_URL is set
// and skips otherwise (openTestDB).
func TestLegacyRevokeTokensIsAtomicWhenACodeDeleteFails(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		subject = "usr_revoke_atomicity"
		client  = "cli_revoke_atomicity"
	)

	if _, err := db.pool.Exec(ctx, `
		INSERT INTO oauth_access_tokens (token_hash, client_id, subject, issued_at, expires_at)
		VALUES ($1, $2, $3, now(), now() + interval '1 hour')`,
		"atomicity-access-hash", client, subject); err != nil {
		t.Fatalf("insert access token: %v", err)
	}
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO oauth_codes
			(token_hash, client_id, subject, redirect_uri, code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + interval '1 hour')`,
		"atomicity-code-hash", client, subject, "https://app.example/cb", "challenge", "S256"); err != nil {
		t.Fatalf("insert authorization code: %v", err)
	}

	// The trigger is what makes the codes delete fail. It is dropped with the
	// function afterwards, so it cannot leak into another test in the package;
	// the pre-drop covers a trigger a hard-killed earlier run left behind.
	_, _ = db.pool.Exec(ctx, `DROP TRIGGER IF EXISTS oauth_codes_block_delete ON oauth_codes`)
	if _, err := db.pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION oauth_codes_block_delete() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'delete blocked by atomicity probe';
		END $$`); err != nil {
		t.Fatalf("create trigger function: %v", err)
	}
	if _, err := db.pool.Exec(ctx, `
		CREATE TRIGGER oauth_codes_block_delete
			BEFORE DELETE ON oauth_codes
			FOR EACH ROW EXECUTE FUNCTION oauth_codes_block_delete()`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.pool.Exec(context.WithoutCancel(ctx), `DROP TRIGGER IF EXISTS oauth_codes_block_delete ON oauth_codes`)
		_, _ = db.pool.Exec(context.WithoutCancel(ctx), `DROP FUNCTION IF EXISTS oauth_codes_block_delete()`)
	})

	// An empty filter matches everything, so the access token is in scope.
	n, err := db.Tokens().RevokeTokens(ctx, oauth.TokenFilter{})
	if err == nil {
		t.Fatal("RevokeTokens reported success although the codes delete failed")
	}
	if n != 0 {
		t.Errorf("RevokeTokens returned count %d on failure, want 0: a partial count is indistinguishable from success", n)
	}

	// The token delete happened in the same transaction as the failing codes
	// delete, so the rollback has to have restored it. Before the fix the token
	// was autocommitted away and this count was 0.
	var remaining int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_access_tokens WHERE subject = $1`, subject).Scan(&remaining); err != nil {
		t.Fatalf("count access tokens: %v", err)
	}
	if remaining != 1 {
		t.Errorf("access tokens remaining after the failed revocation = %d, want 1: the transaction did not roll back", remaining)
	}
}
