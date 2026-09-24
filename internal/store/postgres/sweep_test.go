package postgres

import (
	"context"
	"testing"
	"time"
)

// TestSweepExpiredRemovesDatedRows plants one live and one expired row in every
// dated table, sweeps, and checks that exactly the expired ones went. It is the
// database-backed proof that the sweep's table list matches the schema: a table
// added with a deadline column but left out of expiredTables shows up as an
// expired row that survived.
func TestSweepExpiredRemovesDatedRows(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Each entry inserts one row keyed by $1 with deadline $2. Only columns that
	// are NOT NULL without a default are named; the rest take their defaults.
	cases := []struct {
		table  string
		insert string
	}{
		{"oauth_codes", `INSERT INTO oauth_codes
			(token_hash, client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at)
			VALUES ($1, 'cli', 'usr', '{}', 'https://app/cb', 'ch', 'S256', $2)`},
		{"oauth_access_tokens", `INSERT INTO oauth_access_tokens
			(token_hash, client_id, subject, scopes, issued_at, expires_at)
			VALUES ($1, 'cli', 'usr', '{}', now(), $2)`},
		{"oauth_refresh_tokens", `INSERT INTO oauth_refresh_tokens
			(token_hash, client_id, subject, scopes, issued_at, expires_at)
			VALUES ($1, 'cli', 'usr', '{}', now(), $2)`},
		{"oauth_device_authorizations", `INSERT INTO oauth_device_authorizations
			(device_code_hash, user_code, client_id, scopes, status, expires_at)
			VALUES ($1, 'ABCD', 'cli', '{}', 'pending', $2)`},
		{"federation_bind_flows", `INSERT INTO federation_bind_flows
			(state, id, user_id, game, source, pkce_verifier, expires_at)
			VALUES ($1, 'bnd', 'usr', 'phigros', 'tap', 'v', $2)`},
		{"oidc_auth_requests", `INSERT INTO oidc_auth_requests
			(id, client_id, redirect_uri, response_type, created_at, expires_at)
			VALUES ($1, 'cli', 'https://app/cb', 'code', now(), $2)`},
		{"oidc_codes", `INSERT INTO oidc_codes (code_hash, request_id, expires_at)
			VALUES ($1, 'req', $2)`},
		{"oidc_access_tokens", `INSERT INTO oidc_access_tokens
			(id_hash, client_id, subject, scopes, expires_at)
			VALUES ($1, 'cli', 'usr', '{}', $2)`},
		{"oidc_refresh_tokens", `INSERT INTO oidc_refresh_tokens
			(token_hash, id_hash, client_id, subject, scopes, expires_at)
			VALUES ($1, 'h', 'cli', 'usr', '{}', $2)`},
		// user_code doubles as the row key: the canonical user code carries a
		// UNIQUE index, so the live and dead rows must not collide on it.
		{"oidc_devices", `INSERT INTO oidc_devices
			(device_code_hash, user_code, client_id, scopes, expires_at)
			VALUES ($1, $1, 'cli', '{}', $2)`},
	}

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	for _, c := range cases {
		if _, err := db.pool.Exec(ctx, c.insert, "live_"+c.table, future); err != nil {
			t.Fatalf("insert live %s: %v", c.table, err)
		}
		if _, err := db.pool.Exec(ctx, c.insert, "dead_"+c.table, past); err != nil {
			t.Fatalf("insert dead %s: %v", c.table, err)
		}
	}

	removed, err := db.SweepExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed != int64(len(cases)) {
		t.Fatalf("removed = %d, want %d", removed, len(cases))
	}

	// The live rows survive; the deleted ones stay gone on a second sweep.
	for _, c := range cases {
		var n int
		if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM `+c.table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", c.table, err)
		}
		if n != 1 {
			t.Fatalf("%s has %d rows after the sweep, want 1", c.table, n)
		}
	}
	again, err := db.SweepExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Fatalf("second sweep removed %d, want 0", again)
	}
}
