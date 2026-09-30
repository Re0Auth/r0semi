package postgres

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"
)

// createIndexRE captures an index's target table and its column list from a
// CREATE INDEX. Column lists here are simple (names, or one expression), and the
// expression forms do not contain a top-level `)`, so a non-greedy match is
// enough to answer "is there an index on this column".
var createIndexRE = regexp.MustCompile(`(?is)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF NOT EXISTS\s+)?\w+\s+ON\s+(\w+)\s*\(([^)]*)\)`)

// TestEverySweptTableHasADeadlineIndex is the database-free half of the sweep's
// own guard.
//
// TestSweepExpiredRemovesDatedRows proves the deletes work; it cannot see that one
// of them is a sequential scan. This parses the migrations and asserts the schema
// carries an index on the deadline column of every table in expiredTables — which
// is how oidc_devices.expires_at stayed missing: a table added to the sweep
// without an index is invisible to a test that only counts rows.
func TestEverySweptTableHasADeadlineIndex(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	// table -> the column lists of its indexes.
	indexed := make(map[string][]string)
	total := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range createIndexRE.FindAllStringSubmatch(string(body), -1) {
			indexed[m[1]] = append(indexed[m[1]], m[2])
			total++
		}
	}
	// Anti-vacuous: a broken parser would find nothing and pass every check below.
	if total < 15 {
		t.Fatalf("parsed only %d index definitions; the parser is broken", total)
	}

	for _, t2 := range expiredTables {
		lists := indexed[t2.table]
		if len(lists) == 0 {
			t.Errorf("swept table %q has no index at all: the sweep scans it every run", t2.table)
			continue
		}
		found := false
		for _, cols := range lists {
			for _, col := range strings.Split(cols, ",") {
				if strings.TrimSpace(col) == t2.column {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("swept table %q has no index on %q: DELETE ... WHERE %s < $1 scans the whole table "+
				"every sweep (add a migration like 0017_oidc_devices_expires_idx.sql)",
				t2.table, t2.column, t2.column)
		}
	}
}

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
		{"oidc_refresh_token_tombstones", `INSERT INTO oidc_refresh_token_tombstones
			(token_hash, family_id, id_hash, client_id, subject, expires_at)
			VALUES ($1, 'fam', 'h', 'cli', 'usr', $2)`},
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
