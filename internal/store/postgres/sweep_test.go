package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"os"
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

// sweepDeleteTemplateRE captures the body of a backquoted SQL literal that begins
// with DELETE FROM. The sweep builds its statement from one such template, once
// per expiredTables entry.
var sweepDeleteTemplateRE = regexp.MustCompile("(?s)`(DELETE FROM[^`]*)`")

// boundedDelete reports whether a delete statement bounds one cycle's work: it
// must carry a LIMIT and select its rows through a ctid lookup.
func boundedDelete(stmt string) bool {
	return strings.Contains(strings.ToUpper(stmt), "LIMIT") && strings.Contains(stmt, "ctid IN (")
}

// TestSweepDeletesAreBounded is the database-free half of Z15-1's fix.
//
// TestSweepExpiredRemovesDatedRows proves the deletes still work; it cannot see
// that one of them is unbounded, because an unbounded delete removes the test's
// handful of rows exactly like a bounded one. An unbounded statement is the
// defect: on a grown table it can outlive the pool's statement_timeout, roll the
// single sweep transaction back and leave every tick re-attempting the same,
// still-growing work (Z15-1, docs/issues/P2-medium.md). This parses the shipped
// template and asserts every table's statement is bounded.
//
// The detector is proven to distinguish the two shapes before it is trusted, so a
// broken matcher fails here instead of passing vacuously.
func TestSweepDeletesAreBounded(t *testing.T) {
	if boundedDelete(`DELETE FROM oauth_codes WHERE expires_at < $1`) {
		t.Fatal("harness broken: the boundedness detector accepts an unbounded delete")
	}
	if !boundedDelete(`DELETE FROM oauth_codes WHERE expires_at < $1 AND ctid IN (SELECT ctid FROM oauth_codes WHERE expires_at < $1 LIMIT $2)`) {
		t.Fatal("harness broken: the boundedness detector rejects a bounded delete")
	}

	body, err := os.ReadFile("sweep.go")
	if err != nil {
		t.Fatalf("cannot read sweep.go: %v", err)
	}
	templates := sweepDeleteTemplateRE.FindAllStringSubmatch(string(body), -1)
	if len(templates) != 1 {
		t.Fatalf("found %d DELETE templates in sweep.go, want the one shared by every swept table; "+
			"the guard reads the wrong construct", len(templates))
	}
	if len(expiredTables) == 0 {
		t.Fatal("harness broken: expiredTables is empty, so the guard below proves nothing")
	}
	for _, tc := range expiredTables {
		// The template carries (table, column, table, column); building each table's
		// statement is what makes "every delete is bounded" a per-table assertion
		// rather than one about the template text.
		stmt := fmt.Sprintf(templates[0][1], tc.table, tc.column, tc.table, tc.column)
		if !boundedDelete(stmt) {
			t.Errorf("the delete for %q is unbounded: %q. One cycle must remove at most sweepBatchSize "+
				"rows through a ctid lookup, so a backlog keeps the statement under the pool's "+
				"statement_timeout and the next tick continues (Z15-1)", tc.table, stmt)
		}
	}
	t.Logf("sweep.go: %d tables share one bounded DELETE template (LIMIT + ctid IN)", len(expiredTables))
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
		{"oauth_refresh_tombstones", `INSERT INTO oauth_refresh_tombstones
			(token_hash, family_id, client_id, subject, expires_at)
			VALUES ($1, 'fam', 'cli', 'usr', $2)`},
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

// insertExpiredOAuthCodes plants n already-expired authorization codes in one
// table, which is the backlog shape Z15-1 reasons about.
func insertExpiredOAuthCodes(t *testing.T, db *DB, ctx context.Context, n int, expiry time.Time) {
	t.Helper()
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO oauth_codes
			(token_hash, client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at)
		SELECT 'z15-1-' || i::text, 'cli', 'usr', '{}', 'https://app/cb', 'ch', 'S256', $1
		  FROM generate_series(1, $2) AS i`, expiry, n); err != nil {
		t.Fatalf("plant %d expired oauth_codes: %v", n, err)
	}
}

// countSweptRows runs a scalar count, failing the test if it cannot.
func countSweptRows(t *testing.T, db *DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// TestSweepExpiredIsBoundedPerCycle is the database-backed half of Z15-1's fix.
//
// It plants more than one batch of expired rows in one table and asserts that one
// cycle removes exactly the batch, the rest survive, and the next cycle drains
// them — the bounded-progress property the source guard can only claim. A live row
// must be untouched by either cycle.
func TestSweepExpiredIsBoundedPerCycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const beyond = 7
	past := time.Now().Add(-time.Hour)
	insertExpiredOAuthCodes(t, db, ctx, int(sweepBatchSize)+beyond, past)
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO oauth_codes
			(token_hash, client_id, subject, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at)
		VALUES ('z15-1-live', 'cli', 'usr', '{}', 'https://app/cb', 'ch', 'S256', $1)`,
		time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert live row: %v", err)
	}

	removed, err := db.SweepExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed != sweepBatchSize {
		t.Fatalf("one cycle removed %d rows, want exactly the batch %d (a cycle must be bounded)",
			removed, sweepBatchSize)
	}
	if got := countSweptRows(t, db,
		`SELECT count(*) FROM oauth_codes WHERE expires_at < $1`, past); got != beyond {
		t.Fatalf("after one cycle %d expired rows remain, want %d", got, beyond)
	}
	if got := countSweptRows(t, db, `SELECT count(*) FROM oauth_codes`); got != beyond+1 {
		t.Fatalf("oauth_codes holds %d rows after one cycle, want %d expired + 1 live", got, beyond)
	}

	// The next cycle continues where the first stopped; the live row survives.
	removed, err = db.SweepExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed != beyond {
		t.Fatalf("second cycle removed %d rows, want the remaining %d", removed, beyond)
	}
	if got := countSweptRows(t, db, `SELECT count(*) FROM oauth_codes`); got != 1 {
		t.Fatalf("oauth_codes holds %d rows after the backlog drained, want only the live row", got)
	}
}

// TestSweepSurvivesATightStatementTimeout is the property the bound exists for: a
// cycle over a backlog larger than one batch must finish well inside a tight
// statement_timeout, because each statement is capped, and it must still make
// progress. Before the fix the same cycle was one unbounded delete per table and
// the backlog was the whole statement's work.
func TestSweepSurvivesATightStatementTimeout(t *testing.T) {
	db := openTestDBWith(t, PoolOptions{StatementTimeout: 250 * time.Millisecond})
	ctx := context.Background()

	const backlog = int(sweepBatchSize) + 250
	past := time.Now().Add(-time.Hour)
	insertExpiredOAuthCodes(t, db, ctx, backlog, past)

	removed, err := db.SweepExpired(ctx)
	if err != nil {
		t.Fatalf("a bounded cycle hit the 250ms statement timeout: %v", err)
	}
	if removed <= 0 {
		t.Fatalf("a bounded cycle made no progress: removed %d", removed)
	}
	maxCycle := int64(len(expiredTables)) * sweepBatchSize
	if removed > maxCycle {
		t.Fatalf("a cycle removed %d rows, more than the designed bound %d", removed, maxCycle)
	}
	if got := countSweptRows(t, db,
		`SELECT count(*) FROM oauth_codes WHERE expires_at < $1`, past); got != backlog-int(removed) {
		t.Fatalf("oauth_codes holds %d expired rows after the cycle, want %d", got, backlog-int(removed))
	}
}

// TestEverySweptReadPathAdjudicatesItsDeadline is the N-01 guard. The sweep's
// safety argument is "an expired row is one a lookup already refuses"; that is
// true for most tables but not for all of them, and a table added to
// expiredTables must not be able to inherit the claim silently. Every swept table
// needs an explicit entry: a read-path predicate this test can see in the shipped
// source, or a citation for the service layer that owns the deadline.
//
// Where the predicate lives in an OIDCStore method, the entry names that method
// (entry.method) and the guard reads only its body: `expires_at > $2` is shared by
// several reads in oidc.go, so a file-level `contains` would let a table inherit a
// predicate it never carries. The remaining exemptions are the citations for the
// legacy engine's service layer (oauth/as.go, oauth/device.go,
// internal/federation/bind.go); there is no open gap left in this store.
func TestEverySweptReadPathAdjudicatesItsDeadline(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("cannot read %s: %v", name, err)
		}
		return string(b)
	}
	files := map[string]string{
		"oidc.go":       read("oidc.go"),
		"oauth.go":      read("oauth.go"),
		"federation.go": read("federation.go"),
	}
	adjudicated := map[string]struct {
		file   string
		marker string
		note   string
		// method names the one OIDCStore method that must carry marker. When
		// set, the guard reads that method's body instead of the whole file, so a
		// marker shared by several reads cannot satisfy this entry. Empty means
		// the marker is checked at file level, for the legacy engine whose
		// receivers are not OIDCStore.
		method string
	}{
		"oidc_codes":                    {"oidc.go", "expires_at > $2", "", "AuthRequestByCode"},
		"oidc_access_tokens":            {"oidc.go", "ExpiresAt.After(s.now())", "", "SetIntrospectionFromToken"},
		"oidc_refresh_tokens":           {"oidc.go", "expires_at > $2", "", "TokenRequestByRefreshToken"},
		"oidc_refresh_token_tombstones": {"oidc.go", "expires_at > $2", "", "TokenRequestByRefreshToken"},
		"oidc_auth_requests":            {"oidc.go", "expires_at > $2", "", "AuthRequestByID"},
		"oidc_devices":                  {"oidc.go", "expires_at > $3", "", "GetDeviceAuthorizatonState"},
		"oauth_codes":                   {"oauth.go", "", "service: oauth/as.go judges expiry before the store is read", ""},
		"oauth_access_tokens":           {"oauth.go", "", "service: oauth/as.go judges expiry before the store is read", ""},
		"oauth_refresh_tokens":          {"oauth.go", "", "service: oauth/as.go judges expiry before the store is read", ""},
		"oauth_refresh_tombstones":      {"oauth.go", "expires_at > $2", "", ""},
		"oauth_device_authorizations":   {"oauth.go", "", "service: oauth/device.go judges expiry before the store is read", ""},
		"federation_bind_flows":         {"federation.go", "", "service: internal/federation/bind.go judges expiry", ""},
	}
	for _, tc := range expiredTables {
		entry, ok := adjudicated[tc.table]
		if !ok {
			t.Errorf("swept table %q has no read-path adjudication entry: name the predicate that refuses an "+
				"expired row, or cite the service layer that owns the deadline (N-01)", tc.table)
			continue
		}
		if entry.marker == "" {
			if entry.note == "" {
				t.Errorf("swept table %q carries neither a predicate nor a citation (N-01)", tc.table)
			}
			continue
		}
		// The marker must live in the named method when there is one: several
		// reads share `expires_at > $2`, so a file-level match would prove nothing
		// about this table's own read path (N-01).
		where, subject := entry.file, files[entry.file]
		if entry.method != "" {
			where, subject = entry.method, oidcStoreMethod(t, files["oidc.go"], entry.method)
		}
		if !strings.Contains(subject, entry.marker) {
			t.Errorf("swept table %q claims %s adjudicates its deadline, but %s does not contain %q (N-01)",
				tc.table, where, where, entry.marker)
		}
	}
}
