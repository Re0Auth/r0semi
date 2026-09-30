package postgres

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// These are the database-free half of the RFC 9700 §4.14.2 guard on the PUBLIC
// oauth.Store's Postgres implementation. The behaviour itself needs Postgres (the
// environment has none), so the properties that can be decided by reading the
// shipped SQL are pinned instead: which table the replay path consults, that the
// rotation claim leaves a tombstone carrying the family, that the family
// revocation removes every table's rows, that the lifecycle paths clear the
// residue, and that migration 0025 defines the column and the table the code names.
//
// This is the counterpart of refresh_family_guard_test.go (the OP store's guard)
// and is intentionally separate: the two stores are different implementations of
// the same rule, and one guard must not stand in for the other.

// tokensMethod returns one *Tokens method's source text, from its func line to the
// next top-level declaration. Reading the production source this way is the same
// shape migration_lock_guard_test.go and refresh_family_guard_test.go use; the
// property is "which statements are issued" and no unit test expresses that
// without a database.
func tokensMethod(t *testing.T, src, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func \(s \*Tokens\) ` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("method %s not found in the adapter source; the guard is reading the wrong file", name)
	}
	rest := src[loc[0]:]
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:]); next != nil {
		rest = rest[:next[0]+1]
	}
	return rest
}

// TestTokensStoreSatisfiesTheOAuthContract pins the compile-time assertion that
// keeps the public interface and this implementation from drifting.
func TestTokensStoreSatisfiesTheOAuthContract(t *testing.T) {
	body, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	if !strings.Contains(string(body), "var _ oauth.Store = (*Tokens)(nil)") {
		t.Error("oauth.go no longer asserts `var _ oauth.Store = (*Tokens)(nil)`: a method dropped from the " +
			"public Store contract would no longer fail the build here")
	}
}

// TestTokensConsumeRefreshConsultsTheTombstone pins the mechanism: the live DELETE
// still comes first, its RETURNING carries the family out, the tombstone is
// written in the same transaction, and a second presentation of the spent hash
// returns the typed reuse error rather than an ordinary not-found.
func TestTokensConsumeRefreshConsultsTheTombstone(t *testing.T) {
	body, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	consume := tokensMethod(t, string(body), "ConsumeRefresh")

	for _, want := range []string{
		"FROM oauth_refresh_tokens",            // the live claim
		"family_id",                            // what the RETURNING carries
		"INSERT INTO oauth_refresh_tombstones", // the residue the replay path reads
		"SELECT family_id FROM oauth_refresh_tombstones",
		"oauth.RefreshReuseError",
		"oauth.ErrTokenNotFound",
		"look up spent refresh token", // a database error is surfaced, not folded
	} {
		if !strings.Contains(consume, want) {
			t.Errorf("ConsumeRefresh no longer contains %q: a replayed refresh token is refused without "+
				"revoking the family it belongs to (RFC 9700 §4.14.2)", want)
		}
	}
	// The delete and the tombstone must be one transaction, or a crash between
	// them loses the only pointer to the family.
	if !strings.Contains(consume, "s.pool.Begin(ctx)") || !strings.Contains(consume, "tx.Commit(ctx)") {
		t.Error("ConsumeRefresh no longer wraps the claim and its tombstone in one transaction: the family " +
			"would be unrecoverable between the DELETE and the INSERT")
	}
	// The tombstone lookup is judged by the store clock, not the database's: a
	// deadline this process wrote must be judged by the clock that wrote it.
	if !strings.Contains(consume, "s.clock()") {
		t.Error("ConsumeRefresh no longer judges the tombstone's deadline with the store clock; mixing in " +
			"the database's now() is the two-clock policy violation clock_test.go guards")
	}
}

// TestTokensRevokeRefreshFamilyDeletesTheWholeChain pins the deletion set: every
// live refresh generation, every tombstone of the family, and every access record
// minted with it — in one transaction, with an empty id revoking nothing.
func TestTokensRevokeRefreshFamilyDeletesTheWholeChain(t *testing.T) {
	body, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	revoke := tokensMethod(t, string(body), "RevokeRefreshFamily")

	for _, want := range []string{
		`DELETE FROM oauth_access_tokens WHERE family_id = $1`,
		`DELETE FROM oauth_refresh_tokens WHERE family_id = $1`,
		`DELETE FROM oauth_refresh_tombstones WHERE family_id = $1`,
		`s.pool.Begin(ctx)`,
	} {
		if !strings.Contains(revoke, want) {
			t.Errorf("RevokeRefreshFamily no longer contains %q: the family revocation is incomplete", want)
		}
	}
	// An empty family id must short-circuit before any statement: a caller with no
	// family must never turn a detection into a global token wipe.
	if !strings.Contains(revoke, `if familyID == ""`) {
		t.Error("RevokeRefreshFamily no longer refuses an empty familyID explicitly; the empty string would " +
			"otherwise be used as a predicate")
	}
}

// TestTokensWritesTheFamilyOnBothTokenTables pins the write half: a first issuance
// mints a family and both records carry it, so the access token dies with the
// chain it was minted for.
func TestTokensWritesTheFamilyOnBothTokenTables(t *testing.T) {
	body, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	src := string(body)
	for _, method := range []string{"SaveAccess", "SaveRefresh"} {
		got := tokensMethod(t, src, method)
		if !strings.Contains(got, "family_id") {
			t.Errorf("%s no longer writes family_id: the record joins no rotation family and a replay cannot "+
				"revoke it", method)
		}
	}
}

// TestTokensLifecycleClearsTheSpentFamilyResidue pins the other half: an RFC 7009
// revocation, a per-client grant revocation and a bulk Kill Switch all clear the
// tombstones they match, so a family's residue does not outlive the action that
// removed its live generations.
func TestTokensLifecycleClearsTheSpentFamilyResidue(t *testing.T) {
	body, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	src := string(body)

	cases := []struct {
		method string
		want   []string
	}{
		{"DeleteRefresh", []string{"DELETE FROM oauth_refresh_tombstones WHERE token_hash = $1"}},
		{"DeleteBySubjectClient", []string{"DELETE FROM oauth_refresh_tombstones WHERE subject = $1 AND client_id = $2"}},
		{"RevokeTokens", []string{"oauth_refresh_tombstones"}},
	}
	for _, c := range cases {
		got := tokensMethod(t, src, c.method)
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s no longer contains %q: this lifecycle path leaves the spent family's residue "+
					"behind, and only a later replay would clear it", c.method, want)
			}
		}
	}
}

// TestSweepCoversTheOAuthTombstoneTable is the database-free half of the sweep
// guard: without the tombstone table in expiredTables the residue accumulates for
// the life of the deployment. TestEverySweptTableHasADeadlineIndex proves the
// migration carries the expires_at index the entry needs.
func TestSweepCoversTheOAuthTombstoneTable(t *testing.T) {
	body, err := os.ReadFile("sweep.go")
	if err != nil {
		t.Fatalf("cannot read the sweep source: %v", err)
	}
	if !strings.Contains(string(body), `{"oauth_refresh_tombstones", "expires_at"}`) {
		t.Error("sweep.go no longer lists oauth_refresh_tombstones with its expires_at column: the tombstone " +
			"residue accumulates for the life of the deployment")
	}
	// Control: the table the tombstones stand in for is still swept too.
	if !strings.Contains(string(body), `{"oauth_refresh_tokens", "expires_at"}`) {
		t.Fatal("control broken: sweep.go no longer lists oauth_refresh_tokens")
	}
}

// TestMigration0025DefinesTheOAuthRefreshFamily proves the code's names exist in
// the schema: the family_id columns the rotation inherits on both token tables,
// their backfill, the tombstone table both paths use, the indexes each lifecycle
// predicate needs, and a Down that removes the table and both columns.
func TestMigration0025DefinesTheOAuthRefreshFamily(t *testing.T) {
	const name = "migrations/0025_oauth_refresh_family.sql"
	body, err := fs.ReadFile(migrationsFS, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	text := string(body)

	up := text
	down := ""
	if i := strings.Index(text, "-- +goose Down"); i >= 0 {
		up, down = text[:i], text[i:]
	} else {
		t.Fatalf("%s has no Down section", name)
	}

	for _, want := range []string{
		"ALTER TABLE oauth_access_tokens ADD COLUMN family_id",
		"ALTER TABLE oauth_refresh_tokens ADD COLUMN family_id",
		"UPDATE oauth_access_tokens SET family_id = token_hash WHERE family_id = ''",
		"UPDATE oauth_refresh_tokens SET family_id = token_hash WHERE family_id = ''",
		"CREATE INDEX oauth_access_tokens_family_id_idx ON oauth_access_tokens (family_id)",
		"CREATE INDEX oauth_refresh_tokens_family_id_idx ON oauth_refresh_tokens (family_id)",
		"CREATE TABLE oauth_refresh_tombstones",
		"CREATE INDEX oauth_refresh_tombstones_family_id_idx ON oauth_refresh_tombstones (family_id)",
		"CREATE INDEX oauth_refresh_tombstones_expires_at_idx ON oauth_refresh_tombstones (expires_at)",
		"CREATE INDEX oauth_refresh_tombstones_client_id_idx ON oauth_refresh_tombstones (client_id)",
		"CREATE INDEX oauth_refresh_tombstones_subject_idx ON oauth_refresh_tombstones (subject)",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("%s Up no longer contains %q", name, want)
		}
	}
	for _, want := range []string{
		"DROP TABLE IF EXISTS oauth_refresh_tombstones",
		"DROP INDEX IF EXISTS oauth_access_tokens_family_id_idx",
		"DROP INDEX IF EXISTS oauth_refresh_tokens_family_id_idx",
		"ALTER TABLE oauth_access_tokens DROP COLUMN IF EXISTS family_id",
		"ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS family_id",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("%s Down no longer contains %q; the rollback leaves schema the next Up collides with", name, want)
		}
	}
}
