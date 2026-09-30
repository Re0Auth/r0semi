package postgres

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// These are the database-free half of the RFC 9700 §4.14.2 family-revocation
// guard. The behaviour itself cannot be exercised here (no Postgres in this
// environment), so the properties that can be decided by reading the shipped SQL
// are pinned instead: which table the replay path consults, that the rotation
// claim returns the family it is inheriting, that the sweep covers the residue,
// and that the migration defines the column and the table the code names.

// oidcStoreMethod returns one OIDCStore method's source text, from its func line
// to the next top-level declaration. Reading the production source this way is
// the same shape migration_lock_guard_test.go uses; the property is "which
// statements are issued" and no unit test expresses that without a database.
func oidcStoreMethod(t *testing.T, src, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func \(s \*OIDCStore\) ` + regexp.QuoteMeta(name) + `\(`)
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

// TestRefreshReplayReadPathConsultsTheTombstone pins the mechanism the library
// forces: a refresh grant calls TokenRequestByRefreshToken FIRST, so a stale
// replay never reaches rotation and the family revocation must live on this read
// path. It keys on the tombstone rotation leaves, because the live row is already
// gone by the time the replay arrives.
func TestRefreshReplayReadPathConsultsTheTombstone(t *testing.T) {
	body, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	src := string(body)

	read := oidcStoreMethod(t, src, "TokenRequestByRefreshToken")
	for _, want := range []string{
		"oidc_refresh_token_tombstones",
		"ErrRefreshTokenSpent",
	} {
		if !strings.Contains(read, want) {
			t.Errorf("TokenRequestByRefreshToken no longer mentions %q: a replayed refresh token is refused "+
				"without revoking the family it belongs to (RFC 9700 §4.14.2)", want)
		}
	}
	// The live lookup is still the first thing it does: the family check is the
	// no-rows branch, not a replacement for resolving a live token.
	if !strings.Contains(read, "FROM oidc_refresh_tokens WHERE token_hash = $1") {
		t.Error("TokenRequestByRefreshToken no longer resolves the live row first; the replay branch must be " +
			"reached only when that lookup finds nothing")
	}

	rotate := oidcStoreMethod(t, src, "CreateAccessAndRefreshTokens")
	for _, want := range []string{
		"RETURNING family_id",
		"INSERT INTO oidc_refresh_token_tombstones",
	} {
		if !strings.Contains(rotate, want) {
			t.Errorf("CreateAccessAndRefreshTokens no longer contains %q: the rotation claim must carry the "+
				"spent row's family out of the DELETE and leave the tombstone the read path keys on", want)
		}
	}
}

// TestRevokeFamilyTxDeletesTheWholeChain pins the deletion set: every live
// generation, every tombstone of the family, and the access token each of them
// was paired with. The access delete joins through both token tables, which is
// why it has to run before either of them loses the rows naming those hashes.
func TestRevokeFamilyTxDeletesTheWholeChain(t *testing.T) {
	body, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	src := string(body)

	// revokeFamilyTx is a free function, not a method, so the method extractor
	// above does not apply; slice it directly.
	if !strings.Contains(src, "func revokeFamilyTx(") {
		t.Fatal("revokeFamilyTx is gone; the family revocation no longer has one implementation")
	}
	family := src[strings.Index(src, "func revokeFamilyTx("):]
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(family[1:]); next != nil {
		family = family[:next[0]+1]
	}

	for _, want := range []string{
		"DELETE FROM oidc_access_tokens",
		"SELECT id_hash FROM oidc_refresh_tokens WHERE family_id = $1",
		"SELECT id_hash FROM oidc_refresh_token_tombstones WHERE family_id = $1",
		"DELETE FROM oidc_refresh_tokens WHERE family_id = $1",
		"DELETE FROM oidc_refresh_token_tombstones WHERE family_id = $1",
	} {
		if !strings.Contains(family, want) {
			t.Errorf("revokeFamilyTx no longer contains %q: the family revocation is incomplete", want)
		}
	}
}

// TestLifecyclePathsClearTheSpentFamilyResidue pins the other half of the
// contract: a session termination, a grant revocation, an RFC 7009 revocation and
// a bulk Kill Switch all clear the tombstones they match, so a family's residue
// does not outlive the lifecycle action that removed its live generations.
func TestLifecyclePathsClearTheSpentFamilyResidue(t *testing.T) {
	body, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	src := string(body)

	cases := []struct {
		method string
		want   []string
	}{
		{"TerminateSession", []string{"DELETE FROM oidc_refresh_token_tombstones WHERE subject = $1 AND client_id = $2"}},
		{"RevokeGrant", []string{"DELETE FROM oidc_refresh_token_tombstones WHERE subject = $1 AND client_id = $2"}},
		{"RevokeToken", []string{
			"DELETE FROM oidc_refresh_token_tombstones WHERE id_hash = $1",
			"DELETE FROM oidc_refresh_token_tombstones WHERE token_hash = $1",
		}},
		{"RevokeTokens", []string{`revokeMatching(ctx, tx, []string{"oidc_refresh_token_tombstones"}, f)`}},
	}
	for _, c := range cases {
		got := oidcStoreMethod(t, src, c.method)
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s no longer contains %q: this lifecycle path leaves the spent family's residue "+
					"behind, and only a later replay would clear it", c.method, want)
			}
		}
	}
}

// TestSweepCoversTheTombstoneTable is the database-free half of the sweep guard:
// adding the table to expiredTables without the migration's expires_at index
// would make every sweep a sequential scan, which
// TestEverySweptTableHasADeadlineIndex proves separately by parsing the
// migrations. This one pins the entry itself.
func TestSweepCoversTheTombstoneTable(t *testing.T) {
	body, err := os.ReadFile("sweep.go")
	if err != nil {
		t.Fatalf("cannot read the sweep source: %v", err)
	}
	if !strings.Contains(string(body), `{"oidc_refresh_token_tombstones", "expires_at"}`) {
		t.Error("sweep.go no longer lists oidc_refresh_token_tombstones with its expires_at column: the " +
			"tombstone residue accumulates for the life of the deployment")
	}
	// Control: the table the tombstones stand in for is still swept too.
	if !strings.Contains(string(body), `{"oidc_refresh_tokens", "expires_at"}`) {
		t.Fatal("control broken: sweep.go no longer lists oidc_refresh_tokens")
	}
}

// TestMigrationDefinesTheRefreshTokenFamily proves the code's names exist in the
// schema: the family_id column the rotation inherits, the tombstone table both
// reads use, and a Down that removes the index before the column (a surviving
// index on a surviving table breaks the next `goose up`).
func TestMigrationDefinesTheRefreshTokenFamily(t *testing.T) {
	const name = "migrations/0024_refresh_token_family.sql"
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
		"ALTER TABLE oidc_refresh_tokens ADD COLUMN family_id",
		"UPDATE oidc_refresh_tokens SET family_id = token_hash WHERE family_id = ''",
		"CREATE TABLE oidc_refresh_token_tombstones",
		"CREATE INDEX oidc_refresh_tokens_family_id_idx ON oidc_refresh_tokens (family_id)",
		"CREATE INDEX oidc_refresh_token_tombstones_expires_at_idx ON oidc_refresh_token_tombstones (expires_at)",
		"CREATE INDEX oidc_refresh_token_tombstones_id_hash_idx ON oidc_refresh_token_tombstones (id_hash)",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("%s Up no longer contains %q", name, want)
		}
	}
	for _, want := range []string{
		"DROP TABLE IF EXISTS oidc_refresh_token_tombstones",
		"DROP INDEX IF EXISTS oidc_refresh_tokens_family_id_idx",
		"ALTER TABLE oidc_refresh_tokens DROP COLUMN IF EXISTS family_id",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("%s Down no longer contains %q; the rollback leaves schema the next Up collides with", name, want)
		}
	}
}

// TestMigrationDefinesTheRefreshNonce pins the schema half of OIDC Core §12.2:
// the refresh row carries the nonce, so migration 0026 must add the column (and
// drop it on rollback), and the production SQL must actually name it in both the
// INSERT that mints the row and the SELECT that reads it back for a rotation. A
// column the code never names is dead weight; a code name with no column is a
// runtime error, and neither is visible without a database.
func TestMigrationDefinesTheRefreshNonce(t *testing.T) {
	const name = "migrations/0026_oidc_refresh_nonce.sql"
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

	if !strings.Contains(up, "ALTER TABLE oidc_refresh_tokens ADD COLUMN nonce") {
		t.Errorf("%s Up no longer adds the nonce column the refresh INSERT writes", name)
	}
	if !strings.Contains(down, "ALTER TABLE oidc_refresh_tokens DROP COLUMN IF EXISTS nonce") {
		t.Errorf("%s Down no longer drops the nonce column; the rollback leaves schema the next Up collides with", name)
	}

	srcBody, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	src := string(srcBody)

	// The INSERT: the minted row must persist the nonce the request carried.
	rotate := oidcStoreMethod(t, src, "CreateAccessAndRefreshTokens")
	if !strings.Contains(rotate, "nonce") {
		t.Error("CreateAccessAndRefreshTokens no longer names the nonce column: the minted refresh row cannot " +
			"carry it to the refresh grant (OIDC Core §12.2)")
	}
	// The SELECT: a rotation rebuilds the request from this projection, so a
	// missing column silently drops the nonce on the next generation.
	read := oidcStoreMethod(t, src, "TokenRequestByRefreshToken")
	if !strings.Contains(read, "nonce") {
		t.Error("TokenRequestByRefreshToken no longer selects the nonce column: a rotation rebuilds the request " +
			"without it and the refreshed id_token drops the nonce")
	}
}
