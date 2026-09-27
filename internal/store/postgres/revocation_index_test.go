package postgres

import (
	"io/fs"
	"strings"
	"testing"
)

// TestRevokeTokenLookupIsIndexed is the database-free half of the revocation
// path's guard.
//
// RevokeToken resolves a presented token by oidc_refresh_tokens.id_hash in three
// statements (the RFC 7009 lookup and the two deletes of the pair). token_hash is
// the primary key; id_hash had no index, so every revocation swept the table. A
// database-backed test can prove the delete works but cannot see the scan, so
// this parses the migrations and asserts the index is present — the same shape as
// TestEverySweptTableHasADeadlineIndex, for the same reason.
func TestRevokeTokenLookupIsIndexed(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	const table = "oidc_refresh_tokens"
	found := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range createIndexRE.FindAllStringSubmatch(string(body), -1) {
			if m[1] != table {
				continue
			}
			for _, col := range strings.Split(m[2], ",") {
				if strings.TrimSpace(col) == "id_hash" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("%s has no index on id_hash: RevokeToken's RFC 7009 path scans the whole table "+
			"(add a migration like 0018_oidc_refresh_tokens_id_hash_idx.sql)", table)
	}
}
