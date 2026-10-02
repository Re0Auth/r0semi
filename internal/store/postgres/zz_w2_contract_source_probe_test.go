package postgres

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// W2 source guards for this round's two contract changes. They need no database:
// what a paged listing and a cascading delete must do is visible in the
// statement shape, and these run in the default `go test` where the Postgres
// integration tests skip without a DSN.
func methodBody(t *testing.T, source, signature string) string {
	t.Helper()
	i := strings.Index(source, signature)
	if i < 0 {
		t.Fatalf("%s not found: the API this guard pins has moved or been renamed", signature)
	}
	body := source[i:]
	if j := strings.Index(body, "\nfunc "); j >= 0 {
		body = body[:j]
	}
	return body
}

// The Postgres listing must be keyset-paged in the database, not read whole and
// sliced in Go: `WHERE id > $n` plus `ORDER BY id LIMIT $n+1` is what keeps the
// page a bounded index scan (S11-9).
func TestW2S119ClientsListIsKeysetPagedInSQL(t *testing.T) {
	source, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("read oauth.go: %v", err)
	}
	body := methodBody(t, string(source), "func (s *Clients) ListClients(")

	if !strings.Contains(body, "ORDER BY id") {
		t.Error("Clients.ListClients does not ORDER BY id: the page order is not the cursor's order")
	}
	if !strings.Contains(body, "LIMIT") {
		t.Error("Clients.ListClients has no LIMIT: the query is not bounded by the page size")
	}
	if !strings.Contains(body, "id > $") {
		t.Error("Clients.ListClients has no `id > $n` predicate: it reads from the start of the table " +
			"on every page instead of resuming at the cursor")
	}
	// limit+1 is how the caller learns whether a next page exists without a
	// second query; a plain `limit` would report a next cursor only by guessing.
	if !strings.Contains(body, "limit + 1") {
		t.Error("Clients.ListClients does not ask for one row beyond the page: it cannot tell a full " +
			"page from the last one")
	}
	// The full-table form is the bug this fixes; a stray unfiltered SELECT would
	// reintroduce it even with the paged one present.
	if regexp.MustCompile(`FROM oauth_clients\s+ORDER BY`).MatchString(body) {
		t.Error("Clients.ListClients still has an unfiltered `FROM oauth_clients ORDER BY` select")
	}
}

// Deleting a client must revoke its credentials, and the Postgres registry is
// the one that owns its token tables, so it does it directly — in one
// transaction, over every table the two RevokeTokens implementations cover
// (KIT-10). The drift guard is the second assertion: a new token table added to
// a bulk revocation has to be added here too.
func TestW2KIT10ClientsDeleteRevokesInOneTransaction(t *testing.T) {
	source, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("read oauth.go: %v", err)
	}
	body := methodBody(t, string(source), "func (s *Clients) Delete(")

	if !strings.Contains(body, "s.pool.Begin(ctx)") || !strings.Contains(body, "tx.Commit(ctx)") {
		t.Error("Clients.Delete is not one transaction: a failure could leave the client gone with its " +
			"tokens still live, or the reverse")
	}
	if !strings.Contains(body, "DELETE FROM oauth_clients WHERE id = $1") {
		t.Error("Clients.Delete does not remove the client row")
	}
	if len(revokedTables(body)) == 0 {
		t.Fatal("the guard found no token table in Clients.Delete: re-derive it, the method shape changed")
	}

	// Every table a bulk revocation clears for a client must be cleared here too.
	oidcSrc, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatalf("read oidc.go: %v", err)
	}
	covered := map[string]bool{}
	for _, src := range []string{
		string(source), // Tokens.RevokeTokens
		string(oidcSrc), // OIDCStore.RevokeTokens
	} {
		for _, sig := range []string{
			"func (s *Tokens) RevokeTokens(",
			"func (s *OIDCStore) RevokeTokens(",
		} {
			if !strings.Contains(src, sig) {
				continue
			}
			for _, table := range revokedTables(methodBody(t, src, sig)) {
				covered[table] = true
			}
		}
	}
	if len(covered) < 8 {
		t.Fatalf("the guard found only %d revoked tables across the bulk revocations: re-derive it", len(covered))
	}
	bodyTables := map[string]bool{}
	for _, table := range revokedTables(body) {
		bodyTables[table] = true
	}
	for table := range covered {
		if !bodyTables[table] {
			t.Errorf("Clients.Delete does not clear %s, which both bulk revocations do: deleting a client "+
				"would leave that credential behind", table)
		}
	}
}

var revokedTableRE = regexp.MustCompile(`"((?:oauth|oidc)_[a-z_]+)"`)

// revokedTables lists the table names a method body names as string literals.
// Only literals: the methods build their statements from compile-time constants,
// which is exactly what makes this readable.
func revokedTables(body string) []string {
	var out []string
	for _, m := range revokedTableRE.FindAllStringSubmatch(body, -1) {
		if m[1] != "oauth_clients" { // the registration, not a token table
			out = append(out, m[1])
		}
	}
	return out
}
