package postgres

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// indexLeadsWith reports whether any index's *first* column is col. A trailing
// column does not help a predicate on it alone, so the (subject, client_id)
// indexes do not satisfy a client_id-only filter.
func indexLeadsWith(lists []string, col string) bool {
	for _, cols := range lists {
		first := strings.TrimSpace(strings.Split(cols, ",")[0])
		if first == col {
			return true
		}
	}
	return false
}

// revokeMatchingTableLiteralRE extracts the table list of a revokeMatching call:
//
//	revokeMatching(ctx, tx, []string{"oidc_access_tokens", "oidc_refresh_tokens"}, f)
//
// It is applied to comment-stripped source, so a table named in prose cannot be
// mistaken for one the adapter deletes from.
var revokeMatchingTableLiteralRE = regexp.MustCompile(`revokeMatching\(ctx, [A-Za-z0-9_.]+, \[\]string\{([^}]*)\}`)

// revokePredicateTableLiteralRE extracts the literal slice a legacy multi-table
// delete walks with revokePredicate:
//
//	for _, table := range []string{"oauth_codes", "oauth_refresh_tombstones"} {
var revokePredicateTableLiteralRE = regexp.MustCompile(`range \[\]string\{([^}]*)\}`)

// stripSourceComments removes // and /* */ comments so a SQL fragment or a table
// name quoted inside prose is never mistaken for executed code.
func stripSourceComments(src string) string {
	out := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// clientScopedRevokeTables derives, from the adapter's own source, every table a
// client_id-only oauth.TokenFilter can delete from.
//
// The table list used to be written out by hand here, and a hand list is exactly
// how a table escaped the guard twice: 0022 covered six tables but missed
// oidc_devices (G-14), and the list that replaced it still missed
// oidc_refresh_token_tombstones. Deriving the set from the call sites is what
// makes a future delete site fail this guard instead of silently scanning:
//
//   - every `revokeMatching(ctx, …, []string{…}` table literal in oidc.go and
//     oauth.go (the OP path and the legacy path both take a filter that can be
//     client-only — admin.SuspendClient / DeleteClient and the `client` Kill
//     Switch target pass exactly that);
//   - the `DELETE FROM oidc_auth_requests` of revokePendingAuthorizations;
//   - the `for _, table := range []string{…}` of the legacy Tokens.RevokeTokens,
//     which applies the same predicate to oauth_codes and oauth_refresh_tombstones.
func clientScopedRevokeTables(t *testing.T) map[string]string {
	t.Helper()
	out := make(map[string]string)
	add := func(table, where string) {
		if table != "" {
			out[table] = where
		}
	}

	for _, file := range []string{"oauth.go", "oidc.go"} {
		code := stripSourceComments(sourceOf(t, file))
		for _, m := range revokeMatchingTableLiteralRE.FindAllStringSubmatch(code, -1) {
			for _, table := range strings.Split(m[1], ",") {
				add(strings.Trim(strings.TrimSpace(table), `" `), file+" revokeMatching")
			}
		}
	}

	oidc := stripSourceComments(sourceOf(t, "oidc.go"))
	pending := functionBody(t, oidc, "func revokePendingAuthorizations(")
	if !strings.Contains(pending, "DELETE FROM oidc_auth_requests") {
		t.Fatal("revokePendingAuthorizations no longer deletes oidc_auth_requests; the derivation is stale")
	}
	add("oidc_auth_requests", "oidc.go revokePendingAuthorizations")
	oauth := stripSourceComments(sourceOf(t, "oauth.go"))
	legacy := receiverMethod(t, oauth, "oauth.go", "RevokeTokens")
	legacyTables := 0
	for _, m := range revokePredicateTableLiteralRE.FindAllStringSubmatch(legacy, -1) {
		for _, table := range strings.Split(m[1], ",") {
			if table = strings.Trim(strings.TrimSpace(table), `" `); table != "" {
				add(table, "oauth.go RevokeTokens (legacy)")
				legacyTables++
			}
		}
	}
	if legacyTables == 0 {
		t.Fatal("the legacy Tokens.RevokeTokens table slice was not found; the derivation is stale")
	}

	if len(out) < 5 {
		t.Fatalf("derived only %d client-scoped revoke tables; the extraction is broken", len(out))
	}
	return out
}

// TestClientScopedRevokeIsIndexed covers the other direction of a bulk revocation:
// the operator's suspend / delete-client action and the `client` Kill Switch filter
// by client_id alone. The (subject, client_id) indexes do not help a predicate on
// client_id by itself, so it needs its own leading-column index.
//
// The table set is derived from the adapter's own statements (see
// clientScopedRevokeTables), not enumerated here: a hand-written list cannot catch
// the table the next delete site adds, which is how G-14 (oidc_devices) and then
// oidc_refresh_token_tombstones were missed.
func TestClientScopedRevokeIsIndexed(t *testing.T) {
	indexed := migrationIndexes(t)
	tables := clientScopedRevokeTables(t)

	// Anti-vacuous: the parser must see the indexes 0021/0022/0025/0029/0031
	// actually created, so a pipeline that stopped reading the schema fails here
	// rather than passing every check below.
	for _, ok := range []struct{ table, col string }{
		{"oidc_access_tokens", "client_id"},
		{"oidc_refresh_tokens", "client_id"},
		{"oidc_auth_requests", "client_id"},
		{"oauth_codes", "client_id"},
		{"oidc_devices", "client_id"},
		{"oidc_refresh_token_tombstones", "client_id"},
	} {
		if !indexLeadsWith(indexed[ok.table], ok.col) {
			t.Fatalf("the parser does not see %s.%s's index; it is not reading the migrations and every "+
				"assertion below is vacuous", ok.table, ok.col)
		}
	}

	for table, where := range tables {
		if !indexLeadsWith(indexed[table], "client_id") {
			t.Errorf("%s has no index with client_id as its leading column; the client-scoped revocation "+
				"(%s) scans the table (add a migration like 0022_bulk_revoke_client_indexes.sql)", table, where)
		}
	}
}

// TestRevokePredicateIsSargable pins the replacement of the old
// `($1 = ” OR client_id = $1) AND ($2 = ” OR subject = $2)` statement: it has to
// drop empty filter fields so the planner can use the indexes, while still meaning
// "everything" for an empty filter.
func TestRevokePredicateIsSargable(t *testing.T) {
	cases := []struct {
		name       string
		filter     oauth.TokenFilter
		wantClause string
		wantArgs   int
	}{
		{"all", oauth.TokenFilter{}, "", 0},
		{"client", oauth.TokenFilter{ClientID: "cli"}, " WHERE client_id = $1", 1},
		{"subject", oauth.TokenFilter{Subject: "usr"}, " WHERE subject = $1", 1},
		{"both", oauth.TokenFilter{ClientID: "cli", Subject: "usr"}, " WHERE client_id = $1 AND subject = $2", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clause, args := revokePredicate(c.filter)
			if clause != c.wantClause {
				t.Fatalf("clause = %q, want %q", clause, c.wantClause)
			}
			if len(args) != c.wantArgs {
				t.Fatalf("args = %v, want %d", args, c.wantArgs)
			}
			if strings.Contains(clause, "= '' OR") {
				t.Fatalf("clause %q keeps the non-sargable OR form", clause)
			}
		})
	}
}
