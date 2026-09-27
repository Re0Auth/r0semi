package postgres

import (
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

// TestClientScopedRevokeIsIndexed covers the other direction of a bulk revocation:
// the operator's suspend / delete-client action and the `client` Kill Switch filter
// by client_id alone. The (subject, client_id) indexes do not help a predicate on
// client_id by itself, so it needs its own leading-column index.
func TestClientScopedRevokeIsIndexed(t *testing.T) {
	indexed := migrationIndexes(t)
	for _, table := range []string{"oidc_access_tokens", "oidc_refresh_tokens"} {
		if !indexLeadsWith(indexed[table], "client_id") {
			t.Errorf("%s has no index with client_id as its leading column: the client-scoped "+
				"revocation scans the table (add a migration like 0021_token_client_indexes.sql)", table)
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
