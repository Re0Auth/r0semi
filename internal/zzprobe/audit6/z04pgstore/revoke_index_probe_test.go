//go:build audit6

package z04pgstore

// The client-scoped bulk revocation's index coverage, derived from the Go
// statements rather than from a hand-written list.
//
// Round 5's P2-4/P2-5 found that client_id-only bulk revocation predicates had
// no leading index; the fix (b35f893) added migration 0022 and extended the
// in-package guard TestClientScopedRevokeIsIndexed to "every table a
// client_id-only predicate deletes from" — six tables. This probe derives that
// set from the adapter's own source instead of enumerating it by hand, which is
// how a seventh table the list missed showed up: OIDCStore.RevokeTokens also
// runs revokeMatching over oidc_devices, and that table had no client_id index.
// G-14 was fixed by migration 0029 and the guard now lists oidc_devices; the
// derivation is kept because it immediately found an EIGHTH table,
// oidc_refresh_token_tombstones, which is still unindexed (STILL-OPEN).

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// clientScopedRevokeTables returns every table a client_id-only oauth.TokenFilter
// deletes from, extracted from the adapter's sources:
//
//   - every `revokeMatching(ctx, …, []string{…}` table list (oidc.go's OP path
//     and oauth.go's legacy path both take a filter that can be client-only —
//     admin.SuspendClient / DeleteClient and the `client` Kill Switch target
//     pass exactly that);
//   - the `DELETE FROM oidc_auth_requests`+clause of revokePendingAuthorizations;
//   - the `DELETE FROM oauth_codes`+clause of the legacy Tokens.RevokeTokens.
func clientScopedRevokeTables(t *testing.T) map[string]string {
	t.Helper()
	out := make(map[string]string)

	scan := func(file string) {
		code := stripGoComments(readShipped(t, adapterDir+"/"+file))
		re := regexp.MustCompile(`revokeMatching\(ctx, [A-Za-z.]+, \[\]string\{([^}]*)\}`)
		for _, m := range re.FindAllStringSubmatch(code, -1) {
			for _, table := range strings.Split(m[1], ",") {
				table = strings.TrimSpace(strings.Trim(table, `" `))
				if table == "" {
					continue
				}
				out[table] = file + " revokeMatching"
			}
		}
	}
	scan("oidc.go")
	scan("oauth.go")

	oidc := stripGoComments(readShipped(t, adapterDir+"/oidc.go"))
	pending := topLevelFuncBodyOf(t, oidc, "revokePendingAuthorizations")
	if m := regexp.MustCompile("DELETE FROM (oidc_auth_requests)").FindStringSubmatch(pending); m != nil {
		out[m[1]] = "oidc.go revokePendingAuthorizations"
	}
	oauthCode := stripGoComments(readShipped(t, adapterDir+"/oauth.go"))
	legacy := methodBodyOf(t, oauthCode, "RevokeTokens")
	if m := regexp.MustCompile("DELETE FROM (oauth_codes)").FindStringSubmatch(legacy); m != nil {
		out[m[1]] = "oauth.go RevokeTokens (legacy)"
	}
	if len(out) < 5 {
		t.Fatalf("derived only %d client-scoped revoke tables; the extraction is broken", len(out))
	}
	return out
}

// TestEveryClientScopedRevokeTableHasALeadingClientIndex started as the G-14
// finding: the table set a client_id-only filter deletes from is seven, not the
// six the fix and its guard enumerated, and the seventh — oidc_devices — had no
// index whose leading column is client_id. Migration 0029 fixed that, so the
// oidc_devices check is now an anti-vacuous guard. The derivation is kept because
// it finds an eighth table, oidc_refresh_token_tombstones, still without a
// leading client_id index (STILL-OPEN, needs a migration outside this probe's
// write scope). Every one of those deletes runs inside the one-transaction
// revocation an operator fires during an incident.
func TestEveryClientScopedRevokeTableHasALeadingClientIndex(t *testing.T) {
	leading := leadingIndexCols(t)
	tables := clientScopedRevokeTables(t)

	// Anti-vacuous in both directions: the schema parser must see the
	// indexes 0021/0022/0029 actually created (these must pass), and must not
	// believe every column is indexed.
	//
	// G-14 used to be asserted on the other side: oidc_devices had no leading
	// client_id index and this probe failed with a message saying so. Migration
	// 0029 added it and the in-package guard now lists the table, so the check
	// below is a guard for that fix rather than the finding.
	for _, ok := range []struct{ table, col string }{
		{"oidc_access_tokens", "client_id"},
		{"oidc_auth_requests", "client_id"},
		{"oauth_codes", "client_id"},
		{"oidc_devices", "client_id"},
	} {
		if !leading[ok.table][ok.col] {
			t.Fatalf("the parser does not see %s.%s's index; it is not reading migration 0021/0022/0029 "+
				"and every assertion below is vacuous", ok.table, ok.col)
		}
	}

	var missing []string
	for table, where := range tables {
		if !leading[table]["client_id"] {
			missing = append(missing, table+" (deleted by "+where+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("UNINDEXED CLIENT-SCOPED REVOKE: %s has no index with client_id as its leading column; "+
			"admin.SuspendClient / DeleteClient and the `client` Kill Switch filter by client_id alone, "+
			"and the delete runs inside the same incident-path transaction as the indexed tables "+
			"(migration 0022 and G-14's 0029 covered the seven; this is the eighth the derivation found)", m)
	}
}

// TestTheClientScopedRevokeGuardCoversTheDerivedTableSet is the guard-quality
// half: the in-package guard TestClientScopedRevokeIsIndexed (revoke_predicate_
// test.go) enumerates its tables by hand and claims to list "every table a
// client_id-only predicate deletes from". A guard that shares the assumption of
// the fix it was shipped with cannot catch the fix's omission — this probe
// fails while the guard's list and the adapter's statements disagree.
func TestTheClientScopedRevokeGuardCoversTheDerivedTableSet(t *testing.T) {
	derived := clientScopedRevokeTables(t)

	guard := readShipped(t, adapterDir+"/revoke_predicate_test.go")
	list := regexp.MustCompile(`(?s)func TestClientScopedRevokeIsIndexed.*?for _, table := range \[\]string\{(.*?)\}`)
	m := list.FindStringSubmatch(guard)
	if m == nil {
		t.Fatal("the guard's table list was not found; the probe is not reading revoke_predicate_test.go")
	}
	guarded := make(map[string]bool)
	for _, table := range strings.Split(m[1], ",") {
		table = strings.Trim(strings.TrimSpace(table), `"`)
		if table != "" {
			guarded[table] = true
		}
	}
	if len(guarded) < 6 {
		t.Fatalf("parsed only %d guarded tables; the extraction is broken", len(guarded))
	}

	var unguarded []string
	for table := range derived {
		if !guarded[table] {
			unguarded = append(unguarded, table)
		}
	}
	sort.Strings(unguarded)
	for _, table := range unguarded {
		t.Errorf("the guard's hand-written table list omits %s, which the adapter deletes from with a "+
			"client_id-only filter: a future index on it would not be checked, and its absence today is "+
			"invisible to the guard — derive the list from the revokeMatching call sites instead", table)
	}
}
