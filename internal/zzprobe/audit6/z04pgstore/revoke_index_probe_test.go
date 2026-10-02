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
// G-14 was fixed by migration 0029; the derivation then immediately found an
// EIGHTH table, oidc_refresh_token_tombstones, which migration 0031 indexed and
// which the in-package guard now derives rather than lists (so it cannot miss a
// ninth). Both tests below are guards for those fixes, not findings.

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
// index whose leading column is client_id. Migration 0029 fixed that. The
// derivation then found an eighth, oidc_refresh_token_tombstones, and migration
// 0031 indexed it; the set is now fully covered, so this test is the guard for
// both fixes. Every one of these deletes runs inside the one-transaction
// revocation an operator fires during an incident, under the pool's statement
// timeout.
func TestEveryClientScopedRevokeTableHasALeadingClientIndex(t *testing.T) {
	leading := leadingIndexCols(t)
	tables := clientScopedRevokeTables(t)

	// Anti-vacuous in both directions: the schema parser must see the
	// indexes 0021/0022/0025/0029/0031 actually created (these must pass), and
	// must not believe every column is indexed.
	//
	// G-14 used to be asserted on the other side: oidc_devices had no leading
	// client_id index and this probe failed with a message saying so. Migration
	// 0029 added it; migration 0031 did the same for
	// oidc_refresh_token_tombstones, so the checks below are guards for those
	// fixes rather than findings.
	for _, ok := range []struct{ table, col string }{
		{"oidc_access_tokens", "client_id"},
		{"oidc_refresh_tokens", "client_id"},
		{"oidc_auth_requests", "client_id"},
		{"oauth_codes", "client_id"},
		{"oidc_devices", "client_id"},
		{"oidc_refresh_token_tombstones", "client_id"},
	} {
		if !leading[ok.table][ok.col] {
			t.Fatalf("the parser does not see %s.%s's index; it is not reading migration 0021/0022/0025/0029/0031 "+
				"and every assertion below is vacuous", ok.table, ok.col)
		}
	}
	// The derivation must still see the table this round fixed: if the regex
	// silently stopped matching its revokeMatching call site, the coverage check
	// below would pass for it without checking anything.
	if _, ok := tables["oidc_refresh_token_tombstones"]; !ok {
		t.Fatalf("the derivation no longer sees oidc_refresh_token_tombstones (%v); the guard would be "+
			"vacuous for the table migration 0031 added the index for", tables)
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
			"(migration 0022 / 0029 / 0031 covered the derived set; this is a table the derivation sees "+
			"and the migrations do not)", m)
	}
}

// TestTheClientScopedRevokeGuardCoversTheDerivedTableSet is the guard-quality
// half. The in-package guard TestClientScopedRevokeIsIndexed
// (revoke_predicate_test.go) used to enumerate its tables by hand and claim to
// list "every table a client_id-only predicate deletes from" — the exact shape
// that let oidc_devices and then oidc_refresh_token_tombstones escape it. This
// probe now requires that the guard DERIVES the set from the adapter's
// revokeMatching call sites (the same derivation this probe uses), so the two
// cannot disagree about a table a future delete site adds. The old hand list is
// a failure: a hand list is the bug, not the fix.
func TestTheClientScopedRevokeGuardCoversTheDerivedTableSet(t *testing.T) {
	// Anti-vacuous: the derived set this name is about must exist.
	if derived := clientScopedRevokeTables(t); len(derived) < 5 {
		t.Fatalf("derived only %d client-scoped revoke tables; the guard-quality check is vacuous", len(derived))
	}

	guard := readShipped(t, adapterDir+"/revoke_predicate_test.go")
	code := stripGoComments(guard)

	// The guard must read the adapter's call sites.
	if !strings.Contains(code, "revokeMatching") {
		t.Error("TestClientScopedRevokeIsIndexed no longer derives its table set from the adapter's " +
			"revokeMatching call sites: without that read a new client-scoped delete table is invisible to " +
			"the guard, which is how oidc_devices (G-14) and oidc_refresh_token_tombstones were missed")
	}
	if !strings.Contains(code, "clientScopedRevokeTables") {
		t.Error("the guard no longer calls the derivation helper; re-derive the table set instead of " +
			"enumerating it by hand")
	}
	// The old failure mode must not come back: a `for _, table := range []string{…}`
	// table list in the guard is a hand enumeration.
	if m := regexp.MustCompile(`for _, table := range \[\]string\{`).FindString(code); m != "" {
		t.Error("the guard enumerates its tables by hand again (" + m + "); derive the set from the " +
			"revokeMatching call sites so the next delete site fails the guard instead of silently scanning")
	}
	// The guard's own anti-vacuous check must survive: a derivation that found
	// nothing would make every assertion below it pass.
	if !strings.Contains(code, "derived only") {
		t.Error("the guard has no anti-vacuous check on the derived set: an empty derivation would pass " +
			"every index assertion vacuously")
	}
}
