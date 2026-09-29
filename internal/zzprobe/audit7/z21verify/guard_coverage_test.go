//go:build audit7

package z21verify

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This probe falsifies one documented claim in the reviewed evidence.
//
// The report's "探过但没破" #2 presents predicate_index_test.go::
// TestEveryGoMutationPredicateHasALeadingIndex as the de-hand-listed guard for
// mutation predicates, and that probe's own doc comment
// (predicate_index_test.go:128-129) claims it "would have caught the
// oidc_devices client_id gap (04-3) without anyone remembering to add the table
// to a list".
//
// It cannot. The bulk-revocation statements do not exist as text anywhere:
// oauth.go:288-298 and oidc.go:1064-1075 execute
//
//	`DELETE FROM ` + table + clause
//
// with `table` a []string argument and `clause` assembled by
// revokePredicate (oauth.go:313-327) via `fmt.Sprintf("client_id = $%d", …)`.
// A guard that walks Go string literals therefore never sees
// `DELETE FROM oidc_devices WHERE client_id = $1` — the one statement 04-3 is
// about. The guard passes oidc_devices only because the literals it *can* see
// (oidc.go:750's consume claim and oidc.go:1016) carry device_code_hash or
// subject predicates, i.e. the "PK 顺序论元" the report waves at.

var (
	reRevokeMatchingCall = regexp.MustCompile(`(?s)revokeMatching\([^,]+,[^,]+,\s*\[\]string\{([^}]*)\}`)
	reQuotedTable        = regexp.MustCompile(`"([a-z_]+)"`)
)

func shippedSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(repoRoot(t) + "/internal/store/postgres/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// runtimeRevokeTables returns the table names the shipped code passes to
// revokeMatching at runtime.
func runtimeRevokeTables(t *testing.T) []string {
	t.Helper()
	set := map[string]bool{}
	for _, name := range []string{"oauth.go", "oidc.go"} {
		for _, m := range reRevokeMatchingCall.FindAllStringSubmatch(shippedSource(t, name), -1) {
			for _, q := range reQuotedTable.FindAllStringSubmatch(m[1], -1) {
				set[q[1]] = true
			}
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) < 5 {
		t.Fatalf("found only %v passed to revokeMatching; the extractor is broken", out)
	}
	return out
}

// TestTheClientOnlyRevokeStatementsAreInvisibleToALiteralWalkingGuard is the red
// probe for the guard's coverage claim.
func TestTheClientOnlyRevokeStatementsAreInvisibleToALiteralWalkingGuard(t *testing.T) {
	tables := runtimeRevokeTables(t)
	t.Logf("revokeMatching is called with: %v", tables)

	// Premise 1: the statement is a runtime concatenation.
	oauthSrc := shippedSource(t, "oauth.go")
	if !strings.Contains(oauthSrc, "db.Exec(ctx, `DELETE FROM `+table+clause, args...)") {
		t.Fatalf("premise changed: revokeMatching no longer builds `DELETE FROM `+table+clause")
	}
	// Premise 2: the client-only predicate is built with Sprintf, not written out.
	if !strings.Contains(oauthSrc, `fmt.Sprintf("client_id = $%d", len(args))`) {
		t.Fatalf("premise changed: revokePredicate no longer builds the client predicate with Sprintf")
	}

	// The text the guard would have to see, for every table it claims to derive.
	blob := allLiteralText(t)
	var invisible []string
	for _, table := range tables {
		stmt := "DELETE FROM " + table + " WHERE client_id = $1"
		if !strings.Contains(blob, stmt) {
			invisible = append(invisible, table)
		}
	}
	// Positive control: the literal-visible statements that the reviewed guard
	// *does* attribute must be present, or this probe is looking at nothing.
	if !strings.Contains(blob, "DELETE FROM oidc_devices") {
		t.Fatalf("control failed: no literal `DELETE FROM oidc_devices` was collected")
	}
	if len(invisible) == 0 {
		t.Log("premise changed: every client-only revoke now exists as text")
		return
	}
	t.Errorf("GUARD COVERAGE GAP: the client-only bulk-revocation statement exists as text for none of "+
		"%v (missing for %v), because revokeMatching concatenates the table and revokePredicate Sprintf's "+
		"the predicate. A guard over Go string literals can therefore never attribute "+
		"`DELETE FROM oidc_devices WHERE client_id = $1` — the 04-3 statement — so "+
		"predicate_index_test.go:128-129's claim that it would have caught 04-3 by derivation is false, and "+
		"the report's 探过没破 #2 presents a guard that is blind exactly where the hand-written list was blind.",
		tables, invisible)
}

// allLiteralText returns the contents of every backtick-quoted string in the
// shipped store sources — the shape a literal-walking extractor sees.
func allLiteralText(t *testing.T) string {
	t.Helper()
	var src strings.Builder
	for _, path := range goSourceFiles(t) {
		src.WriteString(readPath(t, path))
		src.WriteByte('\n')
	}
	var out strings.Builder
	rest := src.String()
	for {
		i := strings.IndexByte(rest, '`')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
		j := strings.IndexByte(rest, '`')
		if j < 0 {
			break
		}
		out.WriteString(rest[:j])
		out.WriteByte('\n')
		rest = rest[j+1:]
	}
	if out.Len() < 2000 {
		t.Fatalf("collected only %d bytes of backtick literals; the extractor is broken", out.Len())
	}
	return out.String()
}
