//go:build audit7

package z21verify

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This file guards the shape that made the reviewed coverage claim fail.
//
// The bulk-revocation statements do not exist as text anywhere: oauth.go and
// oidc.go execute
//
//	`DELETE FROM ` + table + clause
//
// with `table` a []string argument and `clause` assembled by revokePredicate via
// `fmt.Sprintf("client_id = $%d", …)`. A guard that walks Go string literals can
// therefore never see `DELETE FROM oidc_devices WHERE client_id = $1` — the one
// statement 04-3 is about.
//
// The shipped guard (internal/store/postgres/revoke_predicate_test.go) was
// rewritten to derive its table set from the revokeMatching call sites, which is
// the shape the test below now pins: if it ever goes back to literal matching it
// becomes blind to this statement again.

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

// TestTheClientOnlyRevokeStatementsAreInvisibleToALiteralWalkingGuard is the
// guard for the guard: because the client-only bulk revocation is assembled at
// run time, only a derivation guard can see it. This pins that the shipped guard
// derives its table set from the revokeMatching call sites instead of walking
// literal SQL, which is what made it blind to the 04-3 statement before.
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

	// Positive control: the plain per-table revokes still exist as literals, so the
	// blob reader below is looking at real SQL rather than at nothing.
	blob := allLiteralText(t)
	if !strings.Contains(blob, "DELETE FROM oidc_devices") {
		t.Fatalf("control failed: no literal `DELETE FROM oidc_devices` was collected")
	}

	// The shipped guard must not depend on those literals. Because the client-only
	// statement is assembled at run time (premises above), the only shape that can
	// see it derives the table set from the revokeMatching call sites — which is
	// what revoke_predicate_test.go does now. If it goes back to matching literal
	// SQL it becomes blind to exactly this statement again.
	guard := shippedSource(t, "revoke_predicate_test.go")
	for _, needle := range []string{"revokeMatching(", "clientScopedRevokeTables"} {
		if !strings.Contains(guard, needle) {
			t.Fatalf("the shipped revoke guard no longer derives its table set from revokeMatching call "+
				"sites (missing %q): a literal-walking guard cannot see the Sprintf'd client-only statement "+
				"for any of %v", needle, tables)
		}
	}
	t.Logf("the shipped guard derives from revokeMatching call sites and covers %v", tables)
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
