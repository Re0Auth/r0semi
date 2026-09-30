package postgres

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// tokensFuncBody returns one *Tokens method's own body, from its func line
// through its closing brace, matched by brace depth rather than by the next
// top-level declaration. tokensMethod (the sibling guard's helper) runs to the
// next func, which pulls in that func's doc comment; here the question is whether
// the method itself issues a DELETE, so a following comment must not answer it.
func tokensFuncBody(t *testing.T, src, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func \(s \*Tokens\) ` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("method %s not found in the adapter source; the guard is reading the wrong file", name)
	}
	rest := src[loc[0]:]
	open := strings.Index(rest, "{")
	if open < 0 {
		t.Fatalf("method %s has no body in the adapter source", name)
	}
	depth := 0
	for i := open; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:i+1]
			}
		}
	}
	t.Fatalf("unbalanced braces reading method %s; the guard is reading the wrong source", name)
	return ""
}

// These are the database-free guards for Z14-1's read peer on the Postgres
// adapter. The behaviour needs Postgres (the environment has none), so the
// property that can be decided from the sources is pinned instead: GetRefresh is a
// SELECT over oauth_refresh_tokens that mirrors GetAccess, the destructive claim
// is still ConsumeRefresh's DELETE, and the public oauth.Store contract carries
// the method so a third-party implementation is compiled against it.
//
// They are siblings of oauth_refresh_family_guard_test.go and
// oauth_code_preflight_guard_test.go: together they pin that every read of a
// single-use credential is a read, and every claim is a claim.

// TestTokensGetRefreshIsANonDestructiveSelect pins the store half: a cascade
// request that resolves a subject and then fails upstream must be able to retry
// with the same value, so this read must never be a DELETE.
func TestTokensGetRefreshIsANonDestructiveSelect(t *testing.T) {
	body, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	get := tokensFuncBody(t, string(body), "GetRefresh")

	for _, want := range []string{
		"SELECT",
		"FROM oauth_refresh_tokens",
		"token_hash = $1",
		"oauth.ErrTokenNotFound",
	} {
		if !strings.Contains(get, want) {
			t.Errorf("GetRefresh no longer contains %q: the non-destructive refresh read is gone or reads the wrong table", want)
		}
	}
	if strings.Contains(get, "DELETE") {
		t.Error("GetRefresh issues a DELETE: the read spends the token, so a cascade whose upstream call fails can " +
			"never be retried with the same value (Z14-1)")
	}
	if strings.Contains(get, "tombstone") {
		t.Error("GetRefresh consults the tombstone table: the read is judging a replay, which is ConsumeRefresh's job")
	}

	// Control: the claim is still a DELETE, which is what makes rotation atomic
	// and leaves the reuse tombstone.
	consume := tokensFuncBody(t, string(body), "ConsumeRefresh")
	if !strings.Contains(consume, "DELETE") {
		t.Error("control broken: ConsumeRefresh is no longer a DELETE, so a refresh token is no longer claimed " +
			"atomically and a concurrent double rotation could both win")
	}
}

// TestOAuthStoreContractCarriesGetRefresh pins the interface half: GetRefresh is
// on the public contract and documented as the read peer of ConsumeRefresh, and
// the BREAKING CHANGE note names it, so an implementation in another module is
// told the interface grew rather than failing only at the composition root.
func TestOAuthStoreContractCarriesGetRefresh(t *testing.T) {
	body, err := os.ReadFile("../../../oauth/tokens.go")
	if err != nil {
		t.Fatalf("cannot read the oauth.Store contract: %v", err)
	}
	src := string(body)

	if !strings.Contains(src, "GetRefresh(ctx context.Context, value string) (RefreshToken, error)") {
		t.Error("oauth.Store no longer declares GetRefresh: the non-destructive refresh read is gone from the public contract")
	}
	if !strings.Contains(src, "read peer of ConsumeRefresh") {
		t.Error("GetRefresh's documentation no longer states it is the read peer of ConsumeRefresh: the destructive " +
			"claim and the read must not be confused")
	}
	if !strings.Contains(src, "BREAKING CHANGE for Store implementers") || !strings.Contains(src, "RevokeRefreshFamily, GetCode, GetRefresh") {
		t.Error("the BREAKING CHANGE note for Store implementers no longer names GetRefresh: a third-party " +
			"implementation would not be told the interface grew a method")
	}
}
