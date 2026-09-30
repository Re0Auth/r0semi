package postgres

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// These are the database-free guards for the KIT-4 fix: the exchange reads a
// code's bindings before it claims the code, so a failed binding no longer spends
// it. The behaviour itself needs Postgres (the environment has none — the same
// reason oauth_refresh_family_guard_test.go reads the shipped SQL), so the
// properties that can be decided from the sources are pinned instead: GetCode is
// a read on the public contract and in this adapter, and Exchange calls it before
// it consumes.
//
// They are sibling guards to oauth_refresh_family_guard_test.go and are the
// database-free half of the oauth package's behavioural tests: a revert that
// folded the read back into the consume, or that put the consume first again,
// would restore the denial of service KIT-4 removes and must fail here.

// goFuncBody returns one top-level function's source text, from its func line to
// the next top-level declaration. It is the same reading shape tokensMethod and
// migration_lock_guard_test.go use, for sources whose receiver is not *Tokens
// (here, oauth's *service).
func goFuncBody(t *testing.T, src, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("func %s not found in the source; the guard is reading the wrong file", name)
	}
	rest := src[loc[0]:]
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:]); next != nil {
		rest = rest[:next[0]+1]
	}
	return rest
}

// TestTokensGetCodeIsANonDestructiveSelect pins the store half: the exchange's
// pre-flight read must be a SELECT, not a DELETE, or a failed binding spends the
// code again.
func TestTokensGetCodeIsANonDestructiveSelect(t *testing.T) {
	body, err := os.ReadFile("oauth.go")
	if err != nil {
		t.Fatalf("cannot read the adapter source: %v", err)
	}
	get := tokensMethod(t, string(body), "GetCode")

	for _, want := range []string{
		"SELECT",
		"FROM oauth_codes",
		"token_hash = $1",
		"oauth.ErrTokenNotFound",
	} {
		if !strings.Contains(get, want) {
			t.Errorf("GetCode no longer contains %q: the exchange's pre-flight read is gone or reads the wrong table", want)
		}
	}
	if strings.Contains(get, "DELETE") {
		t.Error("GetCode issues a DELETE: the pre-flight read spends the code, so a request that merely knows a code " +
			"denies its owner their tokens again (KIT-4)")
	}

	// Control: the claim is still a DELETE, which is what makes single use atomic.
	consume := tokensMethod(t, string(body), "ConsumeCode")
	if !strings.Contains(consume, "DELETE") {
		t.Error("control broken: ConsumeCode is no longer a DELETE, so a code is no longer claimed atomically and a " +
			"concurrent double exchange could both win")
	}
}

// TestOAuthStoreContractCarriesGetCode pins the interface half: GetCode is on the
// public contract, documented, so an implementation in another module is
// compiled against the read the exchange now performs rather than silently
// missing it (and failing only at the composition root).
func TestOAuthStoreContractCarriesGetCode(t *testing.T) {
	body, err := os.ReadFile("../../../oauth/tokens.go")
	if err != nil {
		t.Fatalf("cannot read the oauth.Store contract: %v", err)
	}
	src := string(body)

	if !strings.Contains(src, "GetCode(ctx context.Context, value string) (AuthorizationCode, error)") {
		t.Error("oauth.Store no longer declares GetCode: the exchange's pre-flight read is gone from the public contract")
	}
	if !strings.Contains(src, "WITHOUT consuming it") {
		t.Error("GetCode's documentation no longer states the code is returned WITHOUT consuming it: the method's whole " +
			"purpose is that a failed binding must not spend the code")
	}
	if !strings.Contains(src, "BREAKING CHANGE for Store implementers") || !strings.Contains(src, "gained\n// RevokeRefreshFamily, GetCode") {
		t.Error("the BREAKING CHANGE note for Store implementers no longer names GetCode: a third-party implementation " +
			"would not be told the interface grew a method")
	}
}

// TestExchangeReadsBeforeItClaims pins the order in the service source: GetCode
// must appear in Exchange before ConsumeCode, and the binding helper must be
// applied to both reads, with the failure recorded. A revert that consumed first
// is exactly KIT-4.
func TestExchangeReadsBeforeItClaims(t *testing.T) {
	body, err := os.ReadFile("../../../oauth/as.go")
	if err != nil {
		t.Fatalf("cannot read the service source: %v", err)
	}
	exchange := goFuncBody(t, string(body), "Exchange")

	read := strings.Index(exchange, "s.tokens.GetCode(")
	claim := strings.Index(exchange, "s.tokens.ConsumeCode(")
	if read < 0 {
		t.Fatal("Exchange no longer calls GetCode: the client/redirect/PKCE bindings are judged after the code is spent")
	}
	if claim < 0 {
		t.Fatal("Exchange no longer calls ConsumeCode: single use lost its atomic gate")
	}
	if read > claim {
		t.Error("Exchange calls ConsumeCode before GetCode: a failed binding spends the code again, so knowing a code " +
			"is enough to deny it to its owner (KIT-4)")
	}
	if got := strings.Count(exchange, "checkCodeBinding"); got < 2 {
		t.Errorf("Exchange applies checkCodeBinding %d times, want 2 (the pre-flight read and the claimed record): only "+
			"the record that won the atomic claim may mint", got)
	}
	if !strings.Contains(exchange, "oauth.exchange_failed") {
		t.Error("Exchange no longer records oauth.exchange_failed on a binding failure: the denial of service is silent " +
			"again, with nothing for an operator to see")
	}
	if !strings.Contains(exchange, "audit.OutcomeDenied") {
		t.Error("Exchange no longer records the binding failure as an OutcomeDenied audit event")
	}
}
