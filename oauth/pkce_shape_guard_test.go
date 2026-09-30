package oauth

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// pkceFuncBody returns one top-level function's source text, from its func line to
// the next top-level declaration. The property here is "which helper is called",
// which no behavioural test can express, so the shipped source is read directly —
// the same shape internal/store/postgres's goFuncBody uses for oauth's *service.
func pkceFuncBody(t *testing.T, src, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("func %s not found in as.go; the guard is reading the wrong source", name)
	}
	rest := src[loc[0]:]
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:]); next != nil {
		rest = rest[:next[0]+1]
	}
	return rest
}

// TestPKCEChallengeShapeIsCheckedAtBothEntrances pins the shared predicate
// (KIT-5): the authorize-side describe and the exchange-side verifyPKCE must both
// call validPKCEChallenge, and it must be defined exactly once. Two copies of the
// shape rule, or one entrance skipping it, is precisely the drift that let
// authorize admit a challenge the exchange could never verify.
func TestPKCEChallengeShapeIsCheckedAtBothEntrances(t *testing.T) {
	body, err := os.ReadFile("as.go")
	if err != nil {
		t.Fatalf("cannot read the service source: %v", err)
	}
	src := string(body)

	if got := strings.Count(src, "func validPKCEChallenge("); got != 1 {
		t.Fatalf("validPKCEChallenge is defined %d times, want exactly 1: the shape rule must not be duplicated", got)
	}

	for _, fn := range []string{"describe", "verifyPKCE"} {
		fnBody := pkceFuncBody(t, src, fn)
		if !strings.Contains(fnBody, "validPKCEChallenge(") {
			t.Errorf("%s no longer calls validPKCEChallenge: one entrance is checking a different shape rule "+
				"(or none), so authorize and exchange can drift apart again", fn)
		}
	}

	// Controls: the shared predicate must be the real shape check, and the
	// exchange must still compare constant-time.
	predicate := pkceFuncBody(t, src, "validPKCEChallenge")
	for _, want := range []string{"len(challenge) != 43", "c >= 'A' && c <= 'Z'", "c == '_'"} {
		if !strings.Contains(predicate, want) {
			t.Errorf("validPKCEChallenge no longer contains %q: it is no longer the unpadded base64url "+
				"SHA-256 digest shape RFC 7636 §4.2 requires", want)
		}
	}
	if !strings.Contains(pkceFuncBody(t, src, "verifyPKCE"), "subtle.ConstantTimeCompare") {
		t.Error("verifyPKCE no longer compares constant-time")
	}
	if description := pkceFuncBody(t, src, "describe"); !strings.Contains(description, `"PKCE with S256 is required"`) {
		t.Error("describe no longer carries the invalid_request message clients have always seen")
	}
}
