package httpapi

import (
	"os"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// R10-138/R10-141: the introspect benchmark must model the recommended
// deployment — a generated secret on the fast salted-HMAC verifier — and keep
// the slow PBKDF2 path as an explicit control. Without this guard the fixture
// can silently drift back to a weak secret, and the headline number goes back to
// measuring the path the fix removed.
func TestBenchIntrospectFixtureModelsAGeneratedSecret(t *testing.T) {
	if !oauth.LooksGeneratedSecret(benchGeneratedSecret) {
		t.Fatalf("the benchmark's secret %q is not a recognised generated shape, so the headline "+
			"introspect benchmark measures the slow PBKDF2 path again", benchGeneratedSecret)
	}
	raw, err := os.ReadFile("bench_test.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, want := range []string{
		"oauth.VerifierGenerated",
		"BenchmarkProtocolIntrospectPBKDF2",
		"newBenchEnvSecret",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("bench_test.go has no %q: the harness no longer distinguishes the generated "+
				"secret path from the PBKDF2 control", want)
		}
	}
}
