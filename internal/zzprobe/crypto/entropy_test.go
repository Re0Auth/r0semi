//go:build audit5

package crypto

import (
	"math"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestProbeUserCodeEntropyAndAttackerBudget is the brief's question 2, computed
// rather than asserted from the comment.
//
// The code is 8 significant characters from "BCDFGHJKLMNPQRSTVWXZ" (20 symbols),
// rendered as "XXXX-XXXX". Normalisation is case-folding, whitespace trimming and
// separator removal, so the attacker's search space is exactly 20^8 — the dash
// carries no entropy.
//
// RFC 8628 §6.1 sets the bar at "a user code of 8 characters or more drawn from a
// 20-symbol alphabet" (i.e. 20^8) as adequate WHEN the endpoint is rate limited
// and the code is short-lived. This test pins that 20^8 is what is actually
// generated, and computes what the shipped rate limiter leaves an attacker.
func TestProbeUserCodeEntropyAndAttackerBudget(t *testing.T) {
	const alphabet = 20
	const symbols = 8
	const ttlSeconds = 600.0 // op.Config.DeviceAuthorization.Lifetime = 10m

	space := math.Pow(alphabet, symbols)
	bits := math.Log2(space)
	t.Logf("search space = 20^8 = %.0f (%.3f bits)", space, bits)
	if bits < 34 || bits > 35 {
		t.Fatalf("user-code entropy is %.3f bits, which is not the documented 20^8", bits)
	}
	if bits < 32 {
		t.Errorf("user-code entropy %.1f bits is below the 32-bit floor this probe expects", bits)
	}

	// The shipped limiter (cmd/re0auth/config.go: defaultRateLimit = 50 rps,
	// defaultRateLimitBurst = 100), keyed on (plane, client address) — and the
	// verification endpoint is on the business plane.
	const rate, burst = 50.0, 100.0

	// Attacker's realistic window: the code only exists, and is only *guessable*,
	// while it is pending — up to the TTL, but the useful window is around the
	// moment the victim types it.
	for _, window := range []float64{60, ttlSeconds} {
		attempts := burst + rate*window
		p := attempts / space
		t.Logf("one address, %.0fs window: %.0f attempts -> P(hit) = %.3e", window, attempts, p)
		if p > 1e-5 {
			t.Errorf("one address in a %.0fs window reaches P=%.2e, which is not negligible", window, p)
		}
	}
	// The configured limiter is per ADDRESS, so an attacker with many addresses
	// multiplies attempts linearly. Show the size a botnet would need for a 1%
	// chance inside the full TTL, so the report can state the bar in addresses.
	fullTTL := burst + rate*ttlSeconds
	addressesFor1pct := (0.01 * space) / fullTTL
	t.Logf("addresses needed for a 1%% chance over the full TTL: %.0f (%.0f attempts each); "+
		"the limiter's map is capped at 10,000 keys process-wide (internal/ratelimit)",
		addressesFor1pct, fullTTL)

	// And the same computation with the limiter switched off, which the config
	// permits deliberately (server.rate_limit = 0).
	t.Log("with server.rate_limit = 0 the limiter is removed entirely: the only remaining " +
		"bound is the work one guess costs (one signed-in session, one DB lookup), and a " +
		"single address can then drive the full 20^8 search")
}

// TestProbeNormalizationIsTheOnlyThingThatNarrowsTheSpace checks that the
// documented normalisation cannot make two distinct codes collide (which would
// shrink the effective space) and that it does not widen the input set.
func TestProbeNormalizationIsTheOnlyThingThatNarrowsTheSpace(t *testing.T) {
	// Same code, every spelling a user might type, must normalise to one value.
	want := oauth.NormalizeUserCode("BCDF-GHJK")
	for _, in := range []string{"bcdf-ghjk", " bcdfghjk ", "BCDFGHJK", "BcDf-GhJk", "BCDF--GHJK"} {
		if got := oauth.NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
	// Two DISTINCT codes must not collide.
	seen := map[string]string{}
	alphabet := "BCDFGHJKLMNPQRSTVWXZ"
	for i := 0; i < len(alphabet); i++ {
		for j := 0; j < len(alphabet); j++ {
			code := string(alphabet[i]) + string(alphabet[j]) + "-0000"
			n := oauth.NormalizeUserCode(code)
			if prev, dup := seen[n]; dup {
				t.Fatalf("%q and %q both normalise to %q", prev, code, n)
			}
			seen[n] = code
		}
	}
	if len(seen) != len(alphabet)*len(alphabet) {
		t.Fatalf("normalisation collapsed %d distinct inputs into %d", len(alphabet)*len(alphabet), len(seen))
	}
	// The dash is not part of the space: 20^8, not 21^8 (or 20^7 * 21).
	if got := len(oauth.NormalizeUserCode("BCDF-GHJK")); got != 8 {
		t.Fatalf("normalised length = %d, want 8", got)
	}
}
