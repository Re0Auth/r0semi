//go:build audit7

// Z11 guards for the rate limiter's bucket key — the questions the area brief
// asks about that this round did NOT break.
package zzprobe_z11resiliencedos

import (
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// limiterStatus drives one path spelling and reports the status. Anything that
// is not 429 was admitted, which is all these probes count.
func limiterStatus(t *testing.T, base, path string) int {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusTooManyRequests, http.StatusUnauthorized,
		http.StatusNotFound, http.StatusForbidden, http.StatusMethodNotAllowed:
		return resp.StatusCode
	default:
		t.Fatalf("GET %s = %d: unexpected status for this probe", path, resp.StatusCode)
		return 0
	}
}

// TestZ11PathSpellingCannotBuyAFourthBucket exercises the "跨平面归桶绕过"
// question.
//
// withRateLimit keys the bucket on `planeOf(path) + "|" + clientKey`
// (middleware.go:349). The plane has exactly three values, so one address holds
// at most three buckets — unless a spelling can make the router reach a handler
// while planeOf classifies the request differently, or make planeOf see
// something the router does not.
//
// The limiter here is cache-only (1e-6/s) with burst 3. The probe spends all
// three tokens of all three planes through canonical paths (the positive
// control), and then requires every spelling variant to be a 429: a variant that
// is admitted is a bucket the caller bought by respelling a URL.
func TestZ11PathSpellingCannotBuyAFourthBucket(t *testing.T) {
	const burst = 3
	srv := miniAPI(t, miniConfig{Limiter: ratelimit.New(1e-6, burst)})

	// Positive control: all three planes exist, are shaped, and each has exactly
	// `burst` tokens to spend.
	spent := 0
	for _, p := range []string{"/oauth/token", "/v1/me", "/nowhere"} {
		for i := 0; i < burst; i++ {
			if limiterStatus(t, srv.URL, p) == http.StatusTooManyRequests {
				t.Fatalf("%s was refused after %d of %d burst tokens: the limiter's arithmetic changed, so the "+
					"spelling cases below prove nothing", p, i, burst)
			}
			spent++
		}
	}
	t.Logf("positive control: %d requests admitted across 3 planes (burst %d each); every bucket is now empty",
		spent, burst)

	spellings := []string{
		// The canonical spellings again: the buckets must still be empty.
		"/oauth/token", "/v1/me", "/nowhere",
		// Same plane, different spelling of the same namespace.
		"/oauth//token",
		"/oauth/./token",
		"/oauth/%2e/token",
		"/oauth/token/",
		"/oauth/token?x=1",
		"/.well-known//openid-configuration",
		"/.well-known/./oauth-authorization-server",
		"/.well-known/openid-configuration",
		"/v1//me",
		"/v1/./me",
		"/v1/%6de",
		"/v1/me/",
		"/v1/me?x=1",
		// Cross-plane cleanings the canonical-path guard refuses.
		"/v1/../oauth/token",
		"/v1/%2e%2e/oauth/token",
		"/oauth/../v1/me",
		"/v1/%2Fme",
		"/oauth%2Ftoken",
		// Case and namespace near-misses, which the router and planeOf agree are
		// the browser plane.
		"/OAuth/token",
		"/V1/me",
		"/.WELL-KNOWN/openid-configuration",
		"/me",
		"/v1",
		"/oauth",
		"/.well-known",
		"/",
		"/v1/me/../../oauth/token",
	}
	extra := 0
	for _, p := range spellings {
		if limiterStatus(t, srv.URL, p) != http.StatusTooManyRequests {
			extra++
			t.Logf("spelling %q was admitted after all three plane buckets were spent", p)
		}
	}
	t.Logf("%d of %d spelling variants were admitted beyond the three exhausted plane buckets", extra, len(spellings))
	if extra != 0 {
		t.Errorf("%d path spellings bought a bucket beyond the three planes: planeOf and the router disagree "+
			"about which plane a request is on, which is a rate-limit bypass", extra)
	}
}

// TestZ11ProbesAreTheOnlyExemptPaths pins what the exemption is keyed on.
//
// isProbe is an exact match on "/healthz" and "/readyz" (health.go:164). A
// near-miss spelling must NOT inherit the exemption, because the exemption means
// "no limiter and no in-flight cap": if a caller could reach real work through
// it, that unlimited path would be the interesting one. The limiter here has
// burst 1, so the second request to any non-exempt path is a 429.
func TestZ11ProbesAreTheOnlyExemptPaths(t *testing.T) {
	srv := miniAPI(t, miniConfig{Limiter: ratelimit.New(1e-6, 1)})

	for _, p := range []string{"/healthz", "/readyz", "/healthz?x=1", "/readyz?x=1"} {
		for i := 0; i < 4; i++ {
			if got := limiterStatus(t, srv.URL, p); got == http.StatusTooManyRequests {
				t.Errorf("%s was rate limited on request %d: the probe exemption is not in force", p, i+1)
			}
		}
	}
	for _, p := range []string{"/healthz/", "/readyz/", "/healthz/x", "/readyz%2F", "/Healthz", "/readyz%20"} {
		// A fresh server per spelling: every near-miss path here is the browser
		// plane, so they all share ONE bucket, and a burst of 1 would be spent by
		// the first spelling — which is a property of the probe, not of the
		// exemption.
		fresh := miniAPI(t, miniConfig{Limiter: ratelimit.New(1e-6, 1)})
		first := limiterStatus(t, fresh.URL, p)
		second := limiterStatus(t, fresh.URL, p)
		t.Logf("%s: first=%d second=%d", p, first, second)
		if first == http.StatusTooManyRequests {
			t.Fatalf("%s was refused on its first request: this probe's premise is wrong", p)
		}
		if second != http.StatusTooManyRequests {
			t.Errorf("%s was admitted twice with a burst of 1: a near-miss spelling inherited the probe "+
				"exemption (or the limiter is not shaping it)", p)
		}
	}
}
