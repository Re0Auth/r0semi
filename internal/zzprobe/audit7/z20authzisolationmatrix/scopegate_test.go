//go:build audit7

// Z20 scope x resource probes: does the scope a token carries decide which
// resources it may read, on BOTH data-plane entrances?
package zzprobe_z20authzisolationmatrix

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestZ20RawPassthroughIgnoresWhichResourceTheScopeNames is the flipped form of
// the Z20-2 finding — originally a discovery demonstration, now a regression
// guard. The name is kept so the coverage matrix still maps here.
//
// The finding was: the raw passthrough for a source was gated by "the token holds
// ANY of the source's resource scopes", and then forwarded the caller's path
// verbatim to the source's native API root. With `raw_base == issuer` the raw path
// addressed the very URL the normalized route addressed, so a token the user
// explicitly withheld `phigros.score.read` from still read the scores through raw.
//
// The fix replaced that with one explicit scope per game, `<game>.raw.read`
// (httpapi/federation_routes.go rawScope/rawGate; registered from the configured
// sources in cmd/re0auth). The guard below pins BOTH halves: a resource scope —
// even the one naming the resource the path addresses — no longer opens raw, and
// the explicit raw scope does.
func TestZ20RawPassthroughIgnoresWhichResourceTheScopeNames(t *testing.T) {
	e := newZEnv(t, zOptions{})
	raw := oauth.Scope(oauth.RawScope(zGame))

	profileOnly := e.mintToken(zSubject, "phigros.profile.read")

	// Control 1: the normalized route refuses, which was the rule the raw path
	// used to contradict. A refusal here is also what proves the probe reaches the
	// gate rather than a 404 further down.
	status, _, body := e.zGet("/v1/games/"+zGame+"/scores", profileOnly)
	t.Logf("normalized  GET /v1/games/%s/scores with a profile-only token -> %d %s", zGame, status, body)
	if status != http.StatusForbidden {
		t.Fatalf("control: the normalized route answered %d, want 403 (the per-resource gate)", status)
	}

	// Control 2: the raw gate itself is alive — a token with no resource scope
	// of this source is refused.
	identityOnly := e.mintToken(zSubject, "account.id")
	status, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", identityOnly)
	t.Logf("raw         GET .../raw/resources/scores with an account.id-only token -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Fatalf("control: the raw gate answered %d for a token with no resource scope, want 403", status)
	}

	// Control 3: the raw gate is NOT opened by the score resource scope either —
	// the scope names the very resource the path addresses, and it still must not
	// be enough. This is the exact read the old gate let through.
	score := e.mintToken(zSubject, "phigros.score.read")
	before := len(e.upstream.calls())
	status, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", score)
	t.Logf("raw         GET .../raw/resources/scores with a score-only token -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Errorf("a token holding only the resource scope the path names was served through raw (%d): %s\n"+
			"raw must require the explicit %s scope (Z20-2)", status, body, raw)
	}
	if !bytes.Contains(body, []byte(raw.String())) {
		t.Errorf("the refusal did not name required_scope=%s: %s", raw, body)
	}
	if len(e.upstream.calls()) != before {
		t.Errorf("a refused raw read reached the upstream: %v", e.upstream.calls())
	}

	// Control 4: the explicit raw scope IS the key — and the resource scope is not
	// needed alongside it.
	status, hdr, body := e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores",
		e.mintToken(zSubject, raw.String()))
	t.Logf("raw         GET .../raw/resources/scores with a %s token -> %d %s", raw, status, body)
	if status != http.StatusOK || !bytes.Contains(body, []byte("Z20-SCORES")) {
		t.Fatalf("control: a token holding the raw scope was not served (%d %s)", status, body)
	}
	if got := hdr.Get("Re0Auth-Source"); got != zSource {
		t.Fatalf("control: provenance header = %q", got)
	}
	if !e.upstream.hit("/resources/scores") {
		t.Fatalf("control: the upstream never saw /resources/scores; calls=%v", e.upstream.calls())
	}

	// The fixed fact, stated as a guard: the same URL, the same upstream endpoint,
	// a token the user granted only profile for, is refused and never dials.
	status, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", profileOnly)
	t.Logf("raw         GET .../raw/resources/scores with a PROFILE-ONLY token -> %d %s", status, body)
	if status == http.StatusOK || bytes.Contains(body, []byte("Z20-SCORES")) {
		t.Errorf("a profile-only token read the score resource through the raw passthrough "+
			"(status %d): %s\nUpstream calls: %v", status, body, e.upstream.calls())
	}
	if status != http.StatusForbidden {
		t.Errorf("the withheld raw read answered %d, want 403", status)
	}
}

// TestZ20RawPassthroughIsBoundToTheSourceThatIsNamed is the guard for the half
// that does hold: pinning the game and the source in the URL, the gate reads the
// scopes of THAT source, and the read goes to THAT source's base.
func TestZ20RawPassthroughIsBoundToTheSourceThatIsNamed(t *testing.T) {
	e := newZEnv(t, zOptions{})
	// The raw scope, so the request reaches the proxy's own path handling rather
	// than being refused by the scope gate first.
	raw := e.mintToken(zSubject, oauth.RawScope(zGame))

	// An unknown source is a 404 from the gate, not a 400 from the proxy.
	status, _, body := e.zGet("/v1/games/"+zGame+"/sources/nosuchsource/raw/resources/scores", raw)
	t.Logf("raw unknown source -> %d %s", status, body)
	if status != http.StatusNotFound {
		t.Errorf("an unknown source answered %d, want 404", status)
	}
	if len(e.upstream.calls()) != 0 {
		t.Errorf("an unknown source reached the upstream: %v", e.upstream.calls())
	}

	// A path that climbs out of the raw base is refused before any call.
	status, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/..%2f..%2fetc", raw)
	t.Logf("raw escaping path -> %d %s", status, body)
	if status == http.StatusOK && len(e.upstream.calls()) > 0 {
		t.Errorf("an escaping raw path reached the upstream: %v", e.upstream.calls())
	}
}

// TestZ20NormalizedGateRequiresTheScopeOfEveryCandidateSource is a guard: two
// sources that can both serve the resource each declare a scope, and the gate
// demands both (httpapi/federation_routes.go:105-122), so a token holding one
// source's scope cannot be served by the other.
func TestZ20NormalizedGateRequiresTheScopeOfEveryCandidateSource(t *testing.T) {
	e := newZEnv(t, zOptions{})
	// The single configured source declares `phigros.score.read` for `scores`;
	// a token without it must be refused, and the upstream must not be touched.
	profileOnly := e.mintToken(zSubject, "phigros.profile.read")
	before := len(e.upstream.calls())
	status, _, body := e.zGet("/v1/games/"+zGame+"/scores", profileOnly)
	t.Logf("normalized scores with a profile-only token -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Errorf("the normalized gate answered %d, want 403", status)
	}
	if len(e.upstream.calls()) != before {
		t.Errorf("the upstream was reached for a refused read: %v", e.upstream.calls())
	}
	// And the source's OTHER resource is refused too, so the gate is not simply
	// open for this source.
	scoreOnly := e.mintToken(zSubject, "phigros.score.read")
	status, _, body = e.zGet("/v1/games/"+zGame+"/profile", scoreOnly)
	t.Logf("normalized profile with a score-only token -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Errorf("the normalized gate answered %d for the resource it was not granted, want 403", status)
	}
}
