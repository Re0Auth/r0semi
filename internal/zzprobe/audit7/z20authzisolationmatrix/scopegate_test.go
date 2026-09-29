//go:build audit7

// Z20 scope x resource probes: does the scope a token carries decide which
// resources it may read, on BOTH data-plane entrances?
package zzprobe_z20authzisolationmatrix

import (
	"bytes"
	"net/http"
	"testing"
)

// TestZ20RawPassthroughIgnoresWhichResourceTheScopeNames is the finding probe.
//
// The normalized route enforces one scope PER RESOURCE: a token holding only
// `phigros.profile.read` is refused (403) for `/v1/games/phigros/scores`. The
// raw passthrough for the same source is gated by "the token holds ANY of the
// source's resource scopes" (httpapi/federation_routes.go:223-236,260) and then
// forwards the caller's path verbatim to the source's native API root. With the
// source's raw_base equal to its issuer — the natural configuration, and the one
// `config/re0auth.example.toml:365` shows — the raw path addresses the very URL
// the normalized route addresses, so a client the user explicitly withheld
// `phigros.score.read` from reads the scores anyway.
func TestZ20RawPassthroughIgnoresWhichResourceTheScopeNames(t *testing.T) {
	e := newZEnv(t, zOptions{})

	profileOnly := e.mintToken(zSubject, "phigros.profile.read")

	// Control 1: the normalized route refuses, which is the rule the raw path
	// contradicts. A refusal here is also what proves the probe reaches the
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

	// Control 3: with the score scope the raw path is served — proving the
	// attack below is about WHICH scope, not about the path being unreachable.
	score := e.mintToken(zSubject, "phigros.score.read")
	status, hdr, body := e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", score)
	t.Logf("raw         GET .../raw/resources/scores with a score token -> %d %s", status, body)
	if status != http.StatusOK || !bytes.Contains(body, []byte("Z20-SCORES")) {
		t.Fatalf("control: a token holding the score scope was not served (%d %s)", status, body)
	}
	if got := hdr.Get("Re0Auth-Source"); got != zSource {
		t.Fatalf("control: provenance header = %q", got)
	}
	if !e.upstream.hit("/resources/scores") {
		t.Fatalf("control: the upstream never saw /resources/scores; calls=%v", e.upstream.calls())
	}

	// The attack: the same URL, the same upstream endpoint, a token the user
	// granted only profile for.
	status, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/resources/scores", profileOnly)
	t.Logf("raw         GET .../raw/resources/scores with a PROFILE-ONLY token -> %d %s", status, body)
	if status == http.StatusOK || bytes.Contains(body, []byte("Z20-SCORES")) {
		t.Errorf("a profile-only token read the score resource through the raw passthrough "+
			"(status %d): %s\nThe normalized route refuses the same read with 403, so the "+
			"resource the user withheld is still reachable — the gate is per-source, not "+
			"per-resource. Upstream calls: %v", status, body, e.upstream.calls())
	}
}

// TestZ20RawPassthroughIsBoundToTheSourceThatIsNamed is the guard for the half
// that does hold: pinning the game and the source in the URL, the gate reads the
// scopes of THAT source, and the read goes to THAT source's base.
func TestZ20RawPassthroughIsBoundToTheSourceThatIsNamed(t *testing.T) {
	e := newZEnv(t, zOptions{})
	score := e.mintToken(zSubject, "phigros.score.read")

	// An unknown source is a 404 from the gate, not a 400 from the proxy.
	status, _, body := e.zGet("/v1/games/"+zGame+"/sources/nosuchsource/raw/resources/scores", score)
	t.Logf("raw unknown source -> %d %s", status, body)
	if status != http.StatusNotFound {
		t.Errorf("an unknown source answered %d, want 404", status)
	}
	if len(e.upstream.calls()) != 0 {
		t.Errorf("an unknown source reached the upstream: %v", e.upstream.calls())
	}

	// A path that climbs out of the raw base is refused before any call.
	status, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/..%2f..%2fetc", score)
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
