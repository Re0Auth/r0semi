//go:build audit7

// Z20 scope x resource probes: does the scope a token carries decide which
// resources it may read, on BOTH data-plane entrances?
package zzprobe_z20authzisolationmatrix

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
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

	// A path that climbs out of the raw base is refused, with the explicit 400 the
	// data plane's ErrRawPathEscapes maps to, and before any upstream call. The old
	// assertion (`status == 200 && calls > 0`) was single-sided: a 500, a 502 or a
	// hang passed it, so "the escape was refused" was never actually pinned.
	beforeEscape := len(e.upstream.calls())
	status, _, body = e.zGet("/v1/games/"+zGame+"/sources/"+zSource+"/raw/..%2f..%2fetc", raw)
	t.Logf("raw escaping path -> %d %s", status, body)
	if status != http.StatusBadRequest {
		t.Errorf("an escaping raw path answered %d, want 400 (federation.ErrRawPathEscapes): %s\n"+
			"upstream calls: %v", status, body, e.upstream.calls())
	}
	if len(e.upstream.calls()) != beforeEscape {
		t.Errorf("an escaping raw path reached the upstream (want zero new calls): %v", e.upstream.calls())
	}
}

// TestZ20NormalizedGateRequiresTheScopeOfEveryCandidateSource is a guard: two
// sources can both serve `scores`, each declaring its OWN scope, and the
// normalized gate demands both (httpapi/federation_routes.go:105-122). A token
// holding one source's scope cannot be served by the other — the exact mix-up the
// old "first source that declares the resource, in config order" rule made.
//
// With a single configured source this property cannot be tested at all: "the
// scope of every candidate" and "the scope of the only source" are the same
// statement, so the guard would pass even if the gate had reverted to reading a
// single source. The second source, with its own scope, is what makes it
// falsifiable.
func TestZ20NormalizedGateRequiresTheScopeOfEveryCandidateSource(t *testing.T) {
	// The second candidate serves the same resource under a different scope. It is
	// deliberately unbound for this user: the gate must refuse before any fetch, so
	// a refusal cannot be confused with "not bound", and the positive control below
	// is served by the first (bound) source, which candidates() tries first.
	second := federation.Source{
		Game: zGame, Name: "fake2", DisplayName: "Fake 2",
		Issuer: "https://fake2.example", ClientID: "cid", ClientSecret: "sec",
		TokenClass: "revocable",
		Resources: []federation.Resource{{
			Name: "scores", Schema: "re0auth.phigros.scores.alt/1", Scope: zSecondScoreScope.String(),
		}},
	}
	registry := zRegistryWithRaw(t)
	if err := registry.Register(oauth.Descriptor{
		Scope: zSecondScoreScope, Title: "读取 Phigros 成绩（第二数据源）", Risk: oauth.RiskMedium,
	}); err != nil {
		t.Fatalf("register %s: %v", zSecondScoreScope, err)
	}
	e := newZEnv(t, zOptions{
		Registry:     registry,
		ClientScopes: []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosProfile, oauth.ScopePhigrosScore, oauth.Scope(oauth.RawScope(zGame)), zSecondScoreScope},
		SecondSource: &second,
	})

	// Control 0: the deployment really has two candidates for `scores`, so the two
	// refusals below are about the "every" rule rather than about a missing source.
	status, _, body := e.zGet("/v1/games/"+zGame+"/sources", "")
	t.Logf("game sources -> %d %s", status, body)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"fake2"`)) || !bytes.Contains(body, []byte(`"fake"`)) {
		t.Fatalf("control: the deployment does not list both candidate sources: %d %s", status, body)
	}

	// Source 1's scope alone is refused, and the refusal names source 2's scope —
	// the requirement the old first-match rule never produced.
	firstOnly := e.mintToken(zSubject, oauth.ScopePhigrosScore.String())
	before := len(e.upstream.calls())
	status, _, body = e.zGet("/v1/games/"+zGame+"/scores", firstOnly)
	t.Logf("normalized scores with source 1's scope only -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Errorf("a token holding source 1's scope but not source 2's was served (%d): %s", status, body)
	}
	if len(e.upstream.calls()) != before {
		t.Errorf("the upstream was reached for a refused read: %v", e.upstream.calls())
	}
	if !bytes.Contains(body, []byte(zSecondScoreScope.String())) {
		t.Errorf("the refusal does not name the second source's required scope %s: %s", zSecondScoreScope, body)
	}

	// Source 2's scope alone is refused too, and the refusal names source 1's scope.
	secondOnly := e.mintToken(zSubject, zSecondScoreScope.String())
	before = len(e.upstream.calls())
	status, _, body = e.zGet("/v1/games/"+zGame+"/scores", secondOnly)
	t.Logf("normalized scores with source 2's scope only -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Errorf("a token holding source 2's scope but not source 1's was served (%d): %s", status, body)
	}
	if len(e.upstream.calls()) != before {
		t.Errorf("the upstream was reached for a refused read: %v", e.upstream.calls())
	}
	if !bytes.Contains(body, []byte(oauth.ScopePhigrosScore.String())) {
		t.Errorf("the refusal does not name the first source's required scope %s: %s", oauth.ScopePhigrosScore, body)
	}

	// Positive control: both scopes together open the gate and the read is served
	// by the bound source. Without this, the two refusals above could be explained
	// by the route being closed for every token.
	both := e.mintToken(zSubject, oauth.ScopePhigrosScore.String(), zSecondScoreScope.String())
	status, hdr, body := e.zGet("/v1/games/"+zGame+"/scores", both)
	t.Logf("normalized scores with both scopes -> %d %s", status, body)
	if status != http.StatusOK || !bytes.Contains(body, []byte("Z20-SCORES")) {
		t.Fatalf("control: holding every candidate source's scope was still not served (%d %s)", status, body)
	}
	if got := hdr.Get("Re0Auth-Source"); got != zSource {
		t.Fatalf("control: the read was served by %q, want the bound source %q", got, zSource)
	}
	if !e.upstream.hit("/resources/scores") {
		t.Fatalf("control: the upstream never saw /resources/scores; calls=%v", e.upstream.calls())
	}

	// And a token with neither resource scope is still refused, so the gate is not
	// simply open once two sources exist.
	profileOnly := e.mintToken(zSubject, "phigros.profile.read")
	before = len(e.upstream.calls())
	status, _, body = e.zGet("/v1/games/"+zGame+"/scores", profileOnly)
	t.Logf("normalized scores with a profile-only token -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Errorf("the normalized gate answered %d for a profile-only token, want 403", status)
	}
	if len(e.upstream.calls()) != before {
		t.Errorf("the upstream was reached for a refused read: %v", e.upstream.calls())
	}

	// The other resource is refused with the resource scopes but no profile scope,
	// so the gate is not simply open once two sources exist.
	before = len(e.upstream.calls())
	status, _, body = e.zGet("/v1/games/"+zGame+"/profile", both)
	t.Logf("normalized profile with the score scopes -> %d %s", status, body)
	if status != http.StatusForbidden {
		t.Errorf("the normalized gate answered %d for the resource the token was not granted, want 403", status)
	}
	if len(e.upstream.calls()) != before {
		t.Errorf("the upstream was reached for a refused read: %v", e.upstream.calls())
	}
}
