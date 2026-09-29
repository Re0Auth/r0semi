//go:build audit7

// Independent verification probes for zone 20. Each probe is written so that it
// can fail: the "X is refused / yields nothing" claims carry a positive control
// that proves the probe reaches the path.
package zzprobe_z20verify

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// TestZ20VBothPlanesAddressTheSameUpstreamEndpoint is the structural half of
// Z20-2 that the reviewed probe asserted from configuration but never observed:
// with raw_base == issuer, the normalized fetch for `scores` and the raw
// passthrough of `resources/scores` must both hit `<issuer>/resources/scores`.
func TestZ20VBothPlanesAddressTheSameUpstreamEndpoint(t *testing.T) {
	e := newVEnv(t, vOptions{})
	score := e.mintToken(vSubject, "phigros.score.read")

	st, _, body := e.vGet("/v1/games/phigros/scores", score)
	if st != http.StatusOK {
		t.Fatalf("control: normalized path with the score scope = %d: %s", st, body)
	}
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/resources/scores", score)
	if st != http.StatusOK {
		t.Fatalf("control: raw path with the score scope = %d: %s", st, body)
	}

	urls := e.upstream.snapshot()
	t.Logf("upstream saw: %v", urls)
	if e.upstream.count("/resources/scores") != 2 {
		t.Errorf("the two entrances did not address the same upstream endpoint: %v", urls)
	}
}

// TestZ20VProfileOnlyTokenReachesAnyNativePath is the impact half of Z20-2,
// pushed past "the same scores URL": a token the user granted only profile for
// reaches a native path that no Re0Auth resource describes at all.
func TestZ20VProfileOnlyTokenReachesAnyNativePath(t *testing.T) {
	e := newVEnv(t, vOptions{})
	profile := e.mintToken(vSubject, "phigros.profile.read")

	// Control 1: the normalized gate refuses the score resource.
	st, _, body := e.vGet("/v1/games/phigros/scores", profile)
	t.Logf("normalized scores (profile-only) -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Fatalf("control: normalized gate = %d, want 403", st)
	}

	// Control 2: the raw gate is alive — no resource scope at all is refused.
	identity := e.mintToken(vSubject, "account.id")
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/admin/wipe", identity)
	t.Logf("raw admin/wipe (account.id only) -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Fatalf("control: raw gate = %d for a token with no resource scope, want 403", st)
	}
	if e.upstream.count("/admin/wipe") != 0 {
		t.Fatalf("control: a refused raw read reached the upstream")
	}

	// The attack: the profile scope opens an arbitrary native path.
	st, _, body = e.vGet("/v1/games/phigros/sources/fake/raw/admin/wipe", profile)
	t.Logf("raw admin/wipe (profile-only) -> %d %s", st, body)
	if st == http.StatusOK && e.upstream.count("/admin/wipe") > 0 {
		t.Errorf("a profile-only token reached the source's native admin path (%d): %s. "+
			"The raw gate is per-source, not per-resource, and does not even require the "+
			"path to name a declared resource. Upstream: %v", st, body, e.upstream.snapshot())
	}
}

// TestZ20VDenyEventAppearsOnlyAtTokenExchange isolates Z20-1's call site: the
// spurious deny must not exist after the consent decision or after the callback,
// and must appear only when the code is exchanged at the token endpoint.
func TestZ20VDenyEventAppearsOnlyAtTokenExchange(t *testing.T) {
	e := newVEnv(t, vOptions{})
	id := e.vStartAuthorize(vSubject, "account.id")
	if n := len(e.vEvents("oidc.consent.deny")); n != 0 {
		t.Fatalf("authorize alone recorded %d deny events", n)
	}
	e.vComplete(id, vSubject, "account.id")
	if n := len(e.vEvents("oidc.consent.deny")); n != 0 {
		t.Fatalf("the consent approval recorded %d deny events", n)
	}
	approves := e.vEvents("oidc.consent.approve")
	if len(approves) != 1 || approves[0].Detail["scopes"] != "account.id offline_access" {
		t.Fatalf("control: the approval event is not the interactive-face shape: %+v", approves)
	}
	code := e.vCallback(id)
	if n := len(e.vEvents("oidc.consent.deny")); n != 0 {
		t.Fatalf("the callback recorded %d deny events", n)
	}
	st, body := e.vExchange(code, vClientID)
	if st != http.StatusOK {
		t.Fatalf("token = %d: %s", st, body)
	}
	denies := e.vEvents("oidc.consent.deny")
	if len(denies) != 1 {
		t.Fatalf("the successful exchange recorded %d deny events, want 1", len(denies))
	}
	d := denies[0]
	t.Logf("spurious deny: subject=%q detail=%v outcome=%s", d.Subject, d.Detail, d.Outcome)
	if d.Subject != "" || d.Detail["client_id"] != "" {
		t.Errorf("the spurious deny is attributable: subject=%q detail=%v", d.Subject, d.Detail)
	}
	if d.Outcome != "denied" {
		t.Errorf("the spurious event is not shaped as a refusal: %+v", d)
	}
}

// TestZ20VEncodedIntrospectionKeepsTheRawCallerIdentity is the positive control
// Z20-6 needs: the negative (encoded -> active=false) is only meaningful if an
// allowlisted caller spelled exactly as the library reads it DOES get the body.
func TestZ20VEncodedIntrospectionKeepsTheRawCallerIdentity(t *testing.T) {
	e := newVEnv(t, vOptions{
		IntrospectionClients: []string{"conf"},
		ConfidentialID:       "conf", ConfidentialSecret: "conf-secret",
	})
	own := e.mintToken(vSubject, "account.id")

	// Positive control 1: the token owner (public, plain spelling) is refused by
	// the runtime guard.
	st, body := e.vPostForm("/oauth/introspect", url.Values{"token": {own}}, vBasic("cli", ""))
	t.Logf("plain public owner -> %d %s", st, body)
	if st != http.StatusUnauthorized {
		t.Fatalf("control: plain public owner = %d, want 401", st)
	}

	// Positive control 2: an allowlisted CONFIDENTIAL client sees the token.
	st, body = e.vPostForm("/oauth/introspect", url.Values{"token": {own}}, vBasic("conf", "conf-secret"))
	t.Logf("allowlisted confidential -> %d %s", st, body)
	var ok map[string]any
	if err := json.Unmarshal(body, &ok); err != nil {
		t.Fatalf("control body is not JSON: %s", body)
	}
	if active, _ := ok["active"].(bool); !active || ok["client_id"] != "cli" {
		t.Fatalf("control: the allowlisted caller did not get the live body: %s", body)
	}

	// The bypass, spelled to decode to the very client that is allowlisted.
	st, body = e.vPostForm("/oauth/introspect", url.Values{"token": {own}}, vBasic("co%6ef", "conf-secret"))
	t.Logf("encoded allowlisted conf -> %d %s", st, body)
	if st == http.StatusUnauthorized {
		t.Skipf("the encoded spelling no longer bypasses the guard (fixed): %s", body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("introspection body is not JSON: %s", body)
	}
	if active, _ := out["active"].(bool); active {
		t.Errorf("active=true reached a caller whose identity the library decoded but the "+
			"filter did not: %s", body)
	}
	for _, f := range []string{"sub", "scope", "client_id", "exp", "aud", "iss"} {
		if _, has := out[f]; has {
			t.Errorf("introspection disclosed %q: %s", f, body)
		}
	}
}

// TestZ20VNormalizedGateRequiresEveryCandidateSourcesScope tests the reviewed
// report's guard claim with TWO sources that declare different scopes for the
// same resource — the shape its own single-source guard cannot distinguish from
// "first source wins".
func TestZ20VNormalizedGateRequiresEveryCandidateSourcesScope(t *testing.T) {
	crit := oauth.Descriptor{
		Scope: "phigros.score2.read", Title: "第二成绩", Description: "verify",
		Risk: oauth.RiskMedium,
	}
	e := newVEnv(t, vOptions{
		Sources:  vTwoSources,
		Registry: vRegistryWith(t, crit),
		ClientScopes: []oauth.Scope{
			oauth.ScopeAccountID, "phigros.score.read", "phigros.score2.read",
		},
	})

	onlyA := e.mintToken(vSubject, "phigros.score.read")
	st, _, body := e.vGet("/v1/games/"+vGame+"/scores", onlyA)
	t.Logf("only alpha's scope -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Errorf("a token holding only one candidate source's scope was served (%d): %s", st, body)
	}

	onlyB := e.mintToken(vSubject, "phigros.score2.read")
	st, _, body = e.vGet("/v1/games/"+vGame+"/scores", onlyB)
	t.Logf("only beta's scope -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Errorf("a token holding only the other candidate's scope was served (%d): %s", st, body)
	}

	both := e.mintToken(vSubject, "phigros.score.read", "phigros.score2.read")
	st, hdr, body := e.vGet("/v1/games/"+vGame+"/scores", both)
	t.Logf("both scopes -> %d source=%s", st, hdr.Get("Re0Auth-Source"))
	if st != http.StatusOK {
		t.Errorf("control: a token holding both scopes was refused (%d): %s", st, body)
	}
}

// TestZ20VDirectApproveDeviceSkipsExplicitConsent checks the residual of Z20-4:
// the ROUTE's entrance (DecideDeviceAuthorization) enforces explicit consent,
// but the exported ApproveDevice it calls into does not, so a direct caller of
// the engine method can approve an ExplicitConsent scope with no tick.
func TestZ20VDirectApproveDeviceSkipsExplicitConsent(t *testing.T) {
	const crit = oauth.Scope("phigros.secret.read")
	e := newVEnv(t, vOptions{
		Registry: vRegistryWith(t, oauth.Descriptor{
			Scope: crit, Title: "机密", Description: "verify",
			Risk: oauth.RiskCritical, ExplicitConsent: true,
		}),
		ClientScopes: []oauth.Scope{oauth.ScopeAccountID, crit},
	})

	newCode := func(t *testing.T) string {
		t.Helper()
		form := url.Values{"client_id": {vClientID}, "scope": {crit.String()}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/device_authorization", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		e.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("device_authorization = %d: %s", rec.Code, rec.Body.String())
		}
		var dev struct {
			UserCode string `json:"user_code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &dev); err != nil || dev.UserCode == "" {
			t.Fatalf("no user code: %s (err=%v)", rec.Body.String(), err)
		}
		return dev.UserCode
	}

	// Control: the route's entrance refuses without the tick.
	uc := newCode(t)
	err := e.store.DecideDeviceAuthorization(t.Context(), uc, vSubject, true, nil, nil)
	t.Logf("DecideDeviceAuthorization without a tick -> %v", err)
	var oe *oauth.Error
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Fatalf("control: the entrance did not refuse with access_denied: %v", err)
	}

	// The engine method itself, called directly, does not consult the catalogue.
	uc2 := newCode(t)
	err = e.store.ApproveDevice(t.Context(), uc2, vSubject, nil)
	t.Logf("ApproveDevice directly without a tick -> %v", err)
	if err == nil {
		t.Errorf("ApproveDevice approved an ExplicitConsent scope with no tick: the gate lives "+
			"only in DecideDeviceAuthorization (the route's entrance), so P-02's literal target "+
			"%q is still ungated — unreachable from a route today, but an exported footgun", "ApproveDevice")
	}
}
