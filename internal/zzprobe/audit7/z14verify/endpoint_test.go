//go:build audit7

// Independent re-verification for zone 14, part two: WHICH URL the conformance
// suite probes.
//
// The suite reads the discovery document and then checks the advertised OAuth
// endpoints only against the target origin: `checkRevocationEndpoint`
// hard-codes `{target}/oauth/revoke` (conformance.go:255) and never looks at
// `disc.OAuth.RevocationEndpoint` at all, and `checkCascadeEndpoint` parses the
// advertised absolute URL only to assert it is absolute, then sends the probe to
// `{target}{path}` (conformance.go:296 `parsed.RequestURI()` with
// request() = base+path). A hand-rolled source whose endpoint lives on another
// origin — which the document permits, and which the cascade check's own
// absoluteness assertion contemplates — is therefore judged on a URL it never
// advertised. The same-origin, non-conventional-path case is a control here
// because RequestURI() keeps the path: only the origin is discarded.
package z14verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
)

// TestZ14VControlTheSuiteProbesTheAdvertisedTargetPath is the positive control:
// a hand-rolled source that advertises the conventional `{base}/oauth/revoke`
// and refuses an unauthenticated caller produces no errors, and the suite is
// shown to have really sent the probe there.
func TestZ14VControlTheSuiteProbesTheAdvertisedTargetPath(t *testing.T) {
	fixture := newVerifySource("", "")
	srv := startVerifySource(t, fixture)
	for path, status := range compliantStatuses() {
		fixture.set(path, status)
	}

	findings := runVerifyConformance(t, srv.URL)
	if msg, bad := hasError(findings, "revoke.present"); bad {
		t.Fatalf("control: the advertised {base}/oauth/revoke was reported missing: %s (%s)", msg, describeVerify(findings))
	}
	if hits := fixture.hitCount("/oauth/revoke"); hits == 0 {
		t.Fatalf("control: the suite never sent a request to {base}/oauth/revoke; findings: %s", describeVerify(findings))
	}
	t.Logf("control: every check passed without a token; findings=%s", describeVerify(findings))
}

// TestZ14VRevocationEndpointOnAnotherPathIsReportedMissing is red: the source
// advertises and serves its revocation endpoint at `{base}/oauth/revoke-v2`
// (refusing an unauthenticated caller), while `{base}/oauth/revoke` answers 404
// exactly as it should — that path is not advertised. The suite still reports
// `revoke.present: revocation endpoint is missing`, and never touches the
// advertised URL.
func TestZ14VRevocationEndpointOnAnotherPathIsReportedMissing(t *testing.T) {
	fixture := newVerifySource("", "")
	srv := startVerifySource(t, fixture)
	fixture.advertisedRevoke = srv.URL + "/oauth/revoke-v2"
	// The conventional path is deliberately NOT registered: 404, which is the
	// correct answer for a path this source never advertised.
	fixture.set("/oauth/authorize", http.StatusBadRequest)
	fixture.set("/oauth/token", http.StatusBadRequest)
	fixture.set("/oauth/revoke-v2", http.StatusUnauthorized)

	findings := runVerifyConformance(t, srv.URL)
	msg, bad := hasError(findings, "revoke.present")
	t.Logf("advertised revocation endpoint %s hits=%d; /oauth/revoke hits=%d; findings=%s",
		srv.URL+"/oauth/revoke-v2", fixture.hitCount("/oauth/revoke-v2"), fixture.hitCount("/oauth/revoke"), describeVerify(findings))

	if bad {
		t.Errorf("the suite reported the revocation endpoint missing (%s) although the advertised endpoint %s exists and refuses an unauthenticated caller.\n"+
			"checkRevocationEndpoint (conformance.go:253-265) POSTs to the literal \"/oauth/revoke\" (r.request prepends r.base) and never reads disc.OAuth.RevocationEndpoint; the advertised URL received %d requests.\n"+
			"A hand-rolled source may advertise any absolute revocation_endpoint, so a compliant source is failed on a URL it never named.",
			msg, srv.URL+"/oauth/revoke-v2", fixture.hitCount("/oauth/revoke-v2"))
	}
}

// TestZ14VControlTheAdvertisedCascadePathIsHonoured is the positive control for
// the cascade half: when the advertised endpoint is on the target's own origin
// but at a non-conventional path, the suite does use that path (it passes
// parsed.RequestURI(), which keeps path and query) and finds the endpoint. Only
// the advertised ORIGIN is discarded, which the probe below this one attacks.
func TestZ14VControlTheAdvertisedCascadePathIsHonoured(t *testing.T) {
	fixture := newVerifySource("", "")
	srv := startVerifySource(t, fixture)
	fixture.advertisedCascade = srv.URL + "/oauth/cascade-v2"
	for path, status := range compliantStatuses() {
		fixture.set(path, status)
	}
	fixture.set("/oauth/cascade-v2", http.StatusUnauthorized)

	findings := runVerifyConformance(t, srv.URL)
	if msg, bad := hasError(findings, "cascade.present"); bad {
		t.Fatalf("control: the advertised same-origin path was reported missing: %s (%s)", msg, describeVerify(findings))
	}
	if hits := fixture.hitCount("/oauth/cascade-v2"); hits == 0 {
		t.Fatalf("control: the suite never reached the advertised path; findings=%s", describeVerify(findings))
	}
	t.Logf("control: advertised path %s hits=%d, no cascade error; findings=%s",
		srv.URL+"/oauth/cascade-v2", fixture.hitCount("/oauth/cascade-v2"), describeVerify(findings))
}

// TestZ14VTheAdvertisedCascadeEndpointIsNeverContacted is the security direction
// of the same defect: the source advertises a cascade endpoint on ITS OWN
// origin (a legal multi-host deployment) which accepts an anonymous POST and
// would end every session; the target origin answers 401 on the conventional
// path because a reverse proxy refuses unknown routes there.
//
// The suite probes the wrong host, sees 401, and reports no error — so the
// advertised endpoint, the one Re0Auth actually calls
// (internal/federation/revocation.go:153), is never looked at.
func TestZ14VTheAdvertisedCascadeEndpointIsNeverContacted(t *testing.T) {
	// The advertised origin: its cascade endpoint answers 200 to anyone.
	open := newVerifySource("", "")
	openSrv := startVerifySource(t, open)
	open.advertisedCascade = openSrv.URL + "/oauth/cascade_revocation"
	open.set("/oauth/cascade_revocation", http.StatusOK)

	// The target the operator hands to conformance.Run: it advertises the open
	// origin's endpoint, and its own conventional path is a decoy 401.
	target := newVerifySource("", "")
	targetSrv := startVerifySource(t, target)
	target.advertisedCascade = openSrv.URL + "/oauth/cascade_revocation"
	for path, status := range compliantStatuses() {
		target.set(path, status)
	}
	target.set("/oauth/cascade_revocation", http.StatusUnauthorized)

	findings := runVerifyConformance(t, targetSrv.URL)
	msg, bad := hasError(findings, "cascade.requires_auth")
	t.Logf("advertised (open) endpoint hits=%d; target's decoy path hits=%d; findings=%s",
		open.hitCount("/oauth/cascade_revocation"), target.hitCount("/oauth/cascade_revocation"), describeVerify(findings))

	if !bad {
		t.Errorf("the suite reported no error for a source whose ADVERTISED cascade endpoint %s answers 200 to an anonymous POST (no credentials, unknown client).\n"+
			"That endpoint received %d requests; the suite probed the target's own %s instead (%d requests, decoy 401). "+
			"Re0Auth posts to the advertised endpoint, so the suite approves the endpoint that matters without ever contacting it.",
			openSrv.URL+"/oauth/cascade_revocation", open.hitCount("/oauth/cascade_revocation"),
			targetSrv.URL+"/oauth/cascade_revocation", target.hitCount("/oauth/cascade_revocation"))
		return
	}
	t.Logf("the suite flagged the advertised endpoint: %s", msg)
}

// TestZ14VGarbageAdvertisedRevocationEndpointIsAccepted is red and is the same
// root cause seen from the document side: `checkDiscovery` requires the
// revocation endpoint to be a non-empty string (conformance.go:171) and
// `checkRevocationEndpoint` never parses it, so a source may advertise a value
// that is not a URL at all and the suite still passes — while
// internal/federation/revocation.go:153 would hand exactly that string to
// http.NewRequestWithContext, which fails on "unsupported protocol scheme".
// The sibling cascade check DOES assert absoluteness (conformance.go:288-292),
// so the omission is an inconsistency, not a policy.
func TestZ14VGarbageAdvertisedRevocationEndpointIsAccepted(t *testing.T) {
	fixture := newVerifySource("", "")
	srv := startVerifySource(t, fixture)
	fixture.advertisedRevoke = "not-a-url"
	for path, status := range compliantStatuses() {
		fixture.set(path, status)
	}

	findings := runVerifyConformance(t, srv.URL)
	if _, bad := hasError(findings, "revoke.present"); bad {
		t.Fatalf("setup: the conventional path unexpectedly failed: %s", describeVerify(findings))
	}
	if !hasAnyError(findings) {
		t.Errorf("the suite reported no error for a discovery document that advertises revocation_endpoint=%q, "+
			"which is not a URL and which internal/federation/revocation.go:153 would pass to http.NewRequestWithContext verbatim. "+
			"The cascade check asserts absoluteness on the sibling endpoint (conformance.go:288-292); findings=%s",
			"not-a-url", describeVerify(findings))
		return
	}
	t.Logf("the advertised value was flagged: %s", describeVerify(findings))
}

// TestZ14VKitCascadeEndpointAuthenticatesBeforeTheHook verifies the audited
// report's "tried and did not break" claim #3 with a real kit endpoint rather
// than by reading: an anonymous POST must be refused and must not reach the
// hook, and the same call with the registered credentials must reach it.
func TestZ14VKitCascadeEndpointAuthenticatesBeforeTheHook(t *testing.T) {
	registry, err := oauth.NewRegistry(
		oauth.Descriptor{Scope: upstreamkit.AccountScope, Title: "Account", Risk: oauth.RiskLow},
	)
	if err != nil {
		t.Fatal(err)
	}
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("re0auth", "Re0Auth", oauth.ClientConfidential, "kit-secret",
		[]string{"https://re0auth.test/auth/upstream/phigros/z14verify/callback"},
		[]oauth.Scope{upstreamkit.AccountScope})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	svc, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://upstream.test",
		Scopes: registry,
	})
	if err != nil {
		t.Fatal(err)
	}

	var handler http.Handler
	kitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(kitSrv.Close)

	var hookCalls atomic.Int64
	kit, err := upstreamkit.New(upstreamkit.Config{
		Game: "phigros", Source: "z14verify", DisplayName: "Z14 verify kit",
		Issuer: kitSrv.URL, TokenClass: upstreamkit.TokenRevocable,
	}, upstreamkit.Hooks{
		OAuth: svc,
		Scope: registry,
		Consent: func(context.Context, upstreamkit.ConsentRequest) (upstreamkit.ConsentDecision, error) {
			return upstreamkit.ConsentDecision{Subject: "kit-subject"}, nil
		},
		Account: func(_ context.Context, subject string) (upstreamkit.AccountInfo, error) {
			return upstreamkit.AccountInfo{Subject: subject}, nil
		},
		CascadeRevoke: func(context.Context, upstreamkit.CascadeRevocationRequest) error {
			hookCalls.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler = kit.Handler()

	form := "token=bogus-token&token_type_hint=refresh_token"
	anonReq, _ := http.NewRequest(http.MethodPost, kitSrv.URL+"/oauth/cascade_revocation", strings.NewReader(form))
	anonReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	anonResp, err := http.DefaultClient.Do(anonReq)
	if err != nil {
		t.Fatal(err)
	}
	anonResp.Body.Close()
	anonHookCalls := hookCalls.Load()

	authReq, _ := http.NewRequest(http.MethodPost, kitSrv.URL+"/oauth/cascade_revocation", strings.NewReader(form))
	authReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authReq.SetBasicAuth(url.QueryEscape(client.ID), url.QueryEscape("kit-secret"))
	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatal(err)
	}
	authResp.Body.Close()

	t.Logf("anonymous POST -> %d (hook calls after it=%d); authenticated POST -> %d (hook calls=%d)",
		anonResp.StatusCode, anonHookCalls, authResp.StatusCode, hookCalls.Load())

	if anonResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an anonymous cascade POST got %d, want 401", anonResp.StatusCode)
	}
	if anonHookCalls != 0 {
		t.Errorf("the hook ran %d times before any credential was presented, want 0", anonHookCalls)
	}
	if authResp.StatusCode/100 == 4 {
		t.Errorf("the registered client's cascade POST got %d, want a non-4xx from the hook path", authResp.StatusCode)
	}
	if got := hookCalls.Load(); got != 1 {
		t.Errorf("the hook ran %d times, want exactly once (anonymous must not reach it)", got)
	}
}
