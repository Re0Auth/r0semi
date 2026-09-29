//go:build audit7

// Upstream Kit probe: what the conformance suite does NOT fail on.
//
// Round 5's KIT-7 was "the suite makes no assertion about client authentication
// at all". The round-5/7 fix closed exactly one instance of it: the suite now
// asserts that a *cascade* endpoint refuses an unauthenticated caller
// (conformance/conformance.go:282-313, "cascade.requires_auth"). The sibling
// check for the RFC 7009 endpoint next to it still only looks for a 404
// (conformance.go:253-265), so dropping Basic auth from /oauth/revoke — the same
// change the cascade assertion exists to catch — is still a silent PASS.
package z14kitrptaptap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/upstreamkit/conformance"
)

// sourceUnderTest is a hand-rolled "source" with one knob: what /oauth/revoke
// answers when the caller supplied no credentials at all.
type sourceUnderTest struct {
	// revokeStatus is what POST /oauth/revoke answers. 200 means "accepted an
	// unauthenticated caller", 401 means "authenticated it first".
	revokeStatus int
	// authorizeRedirect makes /oauth/authorize answer 302 for an unknown client,
	// which is a conformance error — the suite's own liveness control.
	authorizeRedirect bool
	// resources is what the discovery document declares. scopes_supported is
	// deliberately left as just account.read, so a probe can declare a resource
	// whose scope the document never advertises.
	resources []upstreamkit.Resource

	revokeHits int
}

func (s *sourceUnderTest) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/re0auth-upstream", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		probeWriteJSON(w, upstreamkit.Discovery{
			ProtocolVersion: upstreamkit.ProtocolVersion,
			Game:            "phigros",
			Source:          "z14-probe",
			DisplayName:     "Z14 probe source",
			TokenClass:      upstreamkit.TokenRevocable,
			ScopesSupported: []string{upstreamkit.AccountScope},
			OAuth: upstreamkit.OAuthEndpoints{
				Issuer:                base,
				AuthorizationEndpoint: base + "/oauth/authorize",
				TokenEndpoint:         base + "/oauth/token",
				RevocationEndpoint:    base + "/oauth/revoke",
			},
		})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		probeWriteJSON(w, map[string]any{
			"code_challenge_methods_supported": []string{"S256"},
			"response_types_supported":         []string{"code"},
		})
	})
	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		if s.authorizeRedirect {
			w.Header().Set("Location", "https://someone.example/cb?code=x")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		// Rejects the conformance probe's bogus code, so token.rejects_bad_grant
		// passes — while still requiring no client authentication at all.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})
	mux.HandleFunc("POST /oauth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		s.revokeHits++
		w.WriteHeader(s.revokeStatus)
	})
	return mux
}

func runConformance(t *testing.T, target string) []conformance.Finding {
	t.Helper()
	return conformance.Run(context.Background(), target, conformance.Options{})
}

func countLevel(findings []conformance.Finding, level conformance.Level) int {
	n := 0
	for _, f := range findings {
		if f.Level == level {
			n++
		}
	}
	return n
}

func describe(findings []conformance.Finding) string {
	b, _ := json.Marshal(findings)
	return string(b)
}

// TestZ14ControlConformanceDetectsAnObviousNonConformance proves the suite is
// alive: an authorize endpoint that redirects an unknown client is an error.
func TestZ14ControlConformanceDetectsAnObviousNonConformance(t *testing.T) {
	src := &sourceUnderTest{revokeStatus: http.StatusOK, authorizeRedirect: true}
	srv := httptest.NewServer(src.handler())
	defer srv.Close()

	findings := runConformance(t, srv.URL)
	if countLevel(findings, conformance.LevelError) == 0 {
		t.Fatalf("control: the suite reported no error for an authorize endpoint that redirects an unknown client: %s", describe(findings))
	}
	t.Logf("control: %d error(s): %s", countLevel(findings, conformance.LevelError), describe(findings))
}

// TestZ14ConformancePassesARevocationEndpointThatAuthenticatesNobody: a source
// whose /oauth/revoke answers 200 to a caller with no credentials and an unknown
// client id is reported compliant.
//
// RFC 7009 §2.1 requires client authentication, and the kit's own generated
// /oauth/revoke goes through oauth.Service.Revoke, which authenticates first
// (oauth/as.go:219). So the endpoint the assertion is missing is exactly the one
// a third party is most likely to hand-roll.
func TestZ14ConformancePassesARevocationEndpointThatAuthenticatesNobody(t *testing.T) {
	src := &sourceUnderTest{revokeStatus: http.StatusOK}
	srv := httptest.NewServer(src.handler())
	defer srv.Close()

	findings := runConformance(t, srv.URL)
	errors := countLevel(findings, conformance.LevelError)
	t.Logf("unauthenticated /oauth/revoke hits=%d; suite findings: %s", src.revokeHits, describe(findings))

	if errors == 0 {
		t.Errorf("conformance reported zero errors for a source whose /oauth/revoke answers 200 to a request with no credentials and client_id=%q.\n"+
			"conformance.go:253-265 (checkRevocationEndpoint) treats every status except 404 as fine; the cascade check beside it (conformance.go:282-313) was hardened to require a 401/4xx, and this one was not.",
			"conformance-unknown-client")
		return
	}
	t.Logf("the suite did flag it: %s", describe(findings))
}
