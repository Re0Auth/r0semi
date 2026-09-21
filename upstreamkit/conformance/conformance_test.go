package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeOpts struct {
	// mutate adjusts the discovery document before it is served.
	mutate func(disc map[string]any)
	// authorize, token and revoke override the default handlers.
	authorize http.HandlerFunc
	token     http.HandlerFunc
}

func validDiscovery(issuer string) map[string]any {
	return map[string]any{
		"re0auth_upstream_version": 1,
		"game":                     "phigros",
		"source":                   "fake",
		"display_name":             "Fake Backend",
		"oauth": map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/oauth/authorize",
			"token_endpoint":         issuer + "/oauth/token",
			"revocation_endpoint":    issuer + "/oauth/revoke",
		},
		"token_class":      "revocable",
		"scopes_supported": []string{"account.read"},
		"resources":        []any{},
	}
}

func fakeUpstream(t *testing.T, opts fakeOpts) string {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/re0auth-upstream", func(w http.ResponseWriter, r *http.Request) {
		disc := validDiscovery("http://" + r.Host)
		if opts.mutate != nil {
			opts.mutate(disc)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(disc)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code_challenge_methods_supported": []string{"S256"},
			"response_types_supported":         []string{"code"},
		})
	})
	authorize := opts.authorize
	if authorize == nil {
		authorize = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }
	}
	mux.HandleFunc("/oauth/authorize", authorize)
	token := opts.token
	if token == nil {
		token = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }
	}
	mux.HandleFunc("/oauth/token", token)
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func hasError(findings []Finding, check string) bool {
	for _, f := range findings {
		if f.Check == check && f.Level == LevelError {
			return true
		}
	}
	return false
}

func hasSkip(findings []Finding, check string) bool {
	for _, f := range findings {
		if f.Check == check && f.Level == LevelSkipped {
			return true
		}
	}
	return false
}

func TestValidUpstreamHasNoErrors(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{})
	findings := Run(context.Background(), base, Options{})
	for _, f := range findings {
		if f.Level == LevelError {
			t.Errorf("unexpected error: %+v", f)
		}
	}
	if !hasSkip(findings, "data.skipped") {
		t.Fatalf("expected a data.skipped finding: %+v", findings)
	}
}

func TestMissingAccountScopeIsAnError(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{mutate: func(d map[string]any) {
		d["scopes_supported"] = []string{"phigros.score.read"}
	}})
	if !hasError(Run(context.Background(), base, Options{}), "discovery.scopes") {
		t.Fatal("missing account.read was not flagged")
	}
}

func TestBadTokenClassIsAnError(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{mutate: func(d map[string]any) {
		d["token_class"] = "master_key"
	}})
	if !hasError(Run(context.Background(), base, Options{}), "discovery.token_class") {
		t.Fatal("an invalid token_class was not flagged")
	}
}

func TestWrongProtocolVersionIsAnError(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{mutate: func(d map[string]any) {
		d["re0auth_upstream_version"] = 2
	}})
	if !hasError(Run(context.Background(), base, Options{}), "discovery.version") {
		t.Fatal("a wrong protocol version was not flagged")
	}
}

func TestAuthorizeRedirectingUnknownClientIsAnError(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{authorize: func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/cb?code=x", http.StatusFound)
	}})
	if !hasError(Run(context.Background(), base, Options{}), "authorize.rejects_unknown_client") {
		t.Fatal("a redirect for an unknown client was not flagged")
	}
}

func TestTokenAcceptingBadGrantIsAnError(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{token: func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "x"})
	}})
	if !hasError(Run(context.Background(), base, Options{}), "token.rejects_bad_grant") {
		t.Fatal("accepting a bogus grant was not flagged")
	}
}

func TestMissingDiscoveryIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if !hasError(Run(context.Background(), srv.URL, Options{}), "discovery.present") {
		t.Fatal("a missing discovery document was not flagged")
	}
}
