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
	// authorize, token and revoke override the default handlers. The defaults
	// authenticate: an unknown, credential-less caller is refused as
	// invalid_client (401), which is what the Z14-2 checks require.
	authorize http.HandlerFunc
	token     http.HandlerFunc
	revoke    http.HandlerFunc
	// metadata, when set, replaces the whole authorization-server metadata
	// document.
	metadata func(w http.ResponseWriter)
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
	metadata := opts.metadata
	if metadata == nil {
		metadata = func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code_challenge_methods_supported": []string{"S256"},
				"response_types_supported":         []string{"code"},
			})
		}
	}
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		metadata(w)
	})
	authorize := opts.authorize
	if authorize == nil {
		authorize = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }
	}
	mux.HandleFunc("/oauth/authorize", authorize)
	token := opts.token
	if token == nil {
		token = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		}
	}
	mux.HandleFunc("/oauth/token", token)
	revoke := opts.revoke
	if revoke == nil {
		revoke = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		}
	}
	mux.HandleFunc("/oauth/revoke", revoke)

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

// Z14-2: a revocation endpoint that answers 2xx to a caller with no credentials
// and an unknown client id must be an error, not silently compliant.
func TestRevocationAuthenticatingNobodyIsAnError(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{revoke: func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}})
	findings := Run(context.Background(), base, Options{})
	if !hasError(findings, "revoke.requires_auth") {
		t.Fatalf("a revocation endpoint that accepted an unauthenticated caller was not flagged: %+v", findings)
	}
}

// Z14-2: refusing the bogus grant with a non-2xx status is not enough — the
// refusal must be the client-authentication one, so a token endpoint that never
// looks at the client is still an error.
func TestClientAuthenticationIsRequiredOnTheTokenEndpoint(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{token: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}})
	findings := Run(context.Background(), base, Options{})
	if !hasError(findings, "token.requires_auth") {
		t.Fatalf("a token endpoint that answered 400 invalid_grant to an unknown, credential-less client was not flagged: %+v", findings)
	}
	if hasError(findings, "token.rejects_bad_grant") {
		t.Fatalf("the bogus grant was refused (400), so token.rejects_bad_grant must not fire: %+v", findings)
	}
}

// KIT-7: when the run is given credentials, a wrong secret must be refused as
// 401 invalid_client. A token endpoint that answers the bogus-grant error to
// every caller accepts any secret it is handed.
func TestWrongClientSecretIsAnError(t *testing.T) {
	base := fakeUpstream(t, fakeOpts{token: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}})
	findings := Run(context.Background(), base, Options{ClientID: "conf-client", ClientSecret: "conf-secret"})
	if !hasError(findings, "token.rejects_bad_credentials") {
		t.Fatalf("a wrong client secret was not refused as invalid_client: %+v", findings)
	}
}

// KIT-7: the metadata document's token_endpoint_auth_methods_supported must
// contain the method the endpoint was observed to accept; an absent field stays a
// warning rather than an error.
func TestDeclaredAuthMethodsMustMatchWhatIsAccepted(t *testing.T) {
	opts := Options{ClientID: "conf-client", ClientSecret: "conf-secret"}

	// Accepts Basic with the right secret (the bogus grant is then refused as
	// invalid_grant) and refuses every other credential as invalid_client.
	token := func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		if ok && id == "conf-client" && secret == "conf-secret" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}
	metadata := func(methods ...string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			doc := map[string]any{
				"code_challenge_methods_supported": []string{"S256"},
				"response_types_supported":         []string{"code"},
			}
			if methods != nil {
				doc["token_endpoint_auth_methods_supported"] = methods
			}
			_ = json.NewEncoder(w).Encode(doc)
		}
	}

	// Absent: a warning, never an error.
	absent := fakeUpstream(t, fakeOpts{token: token, metadata: metadata()})
	if hasError(Run(context.Background(), absent, opts), "oauth.token_auth_methods") {
		t.Fatal("an absent token_endpoint_auth_methods_supported was reported as an error")
	}

	// Declared client_secret_post while Basic was accepted: an error.
	mismatch := fakeUpstream(t, fakeOpts{token: token, metadata: metadata("client_secret_post")})
	if !hasError(Run(context.Background(), mismatch, opts), "oauth.token_auth_methods") {
		t.Fatal("metadata declared client_secret_post but the endpoint accepted Basic")
	}

	// Control: declaring what was accepted is not flagged.
	match := fakeUpstream(t, fakeOpts{token: token, metadata: metadata("client_secret_basic")})
	if hasError(Run(context.Background(), match, opts), "oauth.token_auth_methods") {
		t.Fatal("metadata declared client_secret_basic and Basic was accepted, yet it was flagged")
	}
}
