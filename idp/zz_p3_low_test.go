package idp

// P3 probes for idp: a partial auth_url/token_url override (S06-7 / Z14-5), a
// discovery document whose OAuth endpoints cannot be used as a redirect target
// (RP-5), a hung issuer that must not pin a login goroutine (S06-8), and a
// transport error that must not hand out QQ's access token (Z19-2).
//
// They carry no build tag: `go test ./idp/` runs them. Each one fails on the code
// as it stood before its fix, so the red run is the evidence for the green one.
// Z18-2 (discovery under providerMu) is probed by the earlier, tag-free
// TestAuditS063DiscoveryFailureDoesNotSerializeConcurrentLogins.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/internal/testoidc"
)

// --- S06-7 / Z14-5: a partial override must survive discovery --------------

// Only one of the two endpoints is configured. Discovery may fill the half the
// operator left empty, but it must not overwrite the half they set: before the
// fix the explicit value was discarded the moment its sibling was empty, and the
// login silently went to the document's endpoint instead.
func TestP3PartialAuthURLOverrideIsUsed(t *testing.T) {
	op := testoidc.New()
	defer op.Close()

	const explicit = "https://login.example.test/custom-authorize"
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   op.Client(),
		Credentials: []Credentials{{
			Provider: "partial-auth", ClientID: "cid", ClientSecret: "sec",
			Issuer: op.URL, AuthURL: explicit,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("partial-auth")
	if !ok {
		t.Fatal("the provider was not registered")
	}

	raw, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, explicit+"?") {
		t.Fatalf("authorization URL = %q, want the configured auth_url %q", raw, explicit)
	}

	// The empty half still comes from discovery: the code exchange must reach the
	// provider's own token endpoint.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, op.Client())
	if _, err := c.Exchange(ctx, "code-1", c.NewVerifier()); err != nil {
		t.Fatalf("the discovered token endpoint was not used: %v", err)
	}
}

// The mirror image: only token_url is configured, so discovery supplies the
// authorization endpoint and the explicit token endpoint must receive the code.
func TestP3PartialTokenURLOverrideIsUsed(t *testing.T) {
	op := testoidc.New()
	defer op.Close()

	var tokenCalls atomic.Int64
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-explicit", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer tokenSrv.Close()

	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   tokenSrv.Client(),
		Credentials: []Credentials{{
			Provider: "partial-token", ClientID: "cid", ClientSecret: "sec",
			Issuer: op.URL, TokenURL: tokenSrv.URL + "/token",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("partial-token")
	if !ok {
		t.Fatal("the provider was not registered")
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, tokenSrv.Client())

	token, err := c.Exchange(ctx, "code-1", c.NewVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "at-explicit" || tokenCalls.Load() != 1 {
		t.Fatalf("token = %+v after %d calls at the explicit token endpoint; the configured token_url was ignored",
			token, tokenCalls.Load())
	}

	raw, err := c.AuthCodeURL(ctx, "st", c.NewVerifier(), "n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, op.URL+"/authorize?") {
		t.Fatalf("authorization URL = %q, want the discovered endpoint", raw)
	}
}

// --- RP-5: a discovery document must not hand out a relative login URL -----

// p3DocClient builds a custom OIDC provider against a discovery document whose
// two OAuth endpoints the test chooses. endpoints maps a field to the value the
// document carries: a leading "/" is resolved against the issuer, and an empty
// value omits the field entirely. jwks_uri is always present, so the case under
// test is the only thing missing.
func p3DocClient(t *testing.T, endpoints map[string]string) (*Client, string) {
	t.Helper()
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                                base,
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		for field, value := range endpoints {
			if value == "" {
				continue
			}
			if strings.HasPrefix(value, "/") {
				value = base + value
			}
			doc[field] = value
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL

	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   srv.Client(),
		Credentials: []Credentials{{
			Provider: "p3doc", ClientID: "cid", ClientSecret: "sec", Issuer: srv.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("p3doc")
	if !ok {
		t.Fatal("the provider was not registered")
	}
	return c, srv.URL
}

// An endpoint the document does not name, or names without a scheme and host,
// cannot be the target of a browser redirect: today it produced a relative login
// URL (http.Redirect happily sends it), so the browser came back to this origin
// in a loop. The refusal names the endpoint the operator has to fix.
func TestP3DiscoveryWithoutUsableEndpointsIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		endpoints map[string]string
		wantRef   string
	}{
		{
			"authorization_endpoint omitted",
			map[string]string{"authorization_endpoint": "", "token_endpoint": "/token"},
			"authorization_endpoint",
		},
		{
			"authorization_endpoint relative",
			map[string]string{"authorization_endpoint": "authorize", "token_endpoint": "/token"},
			"authorization_endpoint",
		},
		{
			"token_endpoint omitted",
			map[string]string{"authorization_endpoint": "/authorize", "token_endpoint": ""},
			"token_endpoint",
		},
		{
			// Anti-vacuity: a usable document is not refused.
			"both usable",
			map[string]string{"authorization_endpoint": "/authorize", "token_endpoint": "/token"},
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, base := p3DocClient(t, tc.endpoints)
			raw, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "n")
			if tc.wantRef == "" {
				if err != nil {
					t.Fatalf("a usable discovery document was refused: %v", err)
				}
				if !strings.HasPrefix(raw, base+"/authorize?") {
					t.Fatalf("authorization URL = %q, want the discovered endpoint", raw)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted a discovery document whose %s is unusable and produced %q; "+
					"the caller redirects the browser to that value", tc.wantRef, raw)
			}
			if !strings.Contains(err.Error(), tc.wantRef) {
				t.Errorf("the refusal does not name %s: %v", tc.wantRef, err)
			}
		})
	}
}

// --- S06-8: a hung issuer must not pin the login goroutine ----------------

// p3HungOP serves a usable discovery document and key set until the test hangs
// one of them. A hung handler blocks until its request is canceled or the test
// ends, so a client that carries no timeout of its own waits there for the whole
// test: that is the state S06-8 describes.
func p3HungOP(t *testing.T) (*httptest.Server, *atomic.Bool, *atomic.Bool) {
	t.Helper()
	var hangDiscovery, hangJWKS atomic.Bool
	unblock := make(chan struct{})
	var base string

	wait := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-unblock:
		case <-r.Context().Done():
		}
		http.Error(w, "the issuer never answered", http.StatusServiceUnavailable)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if hangDiscovery.Load() {
			wait(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		if hangJWKS.Load() {
			wait(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		close(unblock)
		srv.Close()
	})
	base = srv.URL
	return srv, &hangDiscovery, &hangJWKS
}

// p3ClientForIssuer builds one custom OIDC provider with the test's own HTTP
// client, so the client's own Timeout is the test's choice. The discovery
// ceiling is set short so a bounded round trip is observed rather than waited
// out at the 10s default.
func p3ClientForIssuer(t *testing.T, issuer string, hc *http.Client) *Client {
	t.Helper()
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase:     "https://re0auth.test",
		HTTPClient:       hc,
		DiscoveryTimeout: 200 * time.Millisecond,
		Credentials: []Credentials{{
			Provider: "p3hung", ClientID: "cid", ClientSecret: "sec", Issuer: issuer,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("p3hung")
	if !ok {
		t.Fatal("the provider was not registered")
	}
	return c
}

// mustReturn runs one call and reports whether it finished within bound, so a
// hung issuer fails a probe in two seconds instead of hanging the package.
func mustReturn(t *testing.T, bound time.Duration, call func() error) error {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- call() }()
	select {
	case err := <-done:
		t.Logf("the call returned after %s", time.Since(start).Round(time.Millisecond))
		return err
	case <-time.After(bound):
		t.Fatalf("the call had not returned after %s: a hung issuer pins the login goroutine", bound)
		return nil
	}
}

func TestP3HungDiscoveryIsBounded(t *testing.T) {
	srv, hangDiscovery, _ := p3HungOP(t)
	hangDiscovery.Store(true)

	// An injected client with no Timeout of its own is exactly the case S06-8
	// names: nothing in the request context or the client bounds the round trip.
	c := p3ClientForIssuer(t, srv.URL, &http.Client{})

	err := mustReturn(t, 2*time.Second, func() error {
		_, err := c.AuthCodeURL(context.Background(), "st", c.NewVerifier(), "n")
		return err
	})
	if err == nil {
		t.Fatal("a discovery that never answers was reported as success")
	}
}

// The key set is the half that cannot be stopped by cancelation at all: go-oidc
// builds its RemoteKeySet on a context.WithoutCancel, so only a client timeout
// ends the fetch. A syntactically valid token with an unknown kid is enough to
// make the verifier go and fetch it.
func TestP3HungKeySetIsBounded(t *testing.T) {
	srv, _, hangJWKS := p3HungOP(t)
	c := p3ClientForIssuer(t, srv.URL, &http.Client{})
	hangJWKS.Store(true)

	// header {"alg":"RS256","kid":"p3"}, payload {"sub":"x"}, signature "sig".
	const rawIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InAzIn0.eyJzdWIiOiJ4In0.c2ln"
	token := (&oauth2.Token{AccessToken: "at-1"}).WithExtra(map[string]any{"id_token": rawIDToken})

	err := mustReturn(t, 2*time.Second, func() error {
		_, err := c.Identity(context.Background(), token, "n")
		return err
	})
	if err == nil {
		t.Fatal("a key set that never answers was reported as success")
	}
}

// The ceiling must not truncate a healthy login: a real provider answers well
// inside it, and the whole OIDC flow still completes.
func TestP3TheBoundDoesNotBreakAHealthyIssuer(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()

	reg, err := NewRegistry(RegistryConfig{
		RedirectBase:     "https://re0auth.test",
		HTTPClient:       provider.Client(),
		DiscoveryTimeout: 200 * time.Millisecond,
		Credentials: []Credentials{{
			Provider: "p3healthy", ClientID: "cid", ClientSecret: "sec", Issuer: provider.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("p3healthy")
	if !ok {
		t.Fatal("the provider was not registered")
	}

	nonce := c.NewNonce()
	provider.SetNonce(nonce)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, provider.Client())

	token, err := c.Exchange(ctx, "code-1", c.NewVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identity(ctx, token, nonce); err != nil {
		t.Fatalf("a healthy provider was refused: %v", err)
	}
}

// --- Z19-2: a transport error must not carry QQ's access token ------------

// erroringTransport fails every request, so the error getText wraps is the one
// net/http builds from the URL -- and QQ's profile calls carry the access token
// in the query string, because that API has no header form.
type erroringTransport struct{}

func (erroringTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport is broken")
}

func TestP3QQRequestErrorsDoNotCarryTheAccessToken(t *testing.T) {
	const secret = "QQ-ACCESS-TOKEN-SECRET"
	hc := &http.Client{Transport: erroringTransport{}}
	def := definition{
		qqMeURL:       "https://graph.qq.test/oauth2.0/me?unionid=1",
		qqUserInfoURL: "https://graph.qq.test/user/get_user_info",
	}

	_, err := fetchQQ(context.Background(), hc, def, "cid", &oauth2.Token{AccessToken: secret})
	if err == nil {
		t.Fatal("the broken transport was reported as success")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error hands out the access token: %v", err)
	}
	// Anti-vacuity: only the secret is gone; the failure still names what it was
	// about, so the error was not simply emptied.
	if !strings.Contains(err.Error(), "graph.qq.test") {
		t.Fatalf("the error lost the endpoint it was about: %v", err)
	}
}
