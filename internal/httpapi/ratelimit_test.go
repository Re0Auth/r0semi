package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// newLimitedServer builds a server with a one-token bucket, so the first request
// from a client address succeeds and every one after it is throttled.
func newLimitedServer(t *testing.T) *httptest.Server {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://re0auth.test", Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Config{
		Issuer:  "https://re0auth.test",
		AS:      as,
		Limiter: ratelimit.New(0.001, 1), // effectively one request per client address
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// The business plane must answer a throttled request with problem+json, and the
// protocol plane with an OAuth error. A limiter that blurred the two would break
// the plane invariant the whole design rests on.
func TestRateLimitUsesEachPlanesErrorShape(t *testing.T) {
	srv := newLimitedServer(t)

	first, err := http.Get(srv.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first request = %d, want 401", first.StatusCode)
	}

	second, err := http.Get(srv.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", second.StatusCode)
	}
	if second.Header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	if ct := second.Header.Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("content-type = %q, want problem+json", ct)
	}
	var problem map[string]any
	if err := json.NewDecoder(second.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem["code"] != "rate_limited" {
		t.Fatalf("problem = %v", problem)
	}
}

func TestRateLimitProtocolPlaneUsesOAuthError(t *testing.T) {
	srv := newLimitedServer(t)

	post := func() *http.Response {
		resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
			"grant_type": {"bogus"}, "client_id": {"cli"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := post()
	first.Body.Close()
	if first.StatusCode != http.StatusBadRequest {
		t.Fatalf("first request = %d, want 400", first.StatusCode)
	}

	second := post()
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", second.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(second.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "temporarily_unavailable" {
		t.Fatalf("body = %v", body)
	}
	// A protocol-plane body carries error/error_description only.
	if _, leaked := body["code"]; leaked {
		t.Fatalf("protocol plane leaked a problem field: %v", body)
	}
}
