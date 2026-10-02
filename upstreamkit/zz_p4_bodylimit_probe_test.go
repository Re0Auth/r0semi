package upstreamkit_test

// Probe for S01-13/KIT-8: an oversized request body with no Content-Length (a
// chunked body) overflows the shared cap only while ParseForm reads it. All three
// form-reading endpoints must answer 413, not the 400 a generic parse failure
// used to produce. Pre-fix the three handlers classified every ParseForm error as
// "malformed form body", so every assertion below fails.
//
// Run in the default build: `go test ./upstreamkit/... -count=1`.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
)

// p4KitHandler builds a minimal kit and returns its HTTP surface directly, so a
// request can be handed over with ContentLength = -1 (no declared length).
func p4KitHandler(t *testing.T) http.Handler {
	t.Helper()
	registry := oauth.DefaultRegistry()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("re0auth", "Re0Auth", oauth.ClientConfidential, testSecret,
		[]string{testRedirect}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://upstream.test", Scopes: registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	kit, err := upstreamkit.New(upstreamkit.Config{
		Game: "phigros", Source: "reference", DisplayName: "Reference Backend",
		Issuer: "https://upstream.test", TokenClass: upstreamkit.TokenRevocable,
	}, upstreamkit.Hooks{
		OAuth: as,
		Scope: registry,
		Consent: func(context.Context, upstreamkit.ConsentRequest) (upstreamkit.ConsentDecision, error) {
			return upstreamkit.ConsentDecision{Subject: testSubject}, nil
		},
		Account: func(_ context.Context, subject string) (upstreamkit.AccountInfo, error) {
			return upstreamkit.AccountInfo{Subject: subject}, nil
		},
		CascadeRevoke: func(context.Context, upstreamkit.CascadeRevocationRequest) error {
			return nil
		},
		Resources: map[string]upstreamkit.ResourceHandler{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return kit.Handler()
}

func TestP4UndeclaredOversizedBodyAnswers413(t *testing.T) {
	handler := p4KitHandler(t)

	for _, path := range []string{"/oauth/token", "/oauth/revoke", "/oauth/cascade_revocation"} {
		t.Run(path, func(t *testing.T) {
			oversized := "token=" + strings.Repeat("x", oauth.MaxFormBytes+1)
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(oversized)))
			// The whole point: no declared length, so the cap is only discovered
			// while ParseForm reads. LimitFormBody's pre-check cannot see it.
			req.ContentLength = -1
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversized chunked %s = %d, want 413 (body: %s)", path, rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("refusal is not JSON: %v (%s)", err, rec.Body.String())
			}
			if body["error"] != "invalid_request" {
				t.Fatalf("refusal error = %v, want invalid_request", body["error"])
			}
		})
	}

	// Positive control: a small form still reaches the handler, so the cap is not
	// rejecting everything.
	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=nope"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a small unexpected grant = %d, want 400", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "unsupported_grant_type" {
		t.Fatalf("small form error = %v, want unsupported_grant_type", body["error"])
	}
}
