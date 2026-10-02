// S02-8 end-to-end probe: a store fault on the token-introspection path must
// answer the business plane with a 500 problem+json, not 401 invalid_token.
//
// The unit half of this contract lives in
// internal/oidchttp/zz_probe_s02_8_test.go, which pins that Handler.Introspect
// propagates a non-not-found store error and returns Active=false, nil for
// oauth.ErrTokenNotFound. This half drives the real chain — withBearer in
// internal/httpapi/middleware.go:703 — so the wire outcome is asserted, not
// inferred.
//
// Before the oidchttp fix the first subtest is RED: every store error collapsed
// to Active=false and withBearer answered 401 invalid_token.
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/oauth"
)

// s028ErrStorage is an op.Storage whose introspection lookup fails with a fixed
// error. Embedding the interface leaves every other method nil; the probe
// reaches only this one.
type s028ErrStorage struct {
	op.Storage
	err error
}

func (s s028ErrStorage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return s.err
}

// s028Handler answers introspection with err, using the same token key the test
// backend uses so an access token issued by the real plane decrypts here.
func s028Handler(t *testing.T, err error) *oidchttp.Handler {
	t.Helper()
	h, newErr := oidchttp.New(oidchttp.Config{
		Storage:       s028ErrStorage{err: err},
		CryptoKey:     testCryptoKey(),
		CryptoKeyID:   "test",
		AllowInsecure: true,
		Clients:       oauth.NewMemoryClientRegistry(),
		Registry:      oauth.DefaultRegistry(),
	})
	if newErr != nil {
		t.Fatal(newErr)
	}
	return h
}

// s028IssueAccessToken issues a real OP access token through the wired backend.
func s028IssueAccessToken(t *testing.T, env *testEnv) string {
	t.Helper()
	env.register(t, "s028-web", oauth.ClientConfidential, "s3cret", []oauth.Scope{oauth.ScopeAccountID})
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	code := env.issueCode(t, "s028-web", []oauth.Scope{oauth.ScopeAccountID}, verifier)
	tok := decodeJSON(t, env.exchange(t, "s028-web", "s3cret", code, verifier, nil))
	at, _ := tok["access_token"].(string)
	if at == "" {
		t.Fatalf("the code flow returned no access token: %v", tok)
	}
	return at
}

// s028Server mounts introspector as the business plane's bearer authenticator.
func s028Server(t *testing.T, env *testEnv, introspector TokenIntrospector) *Server {
	t.Helper()
	srv, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              env.handler,
		TokenIntrospector: introspector,
		GrantStore:        env.store,
		DeviceStore:       env.store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestProbeStoreFaultOnIntrospectionIs500(t *testing.T) {
	env := newTestEnv(t)
	at := s028IssueAccessToken(t, env)
	srv := s028Server(t, env, s028Handler(t, errors.New("connection refused")))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a store outage answered %d %q; want 500 problem+json so a client can tell a "+
			"database failure from an invalid token", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if body := decodeJSON(t, rec); body["code"] != "internal_error" {
		t.Errorf("problem code = %v, want internal_error (body=%s)", body["code"], rec.Body.String())
	}
	t.Logf("store fault -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
}

func TestProbeUnknownTokenOnIntrospectionIs401(t *testing.T) {
	env := newTestEnv(t)
	at := s028IssueAccessToken(t, env)
	srv := s028Server(t, env, s028Handler(t, oauth.ErrTokenNotFound))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown token answered %d %q; want 401 invalid_token", rec.Code, rec.Body.String())
	}
	if body := decodeJSON(t, rec); body["code"] != "invalid_token" {
		t.Errorf("problem code = %v, want invalid_token (body=%s)", body["code"], rec.Body.String())
	}
	if www := rec.Header().Get("WWW-Authenticate"); !strings.Contains(www, "invalid_token") {
		t.Errorf("WWW-Authenticate = %q, want an invalid_token challenge", www)
	}
	t.Logf("unknown token -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
}
