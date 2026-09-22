package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testCriticalScope is a synthetic ExplicitConsent scope.
//
// The critical-scope path must not be pinned to a production scope's semantics:
// the mechanism and the catalog are separate concerns, and the built-in catalog
// deliberately has no critical scope today.
const testCriticalScope = Scope("test.critical.read")

// testRegistry is the default catalog plus that synthetic critical scope.
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	registry := DefaultRegistry()
	if err := registry.Register(Descriptor{
		Scope: testCriticalScope, Title: "Test critical scope",
		Risk: RiskCritical, ExplicitConsent: true,
	}); err != nil {
		t.Fatal(err)
	}
	return registry
}

func newTestAS(t *testing.T) (Service, *MemoryClientRegistry, *MemoryStore, *audit.MemoryLogger, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	clients := NewMemoryClientRegistry()
	tokens := NewMemoryStore()
	logger := audit.NewMemoryLogger()
	svc, err := NewService(clients, tokens, logger, Config{
		Issuer:          "https://auth.test",
		Scopes:          testRegistry(t),
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		CodeTTL:         time.Minute,
		Now:             clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, clients, tokens, logger, clock
}

func registerClient(t *testing.T, reg *MemoryClientRegistry, id string, typ ClientType, secret string, scopes []Scope) {
	t.Helper()
	c, err := NewClient(id, id, typ, secret, []string{"https://app.example/cb"}, scopes)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func protocolCode(t *testing.T, err error) string {
	t.Helper()
	var oe *Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v, want *oauth.Error", err)
	}
	return oe.Code
}

func TestAuthorizationCodeFlow(t *testing.T) {
	svc, clients, _, logger, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID, ScopePhigrosScore})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"
	redirect := "https://app.example/cb"

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "user-1",
		Scopes: []Scope{ScopeAccountID, ScopePhigrosScore}, State: "xyz",
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Code == "" || auth.State != "xyz" || auth.RedirectURI != redirect {
		t.Fatalf("authorize = %+v", auth)
	}

	tok, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("token = %+v", tok)
	}
	if tok.Scope != "account.id phigros.score.read" {
		t.Fatalf("scope = %q", tok.Scope)
	}

	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active || info.Subject != "user-1" || info.ClientID != "app" || len(info.Scopes) != 2 {
		t.Fatalf("introspect = %+v", info)
	}

	var actions []string
	for _, e := range logger.Events() {
		if strings.HasPrefix(e.Action, "oauth.") {
			actions = append(actions, e.Action)
		}
	}
	if len(actions) != 2 || actions[0] != "oauth.authorize" || actions[1] != "oauth.token" {
		t.Fatalf("audit actions = %v", actions)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := CodeExchangeRequest{ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier}
	if _, err := svc.Exchange(ctx, req); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Exchange(ctx, req)
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("second exchange code = %q", got)
	}
}

func TestPKCEVerificationFails(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge("right-verifier-right-verifier"), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: "wrong-verifier-wrong-verifier",
	})
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("code = %q", got)
	}
}

func TestAuthorizeRequiresPKCE(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	_, err := svc.Authorize(context.Background(), AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID},
	})
	if got := protocolCode(t, err); got != "invalid_request" {
		t.Fatalf("code = %q", got)
	}
}

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	_, err := svc.Authorize(context.Background(), AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://evil.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge("v"), CodeChallengeMethod: "S256",
	})
	if got := protocolCode(t, err); got != "invalid_request" {
		t.Fatalf("code = %q", got)
	}
}

func TestAuthorizeRejectsScopeNotAllowedForClient(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	_, err := svc.Authorize(context.Background(), AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopePhigrosScore}, CodeChallenge: pkceChallenge("v"), CodeChallengeMethod: "S256",
	})
	if got := protocolCode(t, err); got != "invalid_scope" {
		t.Fatalf("code = %q", got)
	}
}

// A scope marked ExplicitConsent must be individually consented to.
func TestCriticalScopeRequiresExplicitConsent(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{testCriticalScope})
	ctx := context.Background()
	base := AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{testCriticalScope}, CodeChallenge: pkceChallenge("v"), CodeChallengeMethod: "S256",
	}

	_, err := svc.Authorize(ctx, base)
	if got := protocolCode(t, err); got != "access_denied" {
		t.Fatalf("without explicit consent: code = %q", got)
	}

	base.Explicit = []Scope{testCriticalScope}
	if _, err := svc.Authorize(ctx, base); err != nil {
		t.Fatalf("with explicit consent: %v", err)
	}
}

func TestRefreshRotatesAndNarrows(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID, ScopePhigrosScore})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"

	auth, _ := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID, ScopePhigrosScore}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	tok, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Narrowing is allowed.
	next, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken, Scopes: []Scope{ScopeAccountID}})
	if err != nil {
		t.Fatal(err)
	}
	if next.Scope != "account.id" {
		t.Fatalf("narrowed scope = %q", next.Scope)
	}

	// The old refresh token is consumed by rotation.
	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken})
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("reused refresh code = %q", got)
	}

	// Widening is refused.
	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: next.RefreshToken, Scopes: []Scope{ScopePhigrosB30}})
	if got := protocolCode(t, err); got != "invalid_scope" {
		t.Fatalf("widen code = %q", got)
	}
}

func TestRevokeInvalidatesAccessToken(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"

	auth, _ := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	tok, _ := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})

	if err := svc.Revoke(ctx, RevokeRequest{ClientID: "app", Token: tok.AccessToken}); err != nil {
		t.Fatal(err)
	}
	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Fatal("revoked token still introspects as active")
	}
	if err := svc.Revoke(ctx, RevokeRequest{ClientID: "app", Token: "unknown"}); err != nil {
		t.Fatalf("revocation must be idempotent: %v", err)
	}
}

func TestAccessTokenExpires(t *testing.T) {
	svc, clients, _, _, clock := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"

	auth, _ := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	tok, _ := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})

	clock.advance(time.Hour + time.Second)
	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Fatal("expired access token still active")
	}
}

func TestConfidentialClientMustAuthenticate(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "conf", ClientConfidential, "s3cret", []Scope{ScopeAccountID})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "conf", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "conf", ClientSecret: "wrong", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})
	if got := protocolCode(t, err); got != "invalid_client" {
		t.Fatalf("code = %q", got)
	}
}

func TestIntrospectUnknownTokenIsInactive(t *testing.T) {
	svc, _, _, _, _ := newTestAS(t)
	info, err := svc.Introspect(context.Background(), "nope")
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Fatal("unknown token reported active")
	}
}
