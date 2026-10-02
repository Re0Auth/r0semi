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

	// Widening is refused. Checked before the replay below: the replay is now the
	// RFC 9700 §4.14.2 detection, and it revokes every generation of this token's
	// family — including `next` — so `next` would be gone by then.
	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: next.RefreshToken, Scopes: []Scope{ScopePhigrosB30}})
	if got := protocolCode(t, err); got != "invalid_scope" {
		t.Fatalf("widen code = %q", got)
	}

	// The old refresh token is consumed by rotation; presenting it again is
	// refused as a reuse (invalid_grant, the same 400 the unknown case gets).
	_, err = svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken})
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("reused refresh code = %q", got)
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

// RFC 7009 §2.1: a token may only be revoked by the client it was issued to.
// Without this check, any registered client that came by another client's token
// value could revoke it — and the refresh chain hanging off it — which is a
// denial of service on somebody else's session. G-8: the foreign attempt is
// answered with the same uniform success an unknown value gets, and revokes
// nothing, so the endpoint is not a liveness oracle.
func TestRevokeRefusesATokenIssuedToAnotherClient(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	registerClient(t, clients, "other", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"

	auth, _ := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	tok, _ := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})

	if err := svc.Revoke(ctx, RevokeRequest{ClientID: "other", Token: tok.AccessToken}); err != nil {
		t.Fatalf("a foreign revocation was not the uniform RFC 7009 success: %v", err)
	}

	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active {
		t.Fatal("the foreign revocation killed the token anyway")
	}

	// The owner still can.
	if err := svc.Revoke(ctx, RevokeRequest{ClientID: "app", Token: tok.AccessToken}); err != nil {
		t.Fatalf("the owner could not revoke its own token: %v", err)
	}
}

// TestRevokeOracleShapeIsUniform is the G-8 shape guard: revoking a foreign live
// token and revoking an unknown value must be indistinguishable from the
// caller's side — both nil, and the foreign token stays live (the mismatch
// guard). RFC 7009 §2.1 asks the server to verify, not to advertise.
func TestRevokeOracleShapeIsUniform(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	registerClient(t, clients, "other", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier"

	auth, _ := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "u",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	tok, _ := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})

	foreignErr := svc.Revoke(ctx, RevokeRequest{ClientID: "other", Token: tok.AccessToken})
	unknownErr := svc.Revoke(ctx, RevokeRequest{ClientID: "other", Token: "not-a-token-at-all"})
	if foreignErr != nil || unknownErr != nil {
		t.Fatalf("the two answers differ: foreign=%v unknown=%v", foreignErr, unknownErr)
	}
	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active {
		t.Fatal("the foreign revocation deleted the live token")
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

// KIT-4: a request that knows a code but cannot prove it owns it must be refused
// WITHOUT spending the code. Before the fix the consume happened before every
// binding check, so anybody who came by a code — no verifier, no client secret —
// could burn it, a low-cost targeted denial of service on the client that earned
// it. Each failed attempt here must leave the code redeemable by the fully
// correct request.
func TestExchangeFailedBindingDoesNotSpendTheCode(t *testing.T) {
	ctx := context.Background()
	const (
		verifier = "verifier-verifier-verifier-verifier"
		redirect = "https://app.example/cb"
	)
	cases := []struct {
		name string
		req  func(code string) CodeExchangeRequest
	}{
		{"wrong verifier", func(code string) CodeExchangeRequest {
			return CodeExchangeRequest{ClientID: "app", Code: code, RedirectURI: redirect, CodeVerifier: "wrong-verifier-wrong-verifier"}
		}},
		{"wrong redirect", func(code string) CodeExchangeRequest {
			return CodeExchangeRequest{ClientID: "app", Code: code, RedirectURI: "https://evil.example/cb", CodeVerifier: verifier}
		}},
		{"wrong client", func(code string) CodeExchangeRequest {
			return CodeExchangeRequest{ClientID: "other", Code: code, RedirectURI: redirect, CodeVerifier: verifier}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, clients, _, _, _ := newTestAS(t)
			registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
			registerClient(t, clients, "other", ClientPublic, "", []Scope{ScopeAccountID})

			auth, err := svc.Authorize(ctx, AuthorizationRequest{
				ClientID: "app", RedirectURI: redirect, Subject: "u",
				Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
			})
			if err != nil {
				t.Fatal(err)
			}

			if _, err := svc.Exchange(ctx, tc.req(auth.Code)); err == nil {
				t.Fatalf("%s: the bogus exchange succeeded", tc.name)
			} else if got := protocolCode(t, err); got != "invalid_grant" {
				t.Fatalf("%s: code = %q, want invalid_grant", tc.name, got)
			}

			// The fully correct request must still redeem it: a failed binding
			// costs the caller nothing.
			if _, err := svc.Exchange(ctx, CodeExchangeRequest{
				ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
			}); err != nil {
				t.Fatalf("%s: the failed exchange spent the code, so the rightful client was denied: %v", tc.name, err)
			}
		})
	}
}

// An expired code is refused by the pre-flight read and, like any other failed
// binding, is not consumed: the refusal is the service's judgment, not a reason
// to destroy the record.
func TestExchangeExpiredCodeIsRefusedWithoutConsuming(t *testing.T) {
	svc, clients, store, _, clock := newTestAS(t)
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

	clock.advance(time.Minute + time.Second) // CodeTTL is one minute.
	_, err = svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})
	if got := protocolCode(t, err); got != "invalid_grant" {
		t.Fatalf("expired exchange code = %q, want invalid_grant", got)
	}
	if _, err := store.GetCode(ctx, auth.Code); err != nil {
		t.Fatalf("the refusal consumed the expired code: %v", err)
	}
}

// The observability half of KIT-4: a binding failure that leaves the code intact
// must be visible in the audit log — the finding noted that, before this, the
// refusal was indistinguishable from a replay and nothing recorded who tried.
func TestExchangeBindingFailureIsAudited(t *testing.T) {
	svc, clients, _, logger, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: "https://app.example/cb", Subject: "usr_victim",
		Scopes: []Scope{ScopeAccountID}, CodeChallenge: pkceChallenge("verifier-verifier-verifier-verifier"), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: "https://app.example/cb", CodeVerifier: "wrong-verifier-wrong-verifier",
	}); err == nil {
		t.Fatal("the wrong verifier was accepted")
	}

	var seen int
	for _, e := range logger.Events() {
		if e.Action != "oauth.exchange_failed" {
			continue
		}
		seen++
		if e.Outcome != audit.OutcomeDenied {
			t.Errorf("outcome = %q, want %q", e.Outcome, audit.OutcomeDenied)
		}
		if e.Subject != "usr_victim" {
			t.Errorf("subject = %q, want the code's subject usr_victim", e.Subject)
		}
		if e.Detail["client_id"] != "app" {
			t.Errorf("client_id = %q, want the authenticated client app", e.Detail["client_id"])
		}
		if e.Provider != "oauth" {
			t.Errorf("provider = %q, want oauth", e.Provider)
		}
	}
	if seen != 1 {
		t.Fatalf("oauth.exchange_failed events = %d, want exactly 1", seen)
	}
}

// Single use is unchanged by the pre-flight read: a concurrent second exchange
// with the same, fully valid request must lose the atomic claim. Exactly one
// request may mint.
func TestConcurrentExchangeMintsOnce(t *testing.T) {
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

	const attempts = 2
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, attempts)
	toks := make([]TokenResponse, attempts)
	for i := range attempts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			toks[i], errs[i] = svc.Exchange(ctx, req)
		}(i)
	}
	close(start)
	wg.Wait()

	minted := 0
	for i, err := range errs {
		if err == nil {
			minted++
			if toks[i].AccessToken == "" || toks[i].RefreshToken == "" {
				t.Errorf("winner %d minted an empty pair: %+v", i, toks[i])
			}
			continue
		}
		if got := protocolCode(t, err); got != "invalid_grant" {
			t.Errorf("loser %d: code = %q, want invalid_grant", i, got)
		}
	}
	if minted != 1 {
		t.Fatalf("concurrent exchanges minted %d times, want exactly 1", minted)
	}
}

// DescribeAuthorization admits only a code_challenge with the shape RFC 7636 §4.2
// requires — 43 unpadded base64url characters — so a malformed one is refused at
// the authorize endpoint instead of minting a code that can never be redeemed
// (KIT-5). The residual is asserted explicitly: an upper-cased digest is
// shape-valid, so authorize accepts it and only the exchange can refuse it.
func TestDescribeAuthorizationValidatesPKCEChallengeShape(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientConfidential, "secret", []Scope{ScopeAccountID})
	ctx := context.Background()
	verifier := "shape-verifier-shape-verifier-shape"
	sum := sha256.Sum256([]byte(verifier))
	full := base64.RawURLEncoding.EncodeToString(sum[:])
	const redirect = "https://app.example/cb"
	base := AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "user-1",
		Scopes: []Scope{ScopeAccountID}, CodeChallengeMethod: "S256",
	}

	base.CodeChallenge = full
	if _, err := svc.DescribeAuthorization(ctx, base); err != nil {
		t.Fatalf("vacuity: a real 43-character S256 challenge was refused: %v", err)
	}

	for _, tc := range []struct{ name, ch string }{
		{"padded", base64.URLEncoding.EncodeToString(sum[:])},
		{"42 chars", full[:len(full)-1]},
		{"one char", "A"},
		{"empty", ""},
		{"illegal alphabet", strings.Repeat("+", 43)},
	} {
		req := base
		req.CodeChallenge = tc.ch
		_, err := svc.DescribeAuthorization(ctx, req)
		if err == nil {
			t.Errorf("%s challenge %q was accepted at authorize", tc.name, tc.ch)
			continue
		}
		if got := protocolCode(t, err); got != "invalid_request" {
			t.Errorf("%s: error code = %q, want invalid_request", tc.name, got)
		}
		t.Logf("%-17s rejected at authorize: %v", tc.name, err)
	}

	upper := strings.ToUpper(full)
	if upper == full {
		t.Fatalf("vacuity: the sample challenge has no letters to upper-case")
	}
	req := base
	req.CodeChallenge = upper
	resp, err := svc.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("an upper-cased 43-character digest was refused at authorize (%v); §4.2 leaves no way to "+
			"refuse it without the verifier, so this is the shape check over-reaching", err)
	}
	if _, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", ClientSecret: "secret", Code: resp.Code,
		RedirectURI: redirect, CodeVerifier: verifier,
	}); err == nil {
		t.Error("the exchange accepted an upper-cased digest, so the residual claim is wrong too")
	} else {
		t.Logf("residual: authorize accepted the upper-cased digest; the exchange refused it: %v", err)
	}
}

// S01-6 (P2): AuthenticateClient went through client(..., true), which only
// verifies a secret when the client is ClientConfidential. A registered public
// client therefore authenticated with any secret at all — including the empty
// one — so this "credential check" admitted any registered client and the
// cascade-revocation gate in upstreamkit (server.go handleCascadeRevocation)
// authenticated nothing. Unlike Exchange/Refresh/Revoke, where a public client is
// protected by PKCE and the code/refresh binding, here the caller's identity IS
// the check, so a non-confidential client must be refused.
func TestAuthenticateClientRejectsPublicClient(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "public", ClientPublic, "", []Scope{ScopeAccountID})
	registerClient(t, clients, "conf", ClientConfidential, "s3cret", []Scope{ScopeAccountID})
	ctx := context.Background()

	// Any secret — even the empty one — must be refused for a public client.
	for _, secret := range []string{"", "anything", "s3cret"} {
		err := svc.AuthenticateClient(ctx, "public", secret)
		if err == nil {
			t.Fatalf("AuthenticateClient(public, %q) succeeded; a public client cannot authenticate", secret)
		}
		if got := protocolCode(t, err); got != "invalid_client" {
			t.Fatalf("AuthenticateClient(public, %q) code = %q, want invalid_client", secret, got)
		}
		t.Logf("public client with secret %q rejected: %v", secret, err)
	}

	// The confidential positive case must be preserved.
	if err := svc.AuthenticateClient(ctx, "conf", "s3cret"); err != nil {
		t.Fatalf("the correct confidential credentials were refused: %v", err)
	}
	// ...and its negative case.
	err := svc.AuthenticateClient(ctx, "conf", "wrong")
	if err == nil {
		t.Fatal("a wrong secret for a confidential client was accepted")
	}
	if got := protocolCode(t, err); got != "invalid_client" {
		t.Fatalf("confidential wrong-secret code = %q, want invalid_client", got)
	}
	// An unknown client is still invalid_client.
	if err := svc.AuthenticateClient(ctx, "nobody", "s3cret"); err == nil {
		t.Fatal("an unknown client was accepted")
	} else if got := protocolCode(t, err); got != "invalid_client" {
		t.Fatalf("unknown-client code = %q, want invalid_client", got)
	}
}
