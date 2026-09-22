package idp

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/Re0Auth/r0semi/internal/testoidc"
)

// oidcClient wires a Google client against a fake OpenID Provider. Google is an
// OIDC provider, so its id_token is verified against the provider's JWKS.
func oidcClient(t *testing.T, provider *testoidc.Server) *Client {
	t.Helper()
	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   provider.Client(),
		Credentials: []Credentials{{
			Provider: Google, ClientID: "cid", ClientSecret: "sec",
			AuthURL:  provider.URL + "/authorize",
			TokenURL: provider.URL + "/token",
			Issuer:   provider.URL,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get(Google)
	if !ok {
		t.Fatal("google not configured")
	}
	return c
}

func oidcContext(provider *testoidc.Server) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, provider.Client())
}

func TestOIDCVerifiesIDToken(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	c := oidcClient(t, provider)

	nonce := c.NewNonce()
	provider.SetNonce(nonce)
	ctx := oidcContext(provider)

	token, err := c.Exchange(ctx, "code-1", c.NewVerifier())
	if err != nil {
		t.Fatal(err)
	}
	ident, err := c.Identity(ctx, token, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Provider != Google || ident.Subject != "oidc-user-1" || ident.Email != "oidc@example.com" {
		t.Fatalf("identity = %+v", ident)
	}
	if ident.DisplayName != "OIDC User" {
		t.Fatalf("display name = %q", ident.DisplayName)
	}
}

// A nonce that does not match the authorization request is a replay.
func TestOIDCRejectsNonceMismatch(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	c := oidcClient(t, provider)

	provider.SetNonce("the-nonce-the-provider-put-in")
	ctx := oidcContext(provider)
	token, err := c.Exchange(ctx, "code-1", c.NewVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identity(ctx, token, "a-different-nonce"); err == nil {
		t.Fatal("accepted an id_token whose nonce did not match")
	}
}

// go-oidc must reject a token minted for a different audience or with a broken
// signature -- that is the whole point of not trusting the userinfo endpoint.
func TestOIDCRejectsForgedTokens(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	c := oidcClient(t, provider)
	ctx := oidcContext(provider)
	nonce := c.NewNonce()
	now := time.Now()

	base := map[string]any{
		"iss": provider.URL, "sub": "attacker", "aud": "cid",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": nonce,
	}
	for name, mutate := range map[string]func(m map[string]any){
		"wrong audience": func(m map[string]any) { m["aud"] = "someone-else" },
		"wrong issuer":   func(m map[string]any) { m["iss"] = "https://evil.example" },
		"expired":        func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() },
		"no subject":     func(m map[string]any) { delete(m, "sub") },
	} {
		claims := map[string]any{}
		for k, v := range base {
			claims[k] = v
		}
		mutate(claims)
		forged, err := provider.SignIDToken(claims)
		if err != nil {
			t.Fatal(err)
		}
		token := (&oauth2.Token{AccessToken: "at-1"}).WithExtra(map[string]any{"id_token": forged})
		if _, err := c.Identity(ctx, token, nonce); err == nil {
			t.Errorf("%s: accepted a forged id_token", name)
		}
	}
}

// An OIDC provider that returns no id_token must fail closed: falling back to
// userinfo would silently downgrade the verification we just paid for.
func TestOIDCRequiresIDToken(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()
	c := oidcClient(t, provider)

	token := &oauth2.Token{AccessToken: "at-1"}
	if _, err := c.Identity(oidcContext(provider), token, "nonce"); err == nil {
		t.Fatal("accepted a token response without an id_token")
	}
}

// A custom OIDC provider is configured by issuer alone: the built-in table has no
// entry for it, so its OAuth endpoints come from discovery and its label from
// configuration. This is how a self-hosted Keycloak/Authentik/Passkey provider is
// wired without a code change.
func TestCustomOIDCProviderDiscoversEndpoints(t *testing.T) {
	provider := testoidc.New()
	defer provider.Close()

	reg, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   provider.Client(),
		Credentials: []Credentials{{
			Provider: "authentik", ClientID: "cid", ClientSecret: "sec",
			Issuer: provider.URL, DisplayName: "Authentik",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := reg.Get("authentik")
	if !ok {
		t.Fatal("the custom provider was not registered")
	}
	if c.DisplayName() != "Authentik" {
		t.Fatalf("display name = %q, want the configured label", c.DisplayName())
	}

	nonce := c.NewNonce()
	provider.SetNonce(nonce)
	ctx := oidcContext(provider)

	// No AuthURL was configured, so it must have been discovered.
	authURL, err := c.AuthCodeURL(ctx, "st", c.NewVerifier(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(authURL, provider.URL+"/authorize?") {
		t.Fatalf("authorization URL = %q, want the discovered endpoint", authURL)
	}

	token, err := c.Exchange(ctx, "code-1", c.NewVerifier())
	if err != nil {
		t.Fatal(err)
	}
	ident, err := c.Identity(ctx, token, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Provider != "authentik" || ident.Subject != "oidc-user-1" {
		t.Fatalf("identity = %+v", ident)
	}
}

// A custom name without an issuer is a typo, not a provider: there is no profile
// mapping to guess and no discovery document to read.
func TestCustomOIDCProviderNeedsIssuer(t *testing.T) {
	_, err := NewRegistry(RegistryConfig{
		RedirectBase: "https://re0auth.test",
		Credentials:  []Credentials{{Provider: "authentik", ClientID: "cid"}},
	})
	if err == nil {
		t.Fatal("accepted a custom provider with no issuer")
	}
}
