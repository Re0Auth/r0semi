// Package idp is the r0semi OAuth *client* for external identity providers.
//
// It is the reverse of oauth: here r0semi authenticates a human
// against GitHub/Google/Discord/QQ/Microsoft. It owns no account state; it turns
// a provider callback into a canonical Identity, which internal/account then
// maps to a usr_. See docs/account-model.md.
package idp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider identifies an external identity provider.
type Provider string

const (
	GitHub    Provider = "github"
	Google    Provider = "google"
	Discord   Provider = "discord"
	QQ        Provider = "qq"
	Microsoft Provider = "microsoft"
)

// Identity is the canonical upstream identity extracted from a provider.
//
// Subject is the provider's stable `sub`/`openid`/`unionid`; it is the only
// field used to key an account. Email is display-only and never used for
// matching (see docs/account-model.md I-3).
type Identity struct {
	Provider    Provider
	Subject     string
	DisplayName string
	Email       string
	AvatarURL   string
}

// Validate reports whether the identity is usable as an account key.
func (i Identity) Validate() error {
	if i.Provider == "" {
		return errors.New("idp: identity has no provider")
	}
	if i.Subject == "" {
		return fmt.Errorf("idp: %s identity has no subject", i.Provider)
	}
	return nil
}

// definition is the static, provider-specific part of a client.
type definition struct {
	endpoint    oauth2.Endpoint
	scopes      []string
	userInfoURL string
	// issuer, when set, makes the provider OIDC: the id_token is verified
	// against the issuer's JWKS instead of trusting the userinfo endpoint.
	issuer string
	// qqMeURL and qqUserInfoURL are used only by the QQ flow, parameterized so
	// tests can point them at a fake server.
	qqMeURL       string
	qqUserInfoURL string
	mapIdentity   func(raw map[string]any) (Identity, error)
	// fetch, when set, replaces the default Bearer+JSON userinfo call. QQ needs
	// it because its profile API is JSONP and non-standard.
	fetch func(ctx context.Context, hc *http.Client, def definition, clientID string, token *oauth2.Token) (Identity, error)
}

var definitions = map[Provider]definition{
	GitHub: {
		endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
		scopes:      []string{"read:user", "user:email"},
		userInfoURL: "https://api.github.com/user",
		mapIdentity: func(raw map[string]any) (Identity, error) {
			return Identity{
				Subject:     field(raw, "id"),
				DisplayName: firstField(raw, "name", "login"),
				Email:       field(raw, "email"),
				AvatarURL:   field(raw, "avatar_url"),
			}, nil
		},
	},
	Google: {
		endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		issuer:      "https://accounts.google.com",
		scopes:      []string{"openid", "email", "profile"},
		userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
		mapIdentity: func(raw map[string]any) (Identity, error) {
			return Identity{
				Subject:     firstField(raw, "sub"),
				DisplayName: firstField(raw, "name", "email"),
				Email:       field(raw, "email"),
				AvatarURL:   field(raw, "picture"),
			}, nil
		},
	},
	Discord: {
		endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
		scopes:      []string{"identify", "email"},
		userInfoURL: "https://discord.com/api/users/@me",
		mapIdentity: func(raw map[string]any) (Identity, error) {
			id := field(raw, "id")
			avatar := ""
			if hash := field(raw, "avatar"); hash != "" && id != "" {
				avatar = "https://cdn.discordapp.com/avatars/" + id + "/" + hash + ".png"
			}
			return Identity{
				Subject:     id,
				DisplayName: firstField(raw, "global_name", "username"),
				Email:       field(raw, "email"),
				AvatarURL:   avatar,
			}, nil
		},
	},
	Microsoft: {
		endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
		issuer:      "https://login.microsoftonline.com/common/v2.0",
		scopes:      []string{"openid", "email", "profile", "offline_access"},
		userInfoURL: "https://graph.microsoft.com/oidc/userinfo",
		mapIdentity: func(raw map[string]any) (Identity, error) {
			return Identity{
				Subject:     firstField(raw, "sub"),
				DisplayName: firstField(raw, "name", "email"),
				Email:       field(raw, "email"),
				AvatarURL:   field(raw, "picture"),
			}, nil
		},
	},
	QQ: {
		endpoint: oauth2.Endpoint{
			AuthURL:  "https://graph.qq.com/oauth2.0/authorize",
			TokenURL: "https://graph.qq.com/oauth2.0/token",
		},
		scopes:        []string{"get_user_info"},
		qqMeURL:       "https://graph.qq.com/oauth2.0/me?unionid=1",
		qqUserInfoURL: "https://graph.qq.com/user/get_user_info",
		fetch:         fetchQQ,
	},
}

// providerLabels are the built-in providers' human names. A deployment may
// override one with Credentials.DisplayName; a custom provider defaults to its id.
var providerLabels = map[Provider]string{
	GitHub:    "GitHub",
	Google:    "Google",
	Discord:   "Discord",
	QQ:        "QQ",
	Microsoft: "Microsoft",
}

// Credentials configures one provider. AuthURL/TokenURL/Scopes/UserInfoURL
// override the built-in definition when non-empty, which is how tests (and
// self-hosted or proxied endpoints) are wired.
type Credentials struct {
	Provider     Provider
	ClientID     string
	ClientSecret string

	AuthURL     string
	TokenURL    string
	Scopes      []string
	UserInfoURL string
	// Issuer overrides the built-in OIDC issuer. Setting it on a non-OIDC
	// provider (GitHub, QQ) makes it OIDC; that is how tests point a provider
	// at a fake OpenID Provider.
	//
	// A provider that is not built in MUST set it: Re0Auth then speaks OIDC to
	// that issuer and discovers its endpoints, which is how a self-hosted
	// Keycloak/Authentik/Passkey provider is configured.
	Issuer string
	// DisplayName is the label a sign-in button shows. Empty falls back to the
	// built-in name, then to the provider id.
	DisplayName string
}

// RegistryConfig configures a Registry.
type RegistryConfig struct {
	// RedirectBase is the public origin, e.g. "https://re0auth.r0semi.net".
	// The callback URL is RedirectBase + CallbackPath.
	RedirectBase string
	// CallbackPath is the callback path template, with "{provider}" substituted.
	// Defaults to "/auth/{provider}/callback".
	CallbackPath string
	// HTTPClient is used for token and userinfo calls. Defaults to a client
	// with a 10s timeout.
	HTTPClient *http.Client
	// Credentials lists the providers to enable. Unlisted providers are simply
	// absent, so the frontend only offers what is configured.
	Credentials []Credentials
}

// Registry holds the configured clients.
type Registry struct {
	clients map[Provider]*Client
}

// Client drives one provider's authorization-code + PKCE flow.
type Client struct {
	provider    Provider
	displayName string
	def         definition
	issuer      string
	oauth       oauth2.Config
	http        *http.Client

	// providerMu guards lazy discovery of the issuer's document. A failed
	// discovery is not cached, so it can be retried on the next request.
	providerMu sync.Mutex
	discovered *oidc.Provider
}

// NewRegistry builds a registry from configuration.
func NewRegistry(cfg RegistryConfig) (*Registry, error) {
	if strings.TrimSpace(cfg.RedirectBase) == "" {
		return nil, errors.New("idp: RedirectBase is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	base := strings.TrimRight(cfg.RedirectBase, "/")
	callbackPath := cfg.CallbackPath
	if callbackPath == "" {
		callbackPath = "/auth/{provider}/callback"
	}

	r := &Registry{clients: make(map[Provider]*Client, len(cfg.Credentials))}
	for _, cred := range cfg.Credentials {
		if err := validateProviderName(cred.Provider); err != nil {
			return nil, err
		}
		baseDef, builtIn := definitions[cred.Provider]
		if !builtIn {
			// A custom provider must be OIDC. There is no built-in profile mapping
			// to fall back on, and inventing one for an arbitrary OAuth2 provider
			// would be a guess presented as a working login.
			if cred.Issuer == "" {
				return nil, fmt.Errorf("idp: provider %q is neither built in nor OIDC (set issuer)", cred.Provider)
			}
			baseDef = definition{
				issuer: cred.Issuer,
				scopes: []string{"openid", "email", "profile"},
			}
		}
		if cred.ClientID == "" {
			return nil, fmt.Errorf("idp: %s: ClientID is required", cred.Provider)
		}

		def := baseDef
		if cred.AuthURL != "" {
			def.endpoint.AuthURL = cred.AuthURL
		}
		if cred.TokenURL != "" {
			def.endpoint.TokenURL = cred.TokenURL
		}
		if len(cred.Scopes) > 0 {
			def.scopes = append([]string(nil), cred.Scopes...)
		}
		if cred.UserInfoURL != "" {
			def.userInfoURL = cred.UserInfoURL
		}
		if cred.Issuer != "" {
			def.issuer = cred.Issuer
		}

		label := cred.DisplayName
		if label == "" {
			label = providerLabels[cred.Provider]
		}
		if label == "" {
			label = string(cred.Provider)
		}

		r.clients[cred.Provider] = &Client{
			provider:    cred.Provider,
			displayName: label,
			def:         def,
			issuer:      def.issuer,
			oauth: oauth2.Config{
				ClientID:     cred.ClientID,
				ClientSecret: cred.ClientSecret,
				Endpoint:     def.endpoint,
				RedirectURL:  base + strings.ReplaceAll(callbackPath, "{provider}", string(cred.Provider)),
				Scopes:       def.scopes,
			},
			http: hc,
		}
	}
	return r, nil
}

// validateProviderName keeps a provider name usable as a URL path segment and as
// an account identity key. The name is operator input, but it ends up in the
// callback URL and in every stored identity, so it is checked rather than trusted.
func validateProviderName(p Provider) error {
	s := string(p)
	if s == "" {
		return errors.New("idp: provider name is required")
	}
	for i, r := range s {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if i == 0 && (r == '-' || r == '_') {
			valid = false
		}
		if !valid {
			return fmt.Errorf("idp: provider name %q must be lowercase letters, digits, '-' or '_', and start with a letter or digit", s)
		}
	}
	return nil
}

// Get returns the client for a provider.
func (r *Registry) Get(p Provider) (*Client, bool) {
	c, ok := r.clients[p]
	return c, ok
}

// Providers returns the enabled providers, sorted.
func (r *Registry) Providers() []Provider {
	out := make([]Provider, 0, len(r.clients))
	for p := range r.clients {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Provider returns the client's provider.
func (c *Client) Provider() Provider { return c.provider }

// DisplayName is the human-facing label for the sign-in button. It comes from the
// deployment's configuration, so a custom OIDC provider is named without a
// frontend release.
func (c *Client) DisplayName() string {
	if c.displayName != "" {
		return c.displayName
	}
	return string(c.provider)
}

// NewVerifier generates a PKCE code verifier for one authorization.
func (c *Client) NewVerifier() string { return oauth2.GenerateVerifier() }

// NewNonce generates an OIDC nonce for one authorization.
func (c *Client) NewNonce() string { return oauth2.GenerateVerifier() }

// AuthCodeURL builds the provider authorization URL with PKCE S256. nonce is
// required for an OIDC provider and ignored otherwise.
//
// It takes a context because a custom OIDC provider's endpoints are discovered
// lazily: a built-in provider carries them statically, but a self-hosted one is
// known only after reading its discovery document.
func (c *Client) AuthCodeURL(ctx context.Context, state, verifier, nonce string) (string, error) {
	cfg, err := c.oauthConfig(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	return cfg.AuthCodeURL(state, opts...), nil
}

// Exchange redeems an authorization code, proving possession of the verifier.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	cfg, err := c.oauthConfig(ctx)
	if err != nil {
		return nil, err
	}
	return cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
}

// oauthConfig returns the oauth2 configuration with its endpoints resolved. A
// built-in provider carries AuthURL/TokenURL statically; a custom OIDC provider
// has them discovered from its issuer.
func (c *Client) oauthConfig(ctx context.Context) (oauth2.Config, error) {
	cfg := c.oauth
	if cfg.Endpoint.AuthURL != "" && cfg.Endpoint.TokenURL != "" {
		return cfg, nil
	}
	provider, err := c.oidcProvider(ctx)
	if err != nil {
		return oauth2.Config{}, err
	}
	cfg.Endpoint = provider.Endpoint()
	return cfg, nil
}

// Identity verifies and canonicalizes the authenticated user.
//
// For an OIDC provider the id_token is authoritative: its signature is checked
// against the issuer's JWKS, and its issuer, audience and expiry must hold. nonce
// must be the value passed to AuthCodeURL for this flow, so it is never optional
// for OIDC -- a replayed id_token would otherwise be accepted. For a non-OIDC
// provider (GitHub, QQ) the userinfo endpoint is used instead.
func (c *Client) Identity(ctx context.Context, token *oauth2.Token, nonce string) (Identity, error) {
	if token == nil || token.AccessToken == "" {
		return Identity{}, errors.New("idp: token has no access token")
	}
	var (
		ident Identity
		err   error
	)
	if c.issuer != "" {
		ident, err = c.identityFromIDToken(ctx, token, nonce)
	} else {
		ident, err = c.identityFromUserInfo(ctx, token)
	}
	if err != nil {
		return Identity{}, err
	}
	ident.Provider = c.provider
	if err := ident.Validate(); err != nil {
		return Identity{}, err
	}
	return ident, nil
}

func (c *Client) identityFromUserInfo(ctx context.Context, token *oauth2.Token) (Identity, error) {
	if c.def.fetch != nil {
		return c.def.fetch(ctx, c.http, c.def, c.oauth.ClientID, token)
	}
	raw, err := getJSON(ctx, c.http, c.def.userInfoURL, token.AccessToken)
	if err != nil {
		return Identity{}, err
	}
	return c.def.mapIdentity(raw)
}

type oidcClaims struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
	Nonce   string `json:"nonce"`
}

func (c *Client) identityFromIDToken(ctx context.Context, token *oauth2.Token, nonce string) (Identity, error) {
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return Identity{}, fmt.Errorf("idp: %s: token response has no id_token", c.provider)
	}
	verifier, err := c.idTokenVerifier(ctx)
	if err != nil {
		return Identity{}, err
	}
	idToken, err := verifier.Verify(oidc.ClientContext(ctx, c.http), rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("idp: %s: verify id_token: %w", c.provider, err)
	}
	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("idp: %s: decode id_token claims: %w", c.provider, err)
	}
	// go-oidc checks signature/issuer/audience/expiry; nothing checks nonce for us.
	if nonce == "" || claims.Nonce != nonce {
		return Identity{}, fmt.Errorf("idp: %s: id_token nonce does not match the authorization request", c.provider)
	}
	if claims.Subject == "" {
		return Identity{}, fmt.Errorf("idp: %s: id_token has no sub", c.provider)
	}
	return Identity{
		Subject:     claims.Subject,
		DisplayName: cmp.Or(claims.Name, claims.Email),
		Email:       claims.Email,
		AvatarURL:   claims.Picture,
	}, nil
}

// oidcProvider discovers the issuer once and caches the result. It is used both
// to verify id_tokens and, for a custom provider, to learn the OAuth endpoints.
func (c *Client) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	c.providerMu.Lock()
	defer c.providerMu.Unlock()
	if c.discovered != nil {
		return c.discovered, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, c.http), c.issuer)
	if err != nil {
		return nil, fmt.Errorf("idp: %s: discovery failed: %w", c.provider, err)
	}
	c.discovered = provider
	return provider, nil
}

// idTokenVerifier returns a verifier for the issuer's id_tokens.
func (c *Client) idTokenVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	provider, err := c.oidcProvider(ctx)
	if err != nil {
		return nil, err
	}
	return provider.Verifier(&oidc.Config{ClientID: c.oauth.ClientID}), nil
}

// fetchQQ handles QQ Connect's non-standard profile API: the openid arrives as
// JSONP and the profile needs the consumer key and openid as query parameters.
func fetchQQ(ctx context.Context, hc *http.Client, def definition, clientID string, token *oauth2.Token) (Identity, error) {
	meBody, err := getText(ctx, hc, def.qqMeURL+"&access_token="+url.QueryEscape(token.AccessToken), "")
	if err != nil {
		return Identity{}, err
	}
	var me struct {
		OpenID  string `json:"openid"`
		UnionID string `json:"unionid"`
	}
	if err := json.Unmarshal([]byte(stripJSONP(meBody)), &me); err != nil {
		return Identity{}, fmt.Errorf("idp: qq: decode openid: %w", err)
	}
	subject := me.UnionID
	if subject == "" {
		subject = me.OpenID
	}
	if subject == "" || me.OpenID == "" {
		return Identity{}, errors.New("idp: qq: no openid returned")
	}

	infoURL := def.qqUserInfoURL + "?fmt=json" +
		"&access_token=" + url.QueryEscape(token.AccessToken) +
		"&oauth_consumer_key=" + url.QueryEscape(clientID) +
		"&openid=" + url.QueryEscape(me.OpenID)
	raw, err := getJSON(ctx, hc, infoURL, "")
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		Subject:     subject,
		DisplayName: firstField(raw, "nickname"),
		AvatarURL:   firstField(raw, "figureurl_qq_2", "figureurl_qq_1"),
	}, nil
}

// stripJSONP unwraps `callback( {...} );` into its JSON payload.
func stripJSONP(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ")")
	return strings.TrimSpace(s)
}

func getJSON(ctx context.Context, hc *http.Client, endpoint, accessToken string) (map[string]any, error) {
	body, err := getText(ctx, hc, endpoint, accessToken)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return nil, fmt.Errorf("idp: decode profile: %w", err)
	}
	return raw, nil
}

func getText(ctx context.Context, hc *http.Client, endpoint, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("idp: build request: %w", err)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("idp: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("idp: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idp: profile endpoint returned HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}

func field(raw map[string]any, key string) string {
	switch v := raw[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func firstField(raw map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := field(raw, k); v != "" {
			return v
		}
	}
	return ""
}
