// Package oidchttp mounts the OpenID Provider (github.com/zitadel/oidc) on the
// project's protocol plane. It owns the OAuth/OIDC wire paths and enforces the
// contract in docs/oidc-decision.md that the library does not: id_token is only
// ever returned when the openid scope was granted (O-2).
//
// It is deliberately a self-contained http.Handler: the business plane (/v1)
// stays where it is, and the protocol plane can be swapped without the two
// planes sharing an error format.
package oidchttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"

	"github.com/Re0Auth/r0semi/internal/authorization"
	"github.com/Re0Auth/r0semi/oauth"
)

// Paths owned by the provider. They are all under /oauth/ so the protocol plane
// can be mounted as a subtree, plus the discovery documents at the well-known
// root.
const (
	pathAuthorize     = "oauth/authorize"
	pathToken         = "oauth/token"
	pathIntrospection = "oauth/introspect"
	pathRevocation    = "oauth/revoke"
	pathUserinfo      = "oauth/userinfo"
	pathKeys          = "oauth/keys"
	pathDeviceAuthz   = "oauth/device_authorization"

	// OIDCDiscoveryPath is the OIDC Discovery 1.0 document.
	OIDCDiscoveryPath = "/.well-known/openid-configuration"
	// RFC8414Path is the OAuth 2.0 Authorization Server Metadata alias. O-1
	// requires it to serve the same content as OIDCDiscoveryPath.
	RFC8414Path = "/.well-known/oauth-authorization-server"
)

// Config wires the provider.
type Config struct {
	// Issuer is the public identifier. When empty it is derived from the
	// request Host, which is what tests and dynamic deployments want.
	Issuer string
	// Storage is the op.Storage (production: internal/store/postgres OIDCStore).
	Storage op.Storage
	// CryptoKey encrypts opaque bearer tokens. 32 bytes.
	CryptoKey [32]byte
	// CryptoKeyID names the encryption key.
	CryptoKeyID string
	// Scopes is advertised in discovery (scopes_supported). Optional.
	Scopes []string
	// DeviceUserFormPath is the human verification page (default /app/device).
	DeviceUserFormPath string
	// AllowInsecure permits an http issuer. Tests set it; production must not.
	AllowInsecure bool
	// Clients and Registry are needed by the consent interaction (client name and
	// scope descriptors). Optional for the protocol plane alone.
	Clients  oauth.ClientRegistry
	Registry *oauth.Registry
	// Consent completes an authorization request after the user decides. It is
	// the postgres OIDCStore. Optional for the protocol plane alone.
	Consent ConsentStore
}

// ConsentStore is what the consent screen needs beyond op.Storage: marking an
// auth request complete with the approved scopes.
type ConsentStore interface {
	CompleteLogin(ctx context.Context, id, subject string, scopes []string) error
}

// ValidID implements authorization.Interaction. OP auth request ids are opaque
// random strings, not the old engine's arq_ handle.
func (h *Handler) ValidID(id string) bool { return id != "" && len(id) <= 128 }

// Handler is the protocol plane.
type Handler struct {
	provider *op.Provider
	clients  oauth.ClientRegistry
	registry *oauth.Registry
	consent  ConsentStore
}

// New builds the provider.
func New(cfg Config) (*Handler, error) {
	if cfg.Storage == nil {
		return nil, errConfig("Storage is required")
	}
	if cfg.DeviceUserFormPath == "" {
		cfg.DeviceUserFormPath = "/app/device"
	}

	oconfig := &op.Config{
		CryptoKey:             cfg.CryptoKey,
		CryptoKeyId:           cfg.CryptoKeyID,
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       cfg.Scopes,
		SupportedUILocales:    []language.Tag{language.English},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     10 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: cfg.DeviceUserFormPath,
			UserCode:     op.UserCodeBase20,
		},
	}

	issuer := op.IssuerFromHost("")
	if cfg.Issuer != "" {
		issuer = op.StaticIssuer(cfg.Issuer)
	}

	options := []op.Option{
		op.WithCustomAuthEndpoint(op.NewEndpoint(pathAuthorize)),
		op.WithCustomTokenEndpoint(op.NewEndpoint(pathToken)),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint(pathIntrospection)),
		op.WithCustomRevocationEndpoint(op.NewEndpoint(pathRevocation)),
		op.WithCustomUserinfoEndpoint(op.NewEndpoint(pathUserinfo)),
		op.WithCustomKeysEndpoint(op.NewEndpoint(pathKeys)),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint(pathDeviceAuthz)),
	}
	if cfg.AllowInsecure {
		options = append(options, op.WithAllowInsecure())
	}

	provider, err := op.NewProvider(oconfig, cfg.Storage, issuer, options...)
	if err != nil {
		return nil, err
	}
	return &Handler{
		provider: provider,
		clients:  cfg.Clients,
		registry: cfg.Registry,
		consent:  cfg.Consent,
	}, nil
}

// ServeHTTP routes the protocol plane.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == RFC8414Path:
		// O-1: identical content, one source. Rewrite to the OIDC document.
		clone := r.Clone(r.Context())
		clone.URL.Path = OIDCDiscoveryPath
		h.provider.ServeHTTP(w, clone)
	case r.URL.Path == OIDCDiscoveryPath:
		h.provider.ServeHTTP(w, r)
	case strings.HasPrefix(r.URL.Path, "/oauth/"):
		h.serveOAuth(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveOAuth delegates to the provider, except that token responses are passed
// through the id_token gate.
func (h *Handler) serveOAuth(w http.ResponseWriter, r *http.Request) {
	const tokenPath = "/" + pathToken
	if r.Method != http.MethodPost || r.URL.Path != tokenPath {
		h.provider.ServeHTTP(w, r)
		return
	}

	bw := newBufferedWriter()
	h.provider.ServeHTTP(bw, r)
	body := bw.body.Bytes()
	if bw.status == http.StatusOK {
		body = sanitizeTokenResponse(body)
	}
	bw.flush(w, body)
}

// sanitizeTokenResponse enforces two contract points the library does not:
//
//   - O-2: id_token is only returned when the granted scope includes openid;
//   - O-6 (revised): offline_access is accepted but never surfaced. Re0Auth
//     always issues a refresh token, and treats offline_access as a
//     compatibility no-op rather than a scope the client can see.
func sanitizeTokenResponse(body []byte) []byte {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	var scope string
	if raw, ok := payload["scope"]; ok {
		_ = json.Unmarshal(raw, &scope)
	}
	changed := false
	if _, ok := payload["id_token"]; ok && !hasField(scope, "openid") {
		delete(payload, "id_token")
		changed = true
	}
	if clean, stripped := withoutField(scope, "offline_access"); stripped {
		if encoded, err := json.Marshal(clean); err == nil {
			payload["scope"] = encoded
			changed = true
		}
	}
	if !changed {
		return body
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return out
}

func hasField(scope, name string) bool {
	for _, s := range strings.Fields(scope) {
		if s == name {
			return true
		}
	}
	return false
}

func withoutField(scope, name string) (string, bool) {
	fields := strings.Fields(scope)
	out := make([]string, 0, len(fields))
	for _, s := range fields {
		if s != name {
			out = append(out, s)
		}
	}
	if len(out) == len(fields) {
		return scope, false
	}
	return strings.Join(out, " "), true
}

// bufferedWriter captures a response so it can be rewritten.
type bufferedWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedWriter() *bufferedWriter {
	return &bufferedWriter{header: make(http.Header), status: http.StatusOK}
}

func (b *bufferedWriter) Header() http.Header { return b.header }

func (b *bufferedWriter) WriteHeader(status int) { b.status = status }

func (b *bufferedWriter) Write(p []byte) (int, error) { return b.body.Write(p) }

func (b *bufferedWriter) flush(w http.ResponseWriter, body []byte) {
	for k, vs := range b.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	// The body may have changed length.
	w.Header().Del("Content-Length")
	w.WriteHeader(b.status)
	_, _ = w.Write(body)
}

// Introspect answers the business plane's question about a bearer token. The
// access token is an encrypted reference (AES-GCM(tokenID:subject)); decrypting
// it recovers the token ID, and the store then answers whether it is live.
// It satisfies the narrow interface internal/httpapi expects, so /v1 can accept
// tokens the OP issued without importing the library.
func (h *Handler) Introspect(ctx context.Context, token string) (oauth.TokenInfo, error) {
	plain, err := h.provider.Crypto().Decrypt(token)
	if err != nil {
		return oauth.TokenInfo{Active: false}, nil
	}
	id, subject, ok := strings.Cut(plain, ":")
	if !ok {
		return oauth.TokenInfo{Active: false}, nil
	}
	resp := new(oidc.IntrospectionResponse)
	if err := h.provider.Storage().SetIntrospectionFromToken(ctx, resp, id, subject, ""); err != nil {
		return oauth.TokenInfo{Active: false}, nil
	}
	scopes := make([]oauth.Scope, 0, len(resp.Scope))
	for _, s := range resp.Scope {
		scopes = append(scopes, oauth.Scope(s))
	}
	return oauth.TokenInfo{
		Active:    resp.Active,
		Subject:   resp.Subject,
		ClientID:  resp.ClientID,
		Scopes:    scopes,
		ExpiresAt: time.Unix(int64(resp.Expiration), 0).UTC(),
	}, nil
}

// DescribeAuthorization implements authorization.Interaction.
func (h *Handler) DescribeAuthorization(ctx context.Context, id string) (authorization.View, error) {
	ar, err := h.provider.Storage().AuthRequestByID(ctx, id)
	if err != nil {
		return authorization.View{}, err
	}
	client, err := h.clients.Get(ctx, ar.GetClientID())
	if err != nil {
		return authorization.View{}, err
	}
	return authorization.View{
		ID:         id,
		ClientID:   client.ID,
		ClientName: client.Name,
		Scopes:     toScopeList(ar.GetScopes()),
	}, nil
}

// ApproveAuthorization records the user's approval (narrowed scopes, explicit
// consent enforced) and returns the browser's next URL: the OP authorize
// callback, which issues the code and redirects to the client.
func (h *Handler) ApproveAuthorization(ctx context.Context, id, subject string, scopes, explicit []oauth.Scope) (string, error) {
	if h.consent == nil || h.registry == nil {
		return "", errConfig("ApproveAuthorization requires Consent and Registry")
	}
	ar, err := h.provider.Storage().AuthRequestByID(ctx, id)
	if err != nil {
		return "", err
	}
	requested := ar.GetScopes()
	granted := requested
	if len(scopes) > 0 {
		granted = make([]string, 0, len(scopes))
		for _, sc := range scopes {
			if !containsString(requested, sc.String()) {
				return "", &oauth.Error{Code: "invalid_scope", Description: "the decision cannot widen the requested scope"}
			}
			granted = append(granted, sc.String())
		}
	}
	descriptors, err := h.registry.Resolve(toScopeList(granted), ar.GetClientID())
	if err != nil {
		return "", err
	}
	ticked := make(map[oauth.Scope]struct{}, len(explicit))
	for _, sc := range explicit {
		ticked[sc] = struct{}{}
	}
	for _, d := range descriptors {
		if d.ExplicitConsent {
			if _, ok := ticked[d.Scope]; !ok {
				return "", &oauth.Error{Code: "access_denied", Description: "explicit consent is required for " + d.Scope.String()}
			}
		}
	}
	// ADR-0001 O-6 (revised): Re0Auth always issues a refresh token. It grants
	// offline_access implicitly rather than itemising it, because it is a
	// token-lifetime flag, not a data permission.
	granted = withOfflineAccess(granted)
	if err := h.consent.CompleteLogin(ctx, id, subject, granted); err != nil {
		return "", err
	}
	return h.provider.AuthorizationEndpoint().Relative() + "/callback?id=" + url.QueryEscape(id), nil
}

// DenyAuthorization returns the redirect that sends the browser back to the
// client with error=access_denied, and discards the request.
func (h *Handler) DenyAuthorization(ctx context.Context, id string) (string, error) {
	ar, err := h.provider.Storage().AuthRequestByID(ctx, id)
	if err != nil {
		return "", err
	}
	e := oidc.ErrAccessDenied().WithDescription("the user denied the request")
	e.State = ar.GetState()
	redirect, err := op.AuthResponseURL(ar.GetRedirectURI(), ar.GetResponseType(), ar.GetResponseMode(), e, h.provider.Encoder())
	if err != nil {
		return "", err
	}
	_ = h.provider.Storage().DeleteAuthRequest(ctx, id)
	return redirect, nil
}

func toScopeList(in []string) []oauth.Scope {
	out := make([]oauth.Scope, len(in))
	for i, s := range in {
		out[i] = oauth.Scope(s)
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// withOfflineAccess appends the OIDC offline_access scope if absent. It is how
// Re0Auth keeps its "a code flow always yields a refresh token" contract while
// still speaking OIDC (ADR-0001 O-6, revised).
func withOfflineAccess(scopes []string) []string {
	if containsString(scopes, oidc.ScopeOfflineAccess) {
		return scopes
	}
	return append(scopes, oidc.ScopeOfflineAccess)
}

type configError string

func (e configError) Error() string { return "oidchttp: " + string(e) }

func errConfig(msg string) error { return configError(msg) }
