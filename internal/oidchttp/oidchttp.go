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
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
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
}

// Handler is the protocol plane.
type Handler struct {
	provider *op.Provider
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
	return &Handler{provider: provider}, nil
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
		body = gateIDToken(body)
	}
	bw.flush(w, body)
}

// gateIDToken drops id_token from a token response unless the granted scope
// includes openid. The library adds it unconditionally (see
// docs/zitadel-oidc-spike.md §2); O-2 forbids that.
func gateIDToken(body []byte) []byte {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	if _, ok := payload["id_token"]; !ok {
		return body
	}
	var scope string
	if raw, ok := payload["scope"]; ok {
		_ = json.Unmarshal(raw, &scope)
	}
	for _, s := range strings.Fields(scope) {
		if s == "openid" {
			return body
		}
	}
	delete(payload, "id_token")
	out, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return out
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

type configError string

func (e configError) Error() string { return "oidchttp: " + string(e) }

func errConfig(msg string) error { return configError(msg) }
