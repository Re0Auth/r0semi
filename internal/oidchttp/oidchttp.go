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
	// Storage is the op.Storage: internal/store/postgres.OIDCStore when durable,
	// internal/store/memory.OIDCStore otherwise (ADR-0001 P4b).
	Storage op.Storage
	// CryptoKey encrypts opaque bearer tokens. 32 bytes.
	CryptoKey [32]byte
	// CryptoKeyID names the encryption key.
	CryptoKeyID string
	// RetiredTokenKeys lets a token-key rotation overlap: old keys still decrypt
	// tokens issued before the rotation, but only the current key encrypts.
	RetiredTokenKeys []RetiredTokenKey
	// Scopes is advertised in discovery (scopes_supported). Optional.
	Scopes []string
	// DeviceUserFormPath is the human verification page (default /app/device).
	DeviceUserFormPath string
	// AllowInsecure permits an http issuer. Tests set it; production must not.
	AllowInsecure bool
	// Clients and Registry are required, not optional. Every pre-flight this
	// wrapper adds — the client-scope allowance on authorize and on the device
	// endpoint, the registration lookup, PKCE for confidential clients — reads one
	// of them. Leaving them nil silently disabled all of it and handed the request
	// to the library's own defaults, which is precisely the state the pre-flights
	// exist to correct. A protocol plane without them is not a smaller plane; it is
	// an unguarded one, so it fails here instead.
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

// RetiredTokenKey is an old 32-byte token-encryption key kept for decryption
// only. It is how a token-key rotation overlaps without invalidating every live
// access token at once.
type RetiredTokenKey struct {
	ID  string
	Key [32]byte
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
	if cfg.Clients == nil {
		return nil, errConfig("Clients is required: without it the author and device scope, redirect and PKCE pre-flights are disabled")
	}
	if cfg.Registry == nil {
		return nil, errConfig("Registry is required: without it the scope catalogue cannot be checked")
	}
	if cfg.DeviceUserFormPath == "" {
		cfg.DeviceUserFormPath = "/app/device"
	}

	oconfig := &op.Config{
		CryptoKey:             cfg.CryptoKey,
		CryptoKeyId:           cfg.CryptoKeyID,
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       withCoreScopes(cfg.Scopes),
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

	// Encrypt with the current key, decrypt with it or any retired key. This is
	// the token-key half of a rotation; the signing half is in the storage's
	// KeySet.
	currentCrypto := op.NewAES256GCMCrypto(cfg.CryptoKey, cfg.CryptoKeyID)
	decrypters := make([]op.Decrypter, 0, 1+len(cfg.RetiredTokenKeys))
	decrypters = append(decrypters, currentCrypto)
	for _, r := range cfg.RetiredTokenKeys {
		decrypters = append(decrypters, op.NewAES256GCMCrypto(r.Key, r.ID))
	}
	options = append(options, op.WithCrypto(op.NewCompositeCrypto(currentCrypto, decrypters)))

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
		h.serveDiscovery(w, r, OIDCDiscoveryPath)
	case r.URL.Path == OIDCDiscoveryPath:
		h.serveDiscovery(w, r, OIDCDiscoveryPath)
	case strings.HasPrefix(r.URL.Path, "/oauth/"):
		h.serveOAuth(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveDiscovery serves a discovery document with the capabilities Re0Auth has
// decided not to offer removed. The library advertises end_session because it
// implements it; O-9 says Re0Auth does not offer RP-initiated logout, and an
// advertised endpoint that is out of contract is worse than a missing one.
func (h *Handler) serveDiscovery(w http.ResponseWriter, r *http.Request, path string) {
	clone := r.Clone(r.Context())
	clone.URL.Path = path
	bw := newBufferedWriter()
	h.provider.ServeHTTP(bw, clone)
	bw.flush(w, stripUnsupportedDiscoveryFields(bw.body.Bytes()))
}

// stripUnsupportedDiscoveryFields removes advertised capabilities that are
// deliberately out of contract (ADR-0001 O-9).
func stripUnsupportedDiscoveryFields(body []byte) []byte {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	changed := false
	for _, key := range []string{"end_session_endpoint", "end_session_encryption_alg_values_supported"} {
		if _, ok := payload[key]; ok {
			delete(payload, key)
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

// serveOAuth delegates to the provider, except for the contract points the
// library leaves open: the authorize and device-authorization pre-flights (O-7),
// and the token response's no-store headers (RFC 6749 §5.1).
//
// The method is deliberately not part of any of these conditions. The library
// registers its endpoints without a method constraint and reads `r.Form`, which
// includes a POST body on a GET's query string, so a check that only ran for one
// method let the other through with no client, redirect, PKCE or scope
// validation at all — which is how a confidential client could obtain a code
// with no `code_challenge`, and how a GET could mint a device authorization for a
// scope the client was never registered for.
func (h *Handler) serveOAuth(w http.ResponseWriter, r *http.Request) {
	if !knownOAuthPath(r.URL.Path) {
		writeOAuthJSONError(w, http.StatusNotFound, "invalid_request", "unknown OAuth endpoint")
		return
	}
	// The authorize entrance, for either method. `/oauth/authorize/callback` is the
	// library's own leg and is deliberately not included: it carries no client or
	// scope parameters, and validating it as an entrance would break the flow.
	if r.URL.Path == "/"+pathAuthorize {
		if h.validateAuthorize(w, r) {
			return
		}
	}
	// Also method-independent: see the note on this function.
	if r.URL.Path == "/"+pathDeviceAuthz {
		if h.validateDeviceAuthorization(w, r) {
			return
		}
	}

	const tokenPath = "/" + pathToken
	// Path-only, not POST-only. `op.Exchange` dispatches on the `grant_type` it
	// reads from `r.Form`, so a GET is a working code exchange; gating the
	// response contract on POST meant a GET token response skipped both the
	// `id_token` / `offline_access` sanitising (O-2, O-6) and the
	// `Cache-Control: no-store` RFC 6749 §5.1 requires on every token response.
	isToken := r.URL.Path == tokenPath

	// Everything the provider writes is buffered, so a failure it wrote without an
	// OAuth body can be normalised before it reaches the client. The protocol
	// plane's contract is that every failure parses as `{error, …}`; the library
	// answers some of them — an unauthenticated introspect or userinfo, for
	// instance — in plain text, and a client that has to parse two shapes on one
	// plane has no contract at all.
	bw := newBufferedWriter()
	h.provider.ServeHTTP(bw, r)
	body := bw.body.Bytes()

	switch {
	case isToken:
		if bw.status == http.StatusOK {
			body = sanitizeTokenResponse(body)
		}
		// RFC 6749 §5.1 requires these on every token response, error included: a
		// cached token (or error) is a cached secret.
		bw.header.Set("Cache-Control", "no-store")
		bw.header.Set("Pragma", "no-cache")
	case bw.status >= 400 && !isOAuthErrorBody(bw.header.Get("Content-Type"), body):
		body = normalizeOAuthFailure(bw, r.URL.Path)
	}
	// RFC 6750 §3: a protected resource's 401 must carry a Bearer challenge, so a
	// standard RP can tell "this token is no good, refresh it" from a transport
	// error. userinfo is that resource. The library writes no challenge, and this
	// package's own 401 writer sets a Basic one because it is for client
	// authentication — neither is right here.
	if bw.status == http.StatusUnauthorized && r.URL.Path == "/"+pathUserinfo &&
		bw.header.Get("WWW-Authenticate") == "" {
		bw.header.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	bw.flush(w, body)
}

// isOAuthErrorBody reports whether a response already satisfies the protocol
// plane's failure contract: JSON, carrying a string `error`.
func isOAuthErrorBody(contentType string, body []byte) bool {
	if !strings.Contains(contentType, "json") {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	_, ok := payload["error"].(string)
	return ok
}

// normalizeOAuthFailure rewrites a bare failure into the protocol plane's shape.
//
// The description is the status text, not the library's message: those carry
// internal type names ("ErrorType=invalid_client Parent=…"), and the wire
// contract is not the place for another package's internals. The real text is
// already in the log, which is where an operator needs it.
//
// The library's own headers — `WWW-Authenticate` above all, which RFC 6750 makes
// the challenge — are left alone.
func normalizeOAuthFailure(bw *bufferedWriter, path string) []byte {
	out, err := json.Marshal(map[string]string{
		"error":             oauthErrorCode(path, bw.status),
		"error_description": http.StatusText(bw.status),
	})
	if err != nil {
		// Unreachable for a map of strings; a static body beats an empty one.
		return []byte(`{"error":"server_error"}`)
	}
	bw.header.Set("Content-Type", "application/json")
	return out
}

// oauthErrorCode names the failure a bare status stands for.
func oauthErrorCode(path string, status int) string {
	switch {
	case status == http.StatusUnauthorized && path == "/"+pathUserinfo:
		// userinfo authenticates with a bearer token, not client credentials, and
		// RFC 6750 names its 401 `invalid_token`.
		return "invalid_token"
	case status == http.StatusUnauthorized:
		return "invalid_client"
	case status == http.StatusForbidden:
		return "access_denied"
	case status == http.StatusTooManyRequests:
		return "temporarily_unavailable"
	case status >= 500:
		return "server_error"
	default:
		return "invalid_request"
	}
}

// withCoreScopes ensures the scopes OIDC itself defines are advertised.
//
// OIDC Discovery 1.0 §3 requires a server to support `openid` and says the scopes
// defined in OpenID Core SHOULD be listed when they are supported. Leaving them
// out does not break the library, which accepts them regardless of this list —
// but it breaks relying parties: a client that negotiates from `scopes_supported`
// would never request `openid`, and so would never receive an `id_token`, while
// `offline_access` is accepted and can never be discovered. A capability that is
// accepted but not advertised is the same class of surprise as one that is
// advertised but not implemented, just with the parties swapped.
func withCoreScopes(scopes []string) []string {
	out := append([]string(nil), scopes...)
	for _, s := range []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess} {
		if !containsString(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// splitProtocolScopes partitions a scope set into the ones the catalogue
// describes and the OIDC-standard ones it deliberately does not.
//
// The catalogue is about data permissions. `openid` and `offline_access` are
// protocol flags, and `profile` / `email` / the other claim scopes are accepted
// as no-ops because the `userinfo` endpoint returns only `sub` (O-3). Both kinds
// have to be understood in two places, and they must agree: at the authorize
// entrance, where they are let past the catalogue check, and at the consent
// decision, where they must not be handed to the catalogue or dropped from the
// grant.
func splitProtocolScopes(scopes []string) (described, protocol []string) {
	for _, s := range scopes {
		if standardOIDCScope(s) {
			protocol = append(protocol, s)
			continue
		}
		described = append(described, s)
	}
	return described, protocol
}

// requestParams returns a request's parameters from wherever this method carries
// them: the query string, the form body, or both.
//
// The library reads `r.Form` for GET and POST alike, so reading only
// `r.URL.Query()` here is exactly how a POST slipped past every check. ParseForm
// caches its result, so the library's own call costs nothing and sees what this
// one read.
func requestParams(r *http.Request) url.Values {
	if err := r.ParseForm(); err != nil {
		// A malformed body is not a parameter set. Returning empty makes the
		// pre-flight answer "invalid_request" for the missing field rather than
		// letting the request through unvalidated.
		return url.Values{}
	}
	return r.Form
}

// scopeProblem returns the first requested scope this client may not ask for, or
// "" when every one of them is acceptable.
//
// The catalogue describes data permissions; the OIDC-standard scopes are protocol
// flags it deliberately does not describe, so they are let past. Everything else
// must be both known to the catalogue AND registered for the client — a scope the
// registry can describe but this client was not granted is still a scope it may
// not ask for.
func (h *Handler) scopeProblem(client oauth.Client, scopes []string) string {
	for _, scope := range scopes {
		if standardOIDCScope(scope) {
			continue
		}
		s := oauth.Scope(scope)
		if _, known := h.registry.Get(s); known && client.AllowsScope(s) {
			continue
		}
		return scope
	}
	return ""
}

// validateAuthorize is the pre-flight the library does not do.
//
// OAuth errors. A missing scope, an unknown client and an unregistered redirect
// URI are all errors the resource owner must see, so none of them may redirect.
func (h *Handler) validateAuthorize(w http.ResponseWriter, r *http.Request) bool {
	q := requestParams(r)
	clientID := q.Get("client_id")
	if clientID == "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return true
	}
	client, err := h.clients.Get(r.Context(), clientID)
	if err != nil {
		writeOAuthJSONError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return true
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !client.AllowsRedirect(redirectURI) {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "the redirect_uri is not registered for this client")
		return true
	}
	// OAuth 2.1 requires PKCE on every authorization code request, confidential
	// clients included. The engine only demands it of a public client, so the
	// requirement is enforced here rather than left to the library. The failure is
	// a redirect, not a 400 body: once redirect_uri is validated, RFC 6749
	// §4.1.2.1 says the client is informed through the redirect.
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if challenge == "" || method != "S256" {
		description := "code_challenge is required"
		if challenge != "" {
			description = "code_challenge_method must be S256"
		}
		params := map[string]string{
			"error":             "invalid_request",
			"error_description": description,
			"state":             q.Get("state"),
		}
		http.Redirect(w, r, oauth.BuildRedirect(redirectURI, params), http.StatusFound)
		return true
	}
	rawScope := q.Get("scope")
	if rawScope == "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "scope is required")
		return true
	}
	if h.scopeProblem(client, strings.Fields(rawScope)) != "" {
		params := map[string]string{"error": "invalid_scope", "state": q.Get("state")}
		http.Redirect(w, r, oauth.BuildRedirect(redirectURI, params), http.StatusFound)
		return true
	}
	return false
}

// validateDeviceAuthorization enforces the client's scope allowance on the device
// authorization request.
//
// The library stores the requested scopes verbatim — it checks the grant type and
// decodes the form, and nothing else — so without this a client registered for
// one scope can obtain any scope the catalogue knows by asking the device
// endpoint instead of the authorize endpoint. The answer is a JSON OAuth error
// rather than a redirect: this endpoint has no redirect_uri to send it to.
func (h *Handler) validateDeviceAuthorization(w http.ResponseWriter, r *http.Request) bool {
	form := requestParams(r)

	clientID := form.Get("client_id")
	if clientID == "" {
		// A confidential client authenticates with HTTP Basic instead.
		if id, _, ok := r.BasicAuth(); ok {
			clientID = id
		}
	}
	if clientID == "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return true
	}
	client, err := h.clients.Get(r.Context(), clientID)
	if err != nil {
		writeOAuthJSONError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return true
	}
	rawScope := form.Get("scope")
	if rawScope == "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "scope is required")
		return true
	}
	if bad := h.scopeProblem(client, strings.Fields(rawScope)); bad != "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_scope",
			"the scope "+bad+" is not registered for this client")
		return true
	}
	return false
}

// writeOAuthJSONError keeps the protocol plane's error format uniform even where
// the library would otherwise write plain text.
func writeOAuthJSONError(w http.ResponseWriter, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

// knownOAuthPath reports whether path is an endpoint this provider serves. It
// exists so an unknown /oauth/ path is an OAuth error rather than the library's
// plain-text 404, keeping the protocol plane's error format uniform.
func knownOAuthPath(path string) bool {
	switch path {
	case "/" + pathAuthorize,
		"/" + pathAuthorize + "/callback",
		"/" + pathToken,
		"/" + pathIntrospection,
		"/" + pathRevocation,
		"/" + pathUserinfo,
		"/" + pathKeys,
		"/" + pathDeviceAuthz:
		return true
	default:
		return false
	}
}

// standardOIDCScope reports whether scope is one the library always accepts
// without consulting the catalog. offline_access is included because Re0Auth
// treats it as a compatibility no-op (ADR-0001 O-6).
func standardOIDCScope(scope string) bool {
	switch scope {
	case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeAddress, oidc.ScopeOfflineAccess:
		return true
	default:
		return false
	}
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
		// A token this server cannot decrypt was not issued by it, so the
		// honest answer to "is this active" is no — not an error. Returning one
		// would turn a routine invalid token into a 500.
		return oauth.TokenInfo{Active: false}, nil //nolint:nilerr // unusable token means "inactive", not "error"
	}
	id, subject, ok := strings.Cut(plain, ":")
	if !ok {
		return oauth.TokenInfo{Active: false}, nil
	}
	resp := new(oidc.IntrospectionResponse)
	if err := h.provider.Storage().SetIntrospectionFromToken(ctx, resp, id, subject, ""); err != nil {
		// An unknown or expired token is reported here as an error. Fail closed
		// and answer "inactive": the routine invalid token and a storage fault
		// are not distinguishable from this call, and the safe answer to both is
		// to refuse the token.
		return oauth.TokenInfo{Active: false}, nil //nolint:nilerr // unknown token means "inactive", not "error"
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
		// The consent screen renders the catalogue, so it cannot echo a protocol
		// scope back — `openid` decides whether an id_token is issued at all and is
		// not a data permission, so it never appears there. Re-attach the protocol
		// scopes the client asked for; otherwise a decision silently downgrades an
		// OpenID authorization to a plain OAuth one, and a client that requested
		// `openid` gets a response with no id_token in it.
		_, protocol := splitProtocolScopes(requested)
		for _, s := range protocol {
			if !containsString(granted, s) {
				granted = append(granted, s)
			}
		}
	}
	// Only the scopes the catalogue describes are resolved. It is what carries
	// descriptors and explicit-consent requirements, and the protocol scopes are
	// deliberately absent from it — resolving them would reject every standard
	// relying party, whose default scope set is exactly `openid profile email`.
	described, _ := splitProtocolScopes(granted)
	descriptors, err := h.registry.Resolve(toScopeList(described), ar.GetClientID())
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
