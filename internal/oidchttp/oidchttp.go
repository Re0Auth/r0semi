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
	"github.com/Re0Auth/r0semi/internal/oidcstore"
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
	// IntrospectionClients are client ids allowed to introspect tokens issued to
	// other clients — the resource servers this deployment trusts. A confidential
	// client may always introspect its own tokens; without an entry here nobody
	// else's are visible. Empty is the safe default.
	IntrospectionClients []string
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
	// issuer is the static authorization-server identifier, when one was
	// configured. It is what RFC 9207 `iss` carries on paths that have no request
	// to derive it from (DenyAuthorization). A dynamic-issuer deployment is a
	// development shape; it derives `iss` per request on the HTTP paths.
	issuer string
	// introspectionClients is the allowlist of client ids that may see tokens
	// issued to other clients.
	introspectionClients map[string]bool
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
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       withCoreScopes(cfg.Scopes),
		// userinfo returns only `sub` (O-3), so that is what the metadata may
		// claim. The library's default lists email/name/phone/address, which this
		// deployment can never supply.
		SupportedClaims:    []string{"sub"},
		SupportedUILocales: []language.Tag{language.English},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     10 * time.Minute,
			PollInterval: oidcstore.DefaultDevicePollInterval,
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
	allowedIntrospectors := make(map[string]bool, len(cfg.IntrospectionClients))
	for _, id := range cfg.IntrospectionClients {
		if id != "" {
			allowedIntrospectors[id] = true
		}
	}
	return &Handler{
		provider:             provider,
		clients:              cfg.Clients,
		registry:             cfg.Registry,
		consent:              cfg.Consent,
		issuer:               strings.TrimRight(cfg.Issuer, "/"),
		introspectionClients: allowedIntrospectors,
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
// deliberately out of contract (ADR-0001 O-9) and overrides the ones the library
// advertises more broadly than this deployment actually implements.
//
// Metadata a client negotiates from has to describe this server. The library
// emits its own full capability set — implicit and hybrid response types, the
// implicit and JWT-bearer grants, private_key_jwt client auth, and the full
// profile/email claim list — because it can implement them, not because every
// embedding does. This deployment implements the code flow, refresh and device
// grants, and returns only `sub`, so those are what the document may say.
func stripUnsupportedDiscoveryFields(body []byte) []byte {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	for _, key := range []string{
		"end_session_endpoint",
		"end_session_encryption_alg_values_supported",
		"registration_endpoint",
		"check_session_iframe",
		"request_object_signing_alg_values_supported",
		"request_object_encryption_alg_values_supported",
		"request_object_encryption_enc_values_supported",
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"userinfo_signing_alg_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
		"token_endpoint_auth_signing_alg_values_supported",
		"introspection_endpoint_auth_signing_alg_values_supported",
		"revocation_endpoint_auth_signing_alg_values_supported",
		"acr_values_supported",
		"display_values_supported",
	} {
		delete(payload, key)
	}
	overrides := map[string]any{
		"response_types_supported": []string{"code"},
		// RFC 9207: the authorization response carries `iss`.
		"authorization_response_iss_parameter_supported": true,
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
		"claims_supported": []string{"sub"},
		"token_endpoint_auth_methods_supported": []string{
			"none", "client_secret_basic", "client_secret_post",
		},
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic", "client_secret_post",
		},
		"revocation_endpoint_auth_methods_supported": []string{
			"none", "client_secret_basic", "client_secret_post",
		},
	}
	for key, value := range overrides {
		raw, err := json.Marshal(value)
		if err != nil {
			continue
		}
		payload[key] = raw
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
	// RFC 6749 §3.2/§5.1, RFC 7662 §2.1, RFC 7009 §2.1 and RFC 8628 §3.1 all
	// require POST for these endpoints. The library registers them without a
	// method constraint and reads r.Form, so before this guard a GET was a working
	// exchange — which put authorization codes, refresh tokens and introspection
	// tokens into URLs and access logs. Refusing the method is the fix at the
	// source; the response contract still applies to whatever POST fails.
	if endpointRequiresPOST(r.URL.Path) && r.Method != http.MethodPost {
		writeOAuthJSONError(w, http.StatusMethodNotAllowed, "invalid_request",
			"this endpoint requires POST")
		return
	}
	// RFC 6749 §3.1: request parameters must not be repeated. The library's
	// decoder takes the last value, so a parameter-smuggling attempt (a duplicate
	// client_id, redirect_uri, code or scope) silently picked one — which is how
	// an attacker can make a validation and a use see different values. Refuse
	// the whole request instead of choosing a winner.
	if dup := duplicatedParam(requestParams(r)); dup != "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
			"duplicate parameter: "+dup)
		return
	}
	// RFC 7636 §4.4/§4.6: the verifier is the same 43–128 unreserved-character
	// form as the challenge. The library only hashes and compares, so a malformed
	// verifier would otherwise be accepted whenever it happened to hash correctly.
	if r.URL.Path == "/"+pathToken && r.Method == http.MethodPost {
		form := requestParams(r)
		if form.Get("grant_type") == "authorization_code" {
			if v := form.Get("code_verifier"); v != "" && !validPKCEValue(v) {
				writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
					"code_verifier must be 43-128 unreserved characters")
				return
			}
		}
	}
	// A request that names two different clients is malformed; the library bills
	// the Authorization header and ignores the form value, so a mismatch between
	// what a pre-flight checked and what the library used is exactly the shape of
	// a bypass. This mirrors the device-endpoint rule.
	if r.Method == http.MethodPost &&
		(r.URL.Path == "/"+pathToken || r.URL.Path == "/"+pathIntrospection || r.URL.Path == "/"+pathRevocation) {
		form := requestParams(r)
		if basicID, _, hasBasic := r.BasicAuth(); hasBasic {
			if id := strings.TrimSpace(form.Get("client_id")); id != "" && id != strings.TrimSpace(basicID) {
				writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
					"client_id does not match the authenticated client")
				return
			}
		}
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

	// RFC 9207: every authorization response — success and error alike — carries
	// `iss`, so a client can tell which authorization server answered and is not
	// vulnerable to a mix-up attack. The library does not add it, so the redirect
	// the provider wrote is rewritten here. Only absolute redirects are touched:
	// the authorize endpoint's own redirect to the login/consent UI is relative
	// and is not an authorization response.
	if isAuthorizationResponse(r.URL.Path) && bw.status >= 300 && bw.status < 400 {
		if loc := bw.header.Get("Location"); loc != "" {
			bw.header.Set("Location", withIssuer(loc, h.issuerFor(r)))
		}
	}

	switch {
	case isToken:
		if bw.status == http.StatusOK {
			body = sanitizeTokenResponse(body)
		}
		// RFC 6749 §5.1 requires these on every token response, error included: a
		// cached token (or error) is a cached secret.
		bw.header.Set("Cache-Control", "no-store")
		bw.header.Set("Pragma", "no-cache")
	case r.URL.Path == "/"+pathIntrospection && bw.status == http.StatusOK:
		body = h.filterIntrospection(body, callerClientID(r))
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
	// RFC 6749 §5.2: when the client authenticated with the Authorization header
	// and that authentication failed, the 401 must carry a challenge for the
	// scheme it attempted. The library writes the 401 without one, so a standard
	// client cannot tell a bad secret from a transport failure.
	if bw.status == http.StatusUnauthorized && bw.header.Get("WWW-Authenticate") == "" &&
		(r.URL.Path == "/"+pathToken || r.URL.Path == "/"+pathIntrospection || r.URL.Path == "/"+pathRevocation) {
		bw.header.Set("WWW-Authenticate", `Basic realm="oauth"`)
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
	return oidcstore.SplitProtocolScopes(scopes)
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
		if oidcstore.StandardOIDCScope(scope) {
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
			"iss":               h.issuerFor(r),
		}
		http.Redirect(w, r, oauth.BuildRedirect(redirectURI, params), http.StatusFound)
		return true
	}
	// RFC 7636 §4.1/§4.2: the challenge is 43–128 characters from the unreserved
	// set. The library only compares hashes, so a malformed value was accepted and
	// stored; rejecting it at the entrance keeps the code record well-formed.
	if !validPKCEValue(challenge) {
		params := map[string]string{
			"error":             "invalid_request",
			"error_description": "code_challenge must be 43-128 unreserved characters",
			"state":             q.Get("state"),
			"iss":               h.issuerFor(r),
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
		params := map[string]string{"error": "invalid_scope", "state": q.Get("state"), "iss": h.issuerFor(r)}
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

	// Resolve the client the way the library will, and refuse a request that names
	// two different ones.
	//
	// The library resolves the identity as "HTTP Basic if present, else the form's
	// client_id" (pkg/op/client.go ClientIDFromRequest), and it ignores the form's
	// value outright when Basic is present. Reading the form first — which is what
	// this did — meant the pre-flight checked ONE client while the library recorded
	// ANOTHER: a confidential client registered only for account.id could put a
	// broader client's (public) id in the form, authenticate as itself with Basic,
	// pass the scope check below, and be issued a device code for a scope it was
	// never registered for. Round 4 confirmed that reaching a live access token.
	//
	// Disagreement is not a case with a right answer to prefer. A request that
	// claims two identities is malformed, and answering it by picking a side is
	// exactly how the mismatch stayed invisible.
	formClientID := strings.TrimSpace(form.Get("client_id"))
	basicClientID, _, hasBasic := r.BasicAuth()
	basicClientID = strings.TrimSpace(basicClientID)
	if hasBasic && formClientID != "" && formClientID != basicClientID {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
			"client_id does not match the authenticated client")
		return true
	}
	clientID := formClientID
	if hasBasic {
		// A confidential client authenticates with HTTP Basic instead of naming
		// itself in the body, and the library bills the Basic identity.
		clientID = basicClientID
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

// callerClientID resolves the client the way the library will: HTTP Basic if
// present, else the form's client_id. It is used for the introspection policy, so
// it must not pick a different identity than the authenticated one.
func callerClientID(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok {
		return strings.TrimSpace(id)
	}
	return strings.TrimSpace(requestParams(r).Get("client_id"))
}

// filterIntrospection hides a token's details from a client that neither owns it
// nor is an allowlisted resource server. The answer stays a valid introspection
// response with active=false rather than an error: the caller learns nothing
// about the token, and a resource server that is not allowed to see it treats it
// as unusable, which is the fail-closed direction.
func (h *Handler) filterIntrospection(body []byte, caller string) []byte {
	if caller == "" {
		return body
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	var active bool
	if raw, ok := payload["active"]; ok {
		_ = json.Unmarshal(raw, &active)
	}
	if !active {
		return body
	}
	var tokenClient string
	if raw, ok := payload["client_id"]; ok {
		_ = json.Unmarshal(raw, &tokenClient)
	}
	if tokenClient == "" || tokenClient == caller || h.introspectionClients[caller] {
		return body
	}
	return []byte(`{"active":false}`)
}

// validPKCEValue reports whether s is a well-formed RFC 7636 code challenge or
// verifier: 43 to 128 characters from ALPHA / DIGIT / "-" / "." / "_" / "~".
func validPKCEValue(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// isAuthorizationResponse reports whether path is one of the legs that returns an
// authorization response to the client: the authorize endpoint itself (for an
// error it can answer by redirect) and the provider callback that issues the code.
func isAuthorizationResponse(path string) bool {
	return path == "/"+pathAuthorize || path == "/"+pathAuthorize+"/callback"
}

// issuerFor returns the authorization-server identifier for this request. It
// prefers the configured static issuer and derives from the request host only for
// the dynamic-issuer shape used by tests and development.
func (h *Handler) issuerFor(r *http.Request) string {
	if h.issuer != "" {
		return h.issuer
	}
	if h.provider != nil {
		return strings.TrimRight(h.provider.IssuerFromRequest(r), "/")
	}
	return ""
}

// withIssuer adds the RFC 9207 `iss` parameter to an absolute redirect. A
// relative redirect is not an authorization response and is returned untouched.
func withIssuer(location, issuer string) string {
	if location == "" || issuer == "" {
		return location
	}
	u, err := url.Parse(location)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return location
	}
	q := u.Query()
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// duplicatedParam returns the name of the first parameter that appears more than
// once, or "" when every parameter is single-valued.
func duplicatedParam(values url.Values) string {
	for name, vs := range values {
		if len(vs) > 1 {
			return name
		}
	}
	return ""
}

// endpointRequiresPOST names the protocol endpoints that must only ever accept
// POST. authorize (and its callback), userinfo and keys are absent on purpose:
// they are GET endpoints by specification.
func endpointRequiresPOST(path string) bool {
	switch path {
	case "/" + pathToken, "/" + pathIntrospection, "/" + pathRevocation, "/" + pathDeviceAuthz:
		return true
	default:
		return false
	}
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
	if scopes != nil {
		if len(scopes) == 0 {
			// An explicit empty approval is "grant nothing", which must not be
			// silently reinterpreted as the full request. Omitted (nil) is how a
			// caller asks for everything.
			return "", &oauth.Error{Code: "invalid_request", Description: "an approval must grant at least one scope; omit scopes to grant the requested set"}
		}
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
	// RFC 9207 applies to denied responses too.
	redirect = withIssuer(redirect, h.issuer)
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
