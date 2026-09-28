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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"

	"github.com/Re0Auth/r0semi/internal/authorization"
	"github.com/Re0Auth/r0semi/internal/observability"
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
	//
	// Every entry must name a CONFIDENTIAL client. Introspection is authorized by
	// client authentication alone, and a public client keeps no secret to
	// authenticate with (its id is printed in the client binary and in every
	// authorization URL), so an entry naming one would make the endpoint an
	// anonymous cross-client token reader. Such a caller is refused with 401
	// rather than trusted; see refuseIntrospectionByANonConfidentialClient.
	IntrospectionClients []string
	// Metrics, when set, records token issuance and token-endpoint failures. Nil
	// records nothing; the *observability.Metrics methods are nil-safe, so a
	// deployment that does not want them simply omits this.
	Metrics *observability.Metrics
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
	// metrics observes token issuance and token-endpoint failures. Optional; a nil
	// *observability.Metrics records nothing.
	metrics *observability.Metrics
	// discovery caches the rendered discovery documents. See serveDiscovery.
	discovery discoveryCache
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
		metrics:              cfg.Metrics,
	}, nil
}

// ServeHTTP routes the protocol plane.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ADR-0011: this service is same-origin and does not implement CORS. The
	// provider library disagrees — it reflects the request's Origin into
	// Access-Control-Allow-Origin with Allow-Credentials: true on the endpoints it
	// owns. Left in place that is an undocumented, all-origins CORS policy nobody
	// chose and nothing would notice changing, so it is filtered at this boundary:
	// one place that covers every branch, including ones added later.
	w = corsFreeWriter{ResponseWriter: w}
	switch {
	case r.URL.Path == RFC8414Path:
		// O-1: identical content, one source. Rewrite to the OIDC document.
		if !endpointMethods[RFC8414Path][r.Method] {
			writeOAuthJSONError(w, http.StatusMethodNotAllowed, "invalid_request",
				"this endpoint does not accept "+r.Method)
			return
		}
		h.serveDiscovery(w, r, OIDCDiscoveryPath)
	case r.URL.Path == OIDCDiscoveryPath:
		if !endpointMethods[OIDCDiscoveryPath][r.Method] {
			writeOAuthJSONError(w, http.StatusMethodNotAllowed, "invalid_request",
				"this endpoint does not accept "+r.Method)
			return
		}
		h.serveDiscovery(w, r, OIDCDiscoveryPath)
	case strings.HasPrefix(r.URL.Path, "/oauth/"):
		h.serveOAuth(w, r)
	default:
		// Everything reaching here is under /.well-known/ but is not one of the two
		// documents: an unknown URL, or a trailing-slash spelling of a real one.
		// http.NotFound is text/plain, which is no plane's contract, while planeOf,
		// the limiter and the metric label all call this path the protocol plane.
		// Answer in that plane's shape, as serveOAuth does for an unknown /oauth
		// path.
		writeOAuthJSONError(w, http.StatusNotFound, "invalid_request", "unknown OAuth endpoint")
	}
}

// serveDiscovery serves a discovery document with the capabilities Re0Auth has
// decided not to offer removed. The library advertises end_session because it
// implements it; O-9 says Re0Auth does not offer RP-initiated logout, and an
// advertised endpoint that is out of contract is worse than a missing one.
//
// The rendered document is cached for the life of the handler, because it cannot
// change: the issuer, the endpoints and the scope catalog are fixed at
// construction, and the library's own marshalling reads nothing else. Rendering it
// per request cost 53µs and 336 allocations on an endpoint that needs no
// credentials — an amplification anyone could ask for as often as the limiter
// allowed. Only a 200 is cached; an error response must not become the process's
// permanent answer.
func (h *Handler) serveDiscovery(w http.ResponseWriter, r *http.Request, path string) {
	if doc, ok := h.discovery.get(path); ok {
		doc.write(w)
		return
	}

	clone := r.Clone(r.Context())
	clone.URL.Path = path
	bw := acquireBufferedWriter()
	// Discovery is public metadata; clients and intermediaries may cache it, and
	// an explicit max-age is what keeps them from re-fetching it per request.
	bw.header.Set("Cache-Control", "public, max-age=300")
	h.provider.ServeHTTP(bw, clone)

	doc := discoveryDoc{
		status: bw.status,
		header: bw.header.Clone(),
		body:   stripUnsupportedDiscoveryFields(bw.body.Bytes()),
	}
	releaseBufferedWriter(bw)
	if doc.status == http.StatusOK {
		h.discovery.put(path, doc)
	}
	doc.write(w)
}

// discoveryDoc is one rendered discovery document, cached by request path.
type discoveryDoc struct {
	status int
	header http.Header
	body   []byte
}

// write sends the document. The header is added rather than assigned, so this
// composes with whatever the transport already set; Content-Length is dropped
// because the rendered body may differ in length from the library's.
func (d discoveryDoc) write(w http.ResponseWriter) {
	dst := w.Header()
	for k, vs := range d.header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	dst.Del("Content-Length")
	w.WriteHeader(d.status)
	_, _ = w.Write(d.body)
}

// discoveryCache holds the rendered discovery documents, one per path.
//
// A plain mutex rather than sync.Map: the two keys are written once each and read
// on every fetch, so the map is tiny and the contention is on the read path, where
// a mutex is the cheaper of the two.
type discoveryCache struct {
	mu sync.Mutex
	m  map[string]discoveryDoc
}

func (c *discoveryCache) get(path string) (discoveryDoc, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	doc, ok := c.m[path]
	return doc, ok
}

func (c *discoveryCache) put(path string, doc discoveryDoc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]discoveryDoc)
	}
	c.m[path] = doc
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
//
// The result never aliases body, on any path: the caller's buffer is pooled and
// rewound as soon as this returns.
func stripUnsupportedDiscoveryFields(body []byte) []byte {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return append([]byte(nil), body...)
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
		// RFC 9207: the authorization response carries `iss`. Kept true by
		// validateAuthorize offering only the response modes that can carry it.
		"authorization_response_iss_parameter_supported": true,
		// Only `query`. A form_post response is a 200 HTML form rendered by the
		// library, and the `iss` annotation below is a Location-header rewrite it
		// never reaches — so offering form_post would advertise a capability the
		// response for it contradicts. validateAuthorize refuses it (ADR-0005 §6).
		"response_modes_supported": []string{"query"},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
		"claims_supported": []string{"sub"},
		"token_endpoint_auth_methods_supported": []string{
			"none", "client_secret_basic", "client_secret_post",
		},
		// Basic only, and truthfully so: the library serves introspection through
		// ClientIDFromRequest, whose form struct carries `client_id` and an
		// assertion but no `client_secret`, so a posted secret is never read and the
		// request 401s. token and revoke genuinely accept client_secret_post; this
		// endpoint does not, and advertising it made a client that negotiated from
		// the document fail (ADR-0005 §5: the document states only real
		// capabilities).
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
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
		return append([]byte(nil), body...)
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
	// One table decides the allowed method for every endpoint (knownOAuthPath is
	// derived from it), so a wrong verb is refused with 405 before any pre-flight
	// or handler runs. The failure this prevents is a check attached to one verb:
	// RFC 6749 §3.2/§5.1, RFC 7662 §2.1, RFC 7009 §2.1 and RFC 8628 §3.1 require
	// POST on the token endpoints and the library registers them without a method
	// constraint, so before this guard a GET exchanged codes and put refresh and
	// introspection tokens into URLs and logs; the mirror image was a PUT reaching
	// an endpoint that had no method policy at all.
	if !endpointMethods[r.URL.Path][r.Method] {
		writeOAuthJSONError(w, http.StatusMethodNotAllowed, "invalid_request",
			"this endpoint does not accept "+r.Method)
		return
	}
	// The same table that decides the method decides whether the parameters may
	// arrive in the URL. The POST-only endpoints carry the request in the body, and
	// `r.Form` merges the query string into it — so a POST whose exchange lived in
	// the query put a refresh token, a client_secret or an authorization code into
	// the URL, browser history and every intermediary log. That is the exposure
	// ADR-0005 §3 closed for GET, through a different door. `authorize` is not here:
	// its parameters legitimately live in the query string.
	if methods := endpointMethods[r.URL.Path]; len(methods) == 1 && methods[http.MethodPost] && r.URL.RawQuery != "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
			"this endpoint takes its parameters in the request body, not the query string")
		return
	}
	// ONE parse, ONE parameter set, for the whole request.
	//
	// RFC 6749 §3.1: the parameters ARE the request. net/http commits `r.Form`
	// from the query string even when the body cannot be decoded, and only the
	// FIRST ParseForm call reports that error — so a body Go cannot parse made this
	// wrapper see an empty set (every gate below passed) while the library, calling
	// ParseForm a second time and getting nil, read the real query-string
	// parameters. The two sides then validated and served different requests. A
	// request whose parameters cannot be parsed is malformed on every endpoint and
	// every method, so it is refused here, once, and every gate below is handed
	// this same set: the value a gate checks is the value the library will use.
	form, ok := requestParams(r)
	if !ok {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
			"the request parameters could not be parsed")
		return
	}
	// RFC 6749 §3.1: request parameters must not be repeated. The library's
	// decoder takes the last value, so a parameter-smuggling attempt (a duplicate
	// client_id, redirect_uri, code or scope) silently picked one — which is how
	// an attacker can make a validation and a use see different values. Refuse
	// the whole request instead of choosing a winner.
	if dup := duplicatedParam(form); dup != "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
			"duplicate parameter: "+dup)
		return
	}
	// RFC 7636 §4.4/§4.6: the verifier is the same 43–128 unreserved-character
	// form as the challenge. The library only hashes and compares, so a malformed
	// verifier would otherwise be accepted whenever it happened to hash correctly.
	if r.URL.Path == "/"+pathToken && r.Method == http.MethodPost {
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
		if basicID, _, hasBasic := r.BasicAuth(); hasBasic {
			if id := strings.TrimSpace(form.Get("client_id")); id != "" && id != strings.TrimSpace(basicID) {
				writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request",
					"client_id does not match the authenticated client")
				return
			}
		}
	}
	// RFC 7662 §2.1: introspection is called by a PROTECTED RESOURCE with its own
	// credentials. A public client has none — and the storage's client
	// authentication cannot say so: `AuthorizeClientIDSecret` verifies a secret only
	// for a confidential client and answers nil ("authenticated") for every other
	// type. That is required at the token endpoint, where a public client names
	// itself and keeps no secret, but here the authentication IS the authorization
	// decision, so it is made real: a caller whose client is not confidential is
	// refused, allowlisted or not.
	//
	// The escalation this closes: a public client's id is not a credential — it is
	// printed in the client binary and in every authorization URL — so an allowlist
	// entry naming one (nothing in the config, the docs or Config said it must not)
	// turned the endpoint into an anonymous reader of ANY token's
	// `active/scope/sub/client_id/exp`, with an empty secret.
	if r.URL.Path == "/"+pathIntrospection {
		if h.refuseIntrospectionByANonConfidentialClient(w, r, form) {
			return
		}
	}
	// The authorize entrance, for either method. `/oauth/authorize/callback` is the
	// library's own leg and is deliberately not included: it carries no client or
	// scope parameters, and validating it as an entrance would break the flow.
	if r.URL.Path == "/"+pathAuthorize {
		if h.validateAuthorize(w, r, form) {
			return
		}
	}
	// Also method-independent: see the note on this function.
	if r.URL.Path == "/"+pathDeviceAuthz {
		if h.validateDeviceAuthorization(w, r, form) {
			return
		}
	}
	// RFC 6750 §2: userinfo is a protected resource and its bearer is an access
	// token. The library's bearer decoding is not that strict — pkg/op/userinfo.go
	// getTokenIDAndSubject FALLS BACK from "decrypt the token" to "verify it as a
	// signed JWT" when decryption fails, and the decrypt step of that fallback is a
	// stub that returns its input unchanged (pkg/oidc/verifier.go DecryptToken,
	// `return tokenString, nil // TODO: impl`). A compact JWS signed by this OP
	// therefore authenticates — and the `id_token` is exactly such a JWS, handed to
	// every RP by design. The access tokens this OP mints are compact JWEs (five
	// segments), so the two shapes cannot collide and the fallback can be refused
	// on sight, here, without waiting for the dependency to implement decryption.
	if r.URL.Path == "/"+pathUserinfo {
		if token := bearerOf(r, form); token != "" && isCompactJWS(token) {
			writeUserinfoInvalidToken(w, "the userinfo endpoint accepts access tokens only")
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
	bw := acquireBufferedWriter()
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

	// Cache policy per endpoint. Secrets must not be cached at all; the public
	// metadata documents are cacheable, and saying so stops every client from
	// re-fetching them on each request.
	switch r.URL.Path {
	case "/" + pathIntrospection, "/" + pathUserinfo:
		bw.header.Set("Cache-Control", "no-store")
		bw.header.Set("Pragma", "no-cache")
	case "/" + pathKeys:
		bw.header.Set("Cache-Control", "public, max-age=300")
	}
	switch {
	case isToken:
		// The grant an exchange carried, and whether it produced a token. This is
		// the protocol plane's core health signal: an issue rate and an error
		// breakdown by grant type and OAuth error code. The grant_type is
		// normalized inside observability, because it arrives from the request.
		grantType := form.Get("grant_type")
		if bw.status == http.StatusOK {
			body = sanitizeTokenResponse(body)
			h.metrics.ObserveTokenIssued(grantType)
		} else {
			h.metrics.ObserveTokenError(grantType, tokenErrorCode(body, bw.status))
		}
		// RFC 6749 §5.1 requires these on every token response, error included: a
		// cached token (or error) is a cached secret.
		bw.header.Set("Cache-Control", "no-store")
		bw.header.Set("Pragma", "no-cache")
	case r.URL.Path == "/"+pathIntrospection && bw.status == http.StatusOK:
		body = h.filterIntrospection(body, callerClientID(r, form))
	case bw.status == http.StatusForbidden && r.URL.Path == "/"+pathUserinfo:
		// The storage refused the bearer: it is expired, revoked, erased, or it
		// named an id this store never issued. The library's path for that writes
		// 403 with the bare error marshalled as `{}`, and 403 is not in RFC 6750's
		// contract for a protected resource — §3.1 makes a failed bearer
		// authentication 401 with `invalid_token`, and a client that reads 403 as
		// "authenticated but not allowed" would keep a dead token and never
		// refresh it. Nothing else writes 403 at this path.
		bw.status = http.StatusUnauthorized
		bw.header.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		bw.header.Set("Content-Type", "application/json")
		body = userinfoInvalidTokenBody
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

	// ADR-0011: the provider's CORS headers are removed at the ServeHTTP boundary
	// (corsFreeWriter), so nothing has to be done about them here.
	bw.flush(w, body)
	releaseBufferedWriter(bw)
}

// corsFreeWriter drops the CORS response headers a dependency may set.
//
// Both WriteHeader and Write strip, because a handler that never calls WriteHeader
// explicitly still commits the headers through Go's implicit 200 — filtering only
// the explicit call would leave exactly the responses nobody looked at unstripped.
type corsFreeWriter struct {
	http.ResponseWriter
}

func (w corsFreeWriter) WriteHeader(status int) {
	stripCORS(w.Header())
	w.ResponseWriter.WriteHeader(status)
}

func (w corsFreeWriter) Write(b []byte) (int, error) {
	stripCORS(w.Header())
	return w.ResponseWriter.Write(b)
}

// corsHeaders is the whole Access-Control- family a CORS implementation would own.
// Partial removal would leave a half-stated policy, which is worse than either
// answering cross-origin requests deliberately or not answering at all.
var corsHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Credentials",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Methods",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
}

// stripCORS removes any CORS response header a dependency may have set. See
// ADR-0011 for why the absence is a decision rather than an accident.
func stripCORS(h http.Header) {
	for _, name := range corsHeaders {
		h.Del(name)
	}
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

// tokenErrorCode reads the OAuth error code out of a token error body, so the
// metric can name the failure. A body that is not OAuth JSON falls back to the
// code the status alone implies.
func tokenErrorCode(body []byte, status int) string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Error != "" {
		return payload.Error
	}
	return oauthErrorCode("/"+pathToken, status)
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
		if !slices.Contains(out, s) {
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
// them: the query string, the form body, or both — and whether the request had a
// readable parameter set at all.
//
// The library reads `r.Form` for GET and POST alike, so reading only
// `r.URL.Query()` here is exactly how a POST slipped past every check. ParseForm
// caches its result, so the library's own call costs nothing and sees what this
// one read.
//
// The boolean is not decoration. ParseForm reports a body it could not decode only
// on its FIRST call: it still commits `r.Form` from the query string, and every
// later call returns nil because `r.PostForm` is non-nil by then. Answering
// `url.Values{}` for that case — which is what this did — is indistinguishable
// from "the request carried no parameters", so every gate fed by it could be
// switched off with one unparsable body while the library went on to read the real
// query-string parameters. A caller that cannot see the parameters must refuse the
// request; serveOAuth does exactly that, once, and hands the same set to every
// gate.
func requestParams(r *http.Request) (url.Values, bool) {
	if err := r.ParseForm(); err != nil {
		return nil, false
	}
	return r.Form, true
}

// requestedScopes returns every scope a request asks for: all values of the
// `scope` parameter, each split on whitespace.
//
// `Values.Get` returns the FIRST value while the library's decoder takes the LAST,
// so a gate reading one value is checking a different request than the one being
// served. serveOAuth refuses repeated parameters outright, which is the primary
// rule; reading them all is what keeps this gate correct without depending on that
// rule holding — the assumption "one value is the whole story" is precisely the
// shape that failed here before.
func requestedScopes(form url.Values) []string {
	var out []string
	for _, raw := range form["scope"] {
		out = append(out, strings.Fields(raw)...)
	}
	return out
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
// `q` is the parameter set serveOAuth parsed for this request, not a fresh read:
// checking a second parse of the same request is how "the gate saw one request and
// the library served another" became possible in the first place.
//
// OAuth errors. A missing scope, an unknown client and an unregistered redirect
// URI are all errors the resource owner must see, so none of them may redirect.
func (h *Handler) validateAuthorize(w http.ResponseWriter, r *http.Request, q url.Values) bool {
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
	// The redirect target is resolved FROM THE CLIENT: RegisteredRedirect is an
	// exact match, so it returns the request's own string whenever it is a
	// registered URI and "" otherwise. Taking the value the other way — echoing
	// q.Get("redirect_uri") after AllowsRedirect said yes — is provably the same
	// string, but it leaves the redirect target looking like request input, which
	// is what gosecurity:S5146 read as an open redirect. A value the client
	// registry chose is the one this server can defend.
	redirectURI := client.RegisteredRedirect(q.Get("redirect_uri"))
	if redirectURI == "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "the redirect_uri is not registered for this client")
		return true
	}
	// RFC 9207 + ADR-0005 §6: only a response mode that can carry `iss` is offered.
	// A form_post response is rendered by the library as a 200 HTML form, which the
	// `iss` annotation (a Location rewrite) never reaches, so accepting the request
	// would produce exactly the response the advertisement denies. It is refused
	// through the redirect, like the PKCE refusals below: the redirect_uri is
	// validated by now, so RFC 6749 §4.1.2.1 says the client is told through it.
	if responseMode := q.Get("response_mode"); responseMode != "" && responseMode != "query" {
		params := map[string]string{
			"error":             "invalid_request",
			"error_description": "response_mode " + responseMode + " is not supported; only query is offered",
			"state":             q.Get("state"),
			"iss":               h.issuerFor(r),
		}
		http.Redirect(w, r, oauth.BuildRedirect(redirectURI, params), http.StatusFound)
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
	// EVERY value of `scope`, not just the first. The library's decoder takes the
	// last value of a repeated parameter, so a gate that read one value was
	// checking a different request than the one being granted — the A1-1 escalation
	// with the validation and the use pointing at different scopes. serveOAuth
	// refuses repeats outright; reading them all is what makes this gate right even
	// if that rule is ever relaxed.
	scopes := requestedScopes(q)
	if len(scopes) == 0 {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "scope is required")
		return true
	}
	if h.scopeProblem(client, scopes) != "" {
		params := map[string]string{"error": "invalid_scope", "state": q.Get("state"), "iss": h.issuerFor(r)}
		http.Redirect(w, r, oauth.BuildRedirect(redirectURI, params), http.StatusFound)
		return true
	}
	return false
}

// validateDeviceAuthorization enforces the client's scope allowance on the device
// authorization request.
//
// `form` is the parameter set serveOAuth parsed for this request, not a fresh
// read — see validateAuthorize.
//
// The library stores the requested scopes verbatim — it checks the grant type and
// decodes the form, and nothing else — so without this a client registered for
// one scope can obtain any scope the catalogue knows by asking the device
// endpoint instead of the authorize endpoint. The answer is a JSON OAuth error
// rather than a redirect: this endpoint has no redirect_uri to send it to.
func (h *Handler) validateDeviceAuthorization(w http.ResponseWriter, r *http.Request, form url.Values) bool {

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
	// Every value of `scope`: see validateAuthorize.
	scopes := requestedScopes(form)
	if len(scopes) == 0 {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_request", "scope is required")
		return true
	}
	if bad := h.scopeProblem(client, scopes); bad != "" {
		writeOAuthJSONError(w, http.StatusBadRequest, "invalid_scope",
			"the scope "+bad+" is not registered for this client")
		return true
	}
	return false
}

// refuseIntrospectionByANonConfidentialClient refuses an introspection caller whose
// client has no secret to authenticate with.
//
// It answers on its own only when it can prove the caller cannot authenticate: an
// absent or unknown id is left to the library, which already answers 401 for both.
// What it corrects is the single case the library decides in the unsafe direction,
// because the check it makes — "return nil, i.e. authenticated, for a client that
// keeps no secret" — is right for the token endpoint and wrong here.
func (h *Handler) refuseIntrospectionByANonConfidentialClient(w http.ResponseWriter, r *http.Request, form url.Values) bool {
	id, _, _ := r.BasicAuth()
	if strings.TrimSpace(id) == "" {
		id = strings.TrimSpace(form.Get("client_id"))
	}
	if id == "" {
		return false
	}
	c, err := h.clients.Get(r.Context(), id)
	if err != nil || c.Type == oauth.ClientConfidential {
		return false
	}
	writeOAuthJSONError(w, http.StatusUnauthorized, "invalid_client",
		"introspection requires a confidential client")
	return true
}

// bearerOf resolves the bearer credential a request carries the way the library's
// own userinfo parse does (pkg/op/userinfo.go ParseUserinfoRequest): the
// Authorization header when it holds a Bearer credential, and otherwise the
// `access_token` parameter. Resolving it a different way here would mean checking
// a token the handler is not about to use — so it reads the parameter set
// serveOAuth parsed, not a second parse of its own.
func bearerOf(r *http.Request, form url.Values) string {
	if auth := r.Header.Get("Authorization"); len(auth) >= len(oidc.PrefixBearer) &&
		strings.EqualFold(auth[:len(oidc.PrefixBearer)], oidc.PrefixBearer) {
		return strings.TrimSpace(auth[len(oidc.PrefixBearer):])
	}
	return strings.TrimSpace(form.Get("access_token"))
}

// isCompactJWS reports whether s has the compact JWS shape: three segments
// separated by two dots (RFC 7515 §7.1). Every access token this OP mints is a
// compact JWE — five segments, four dots — so the shapes are disjoint, and a
// two-dot bearer at userinfo is either an id_token or something that cannot be an
// access token.
func isCompactJWS(s string) bool {
	return s != "" && strings.Count(s, ".") == 2
}

// userinfoInvalidTokenBody is the one refusal body for the userinfo endpoint. It
// names no cause: an expired token, a revoked one, one whose id this store never
// issued and a token that is not an access token at all all read the same, because
// anyone holding a string can ask and distinguishing the cases would make the
// endpoint an oracle for token validity.
var userinfoInvalidTokenBody = []byte(`{"error":"invalid_token","error_description":"the bearer is not a live access token"}`)

// writeUserinfoInvalidToken answers a refuted bearer exactly as the rewritten
// storage refusal is answered, so the endpoint has one failure shape.
func writeUserinfoInvalidToken(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	out, err := json.Marshal(map[string]string{
		"error":             "invalid_token",
		"error_description": description,
	})
	if err != nil {
		out = userinfoInvalidTokenBody
	}
	_, _ = w.Write(out)
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
// it must not pick a different identity than the authenticated one — which is why
// it is handed the parameter set serveOAuth parsed rather than reading the request
// a second time.
func callerClientID(r *http.Request, form url.Values) string {
	if id, _, ok := r.BasicAuth(); ok {
		return strings.TrimSpace(id)
	}
	return strings.TrimSpace(form.Get("client_id"))
}

// filterIntrospection hides a token's details from a client that neither owns it
// nor is an allowlisted resource server. The answer stays a valid introspection
// response with active=false rather than an error: the caller learns nothing
// about the token, and a resource server that is not allowed to see it treats it
// as unusable, which is the fail-closed direction.
//
// A token whose response names no client cannot be attributed to anybody, and an
// unattributable token is not one to describe: both cases answer inactive. The
// caller that reaches here with an empty client id is the library's own
// authentication failing to resolve a client, which cannot return 200 today —
// "cannot happen" is not the same as "cannot leak" when the branch that would
// leak is one `if` away from being reachable.
func (h *Handler) filterIntrospection(body []byte, caller string) []byte {
	if caller == "" {
		return []byte(`{"active":false}`)
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
	if tokenClient == "" {
		return []byte(`{"active":false}`)
	}
	if tokenClient == caller || h.introspectionClients[caller] {
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

// endpointMethods is the one place each protocol endpoint's allowed HTTP methods
// are declared. A method absent from its set is refused with 405 before any
// pre-flight or handler runs, so the constraint is method-complete: the failure
// mode this table exists to prevent is a check attached to one verb (a GET that
// exchanged a code, a POST that skipped PKCE) letting every other verb through.
//
// HEAD is listed wherever GET is, because HTTP requires it and net/http serves it
// from the same handler. authorize, its callback and userinfo accept GET and POST
// per their RFCs; keys is GET-only (RFC 7517 §5); the rest are POST-only.
//
// The two discovery documents are in the table too, and are the reason it is not
// just "the /oauth endpoints": they are reached by a different branch in ServeHTTP
// and so were the one pair the /oauth method policy did not cover — every verb
// answered 200 with the full document while the CHANGELOG claimed unlisted verbs
// answer 405. They are metadata reads, so GET (and HEAD) is the whole policy.
var endpointMethods = map[string]map[string]bool{
	"/" + pathAuthorize:               {http.MethodGet: true, http.MethodPost: true, http.MethodHead: true},
	"/" + pathAuthorize + "/callback": {http.MethodGet: true, http.MethodHead: true},
	"/" + pathToken:                   {http.MethodPost: true},
	"/" + pathIntrospection:           {http.MethodPost: true},
	"/" + pathRevocation:              {http.MethodPost: true},
	"/" + pathUserinfo:                {http.MethodGet: true, http.MethodPost: true, http.MethodHead: true},
	"/" + pathKeys:                    {http.MethodGet: true, http.MethodHead: true},
	"/" + pathDeviceAuthz:             {http.MethodPost: true},
	OIDCDiscoveryPath:                 {http.MethodGet: true, http.MethodHead: true},
	RFC8414Path:                       {http.MethodGet: true, http.MethodHead: true},
}

// knownOAuthPath reports whether path is an endpoint this provider serves — and
// therefore whether it has a method policy at all. Deriving it from
// endpointMethods keeps "known" and "has allowed methods" from drifting apart:
// a path in the map is both.
//
// It is consulted only for paths under /oauth (serveOAuth). The two discovery
// documents are also in the table, for their method policy, but ServeHTTP reaches
// them by their own branch before this is ever called.
func knownOAuthPath(path string) bool {
	_, ok := endpointMethods[path]
	return ok
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

// bufferedWriters reuses the capture buffers.
//
// Every protocol-plane response is buffered — the token response's id_token and
// offline_access rules (O-2, O-6), the introspection filter, the RFC 9207 `iss`
// parameter, the error-shape normalisation — so a Header and a Buffer were
// allocated per request on the endpoints that have to stay cheap. The writer never
// escapes the handler that acquired it: it is flushed synchronously and released.
var bufferedWriters = sync.Pool{
	New: func() any { return &bufferedWriter{header: make(http.Header), status: http.StatusOK} },
}

// maxPooledResponseBytes is the largest body whose buffer is kept for reuse. A
// bigger one is dropped instead, so a single large response cannot pin its
// capacity for the life of the process.
const maxPooledResponseBytes = 64 << 10

func acquireBufferedWriter() *bufferedWriter {
	bw, _ := bufferedWriters.Get().(*bufferedWriter)
	if bw == nil {
		bw = &bufferedWriter{header: make(http.Header)}
	}
	bw.reset()
	return bw
}

// release returns the writer for reuse. Anything still holding its bytes must have
// copied them: the buffer is rewound and handed to the next request.
func releaseBufferedWriter(bw *bufferedWriter) {
	if bw.body.Cap() > maxPooledResponseBytes {
		return
	}
	bw.reset()
	bufferedWriters.Put(bw)
}

func (b *bufferedWriter) reset() {
	for k := range b.header {
		delete(b.header, k)
	}
	b.body.Reset()
	b.status = http.StatusOK
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
			if !slices.Contains(requested, sc.String()) {
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
			if !slices.Contains(granted, s) {
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

// withOfflineAccess appends the OIDC offline_access scope if absent. It is how
// Re0Auth keeps its "a code flow always yields a refresh token" contract while
// still speaking OIDC (ADR-0001 O-6, revised).
func withOfflineAccess(scopes []string) []string {
	if slices.Contains(scopes, oidc.ScopeOfflineAccess) {
		return scopes
	}
	return append(scopes, oidc.ScopeOfflineAccess)
}

type configError string

func (e configError) Error() string { return "oidchttp: " + string(e) }

func errConfig(msg string) error { return configError(msg) }
