// Package httpapi is the public HTTP surface. It exposes two strictly separated
// planes:
//
//   - the protocol plane under /oauth (and /.well-known), which speaks RFC 6749
//     and renders OAuth error bodies;
//   - the business plane under /v1, which speaks JSON and renders RFC 9457
//     problem+json.
//
// Each plane has its own sub-mux, its own error writer and its own panic
// recovery, so the two formats can never leak into one another. They share only
// the request-id middleware and the security response headers, both of which are
// identical on either side and have no plane-specific shape. See docs/api-design.md
// §1 and §6.
package httpapi

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/authorization"
	"github.com/Re0Auth/r0semi/internal/compress"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/webui"
	"github.com/Re0Auth/r0semi/oauth"
)

// Config wires the HTTP surface.
type Config struct {
	// Issuer is the authorization server identifier, e.g.
	// "https://re0auth.r0semi.net".
	Issuer string
	// Resource is the protected-resource identifier. Defaults to Issuer.
	Resource string
	// ErrorBase is the prefix for RFC 9457 type URIs. Defaults to
	// "https://r0semi.dev/errors".
	ErrorBase string
	// Scopes is the scope catalog used by discovery. Defaults to the built-in.
	Scopes *oauth.Registry

	// Sessions, when set, enables the browser-session endpoints under /v1 and
	// wraps the whole tree with session loading.
	Sessions *auth.Manager
	// Accounts is required when Sessions is set.
	Accounts account.Store
	// Auth, when set, mounts the IdP login plane under /auth.
	Auth *auth.Handler
	// Authorization, when set, is the consent interaction. It is what the OP
	// handler implements; the consent screen renders through it.
	Authorization authorization.Interaction
	// ConsentPath is the frontend route /oauth/authorize redirects to. It must be a
	// route the mounted frontend actually serves. Defaults to
	// webui.BasePath + "/consent".
	ConsentPath string
	// Federation, when set, mounts the data-plane endpoints under /v1/games.
	Federation federation.Service
	// Limiter, when set, caps requests per client address. It is applied to
	// both planes.
	Limiter *ratelimit.Limiter
	// MaxInFlight caps how many requests are served concurrently. Zero disables
	// the cap. It is the inbound counterpart of the outbound bulkhead: rate
	// limiting bounds arrivals over time, this bounds work in progress.
	MaxInFlight int
	// TrustedProxies are the networks whose X-Forwarded-For header is believed
	// when attributing a request to a client. Empty — the default — trusts no
	// proxy and uses the peer address, which is the correct answer for a
	// deployment with nothing in front of it. Set it only to the addresses of
	// your own reverse proxies; a prefix that is too broad lets clients choose
	// their own rate-limit bucket.
	TrustedProxies []netip.Prefix
	// Secure declares that this issuer is reached over https. It gates the HSTS
	// header only; it is the same deployment fact that makes the session cookie
	// Secure, so a deployment sets both from one switch (`server.cookie_secure`).
	Secure bool
	// Ready, when set, is the readiness probe behind GET /readyz: it must return
	// nil when the service's dependencies are usable. Nil means always ready,
	// which is the honest answer for the in-memory deployment that has nothing to
	// reach. Liveness (GET /healthz) needs no probe.
	Ready ReadinessProbe
	// Metrics, when set, instruments every request with Prometheus golden
	// signals, labelled by plane. Nil disables instrumentation. It is separate
	// from the scrape endpoint: the metrics are recorded whether or not the
	// internal listener that exports them is configured.
	Metrics *observability.Metrics
	// Frontend, when set, is the built single-page app mounted under
	// webui.BasePath. Pass webui.FS() for an embedded build.
	Frontend fs.FS

	// OIDC is the OpenID Provider handler (internal/oidchttp): /oauth/* and both
	// discovery documents are served by it. It is required (ADR-0001 P4b): there
	// is no second engine, in production or in memory mode. TokenIntrospector,
	// GrantStore and DeviceStore are required with it, because the OP issues the
	// tokens the business plane must then accept, list and revoke.
	OIDC http.Handler
	// TokenIntrospector validates bearer tokens for the business plane. An OP
	// deployment passes the OP-backed introspector.
	TokenIntrospector TokenIntrospector
	// GrantStore and DeviceStore route the business-plane grants and device views
	// to the OP store, so the views reflect the tokens the OP actually issued.
	GrantStore  GrantStore
	DeviceStore DeviceStore

	// Admin, when set together with a non-empty Admins allowlist, mounts the
	// operator plane under /v1/admin. Both are required: an admin service with
	// nobody allowed to call it would be a door with no handle, and an allowlist
	// with no service would be a promise that does nothing.
	Admin  admin.Service
	Admins []account.UserID
	// AdminReauthWindow is how recently the operator must have authenticated for
	// a mutating admin call to be accepted. Zero disables the check. It is
	// step-up by re-login: there is no second factor to prompt for, and an
	// operator session that has been idle for hours should not be able to
	// suspend clients or erase bindings without signing in again.
	AdminReauthWindow time.Duration

	// Deleter, when set together with Sessions, enables DELETE /v1/account: the
	// signed-in account erasing itself. It is optional because a deployment can
	// legitimately not offer self-service erasure, and then the endpoint is absent
	// from both the router and the spec rather than answering 501.
	Deleter AccountDeleter

	// Audit, when set, enables the operator-plane audit read and verify endpoints.
	// It requires Sessions and a non-empty Admins allowlist, because reading the
	// audit log means reading about every account.
	Audit AuditReader
	// AuditLog, when set, is the audit log's write side, for events that happen
	// outside the auth and admin planes (identity unlink today). Optional; a nil
	// logger records nothing.
	AuditLog audit.Logger
}

// AuditReader is the audit log's read side, declared here so the HTTP layer does
// not import a storage adapter.
type AuditReader interface {
	Query(ctx context.Context, q audit.Query) (audit.Page, error)
	Verify(ctx context.Context) (audit.Verification, error)
	// Head returns the chain's current head hash. Handed to a system outside this
	// database, it is what makes a truncated tail detectable, which Verify alone
	// cannot do. See migration 0013 and docs/architecture.md §4.16.
	Head(ctx context.Context) ([]byte, error)
}

// AccountDeleter erases an account across every store. It is the
// lifecycle.Deleter's capability, declared here so the HTTP layer does not import
// the package that sequences the erasure.
type AccountDeleter interface {
	DeleteAccount(ctx context.Context, actor, subject account.UserID) (lifecycle.Result, error)
}

// TokenIntrospector resolves a bearer token to its grant. It is the business
// plane's only dependency on the authorization engine, so the engine can be
// swapped without the /v1 layer importing it.
type TokenIntrospector interface {
	Introspect(ctx context.Context, token string) (oauth.TokenInfo, error)
}

// GrantStore is the grants view's engine seam (a subset of oauth.Service).
type GrantStore interface {
	Grants(ctx context.Context, subject string) ([]oauth.Grant, error)
	RevokeGrant(ctx context.Context, subject, clientID string) error
}

// DeviceStore is the device verification page's engine seam.
type DeviceStore interface {
	DescribeDeviceAuthorization(ctx context.Context, userCode string) (oauth.DeviceAuthorization, error)
	DecideDeviceAuthorization(ctx context.Context, userCode, subject string, approve bool, scopes, explicit []oauth.Scope) error
}

// Server is the two-plane HTTP surface.
type Server struct {
	issuer       string
	resource     string
	errorBase    string
	scopes       *oauth.Registry
	sessions     *auth.Manager
	accounts     account.Store
	auth         *auth.Handler
	authInteract authorization.Interaction
	consent      string
	federate     federation.Service
	limiter      *ratelimit.Limiter
	maxInFlight  int
	secure       bool
	ready        ReadinessProbe
	metrics      *observability.Metrics
	frontend     fs.FS
	// trustedProxies is the parsed form of Config.TrustedProxies, consulted by
	// clientAddr when deriving the limiter key.
	trustedProxies []netip.Prefix
	// oidc is the protocol plane; introspector, grants and devices are the
	// OP-backed business-plane seams.
	oidc         http.Handler
	introspector TokenIntrospector
	grants       GrantStore
	devices      DeviceStore
	// adminSvc is the operator plane; nil when it is not configured.
	adminSvc admin.Service
	// adminAllowed is the allowlist of account subjects that may call it.
	adminAllowed map[account.UserID]bool
	// adminReauth is how recent the session's authentication must be for a
	// mutating admin call. Zero disables the check.
	adminReauth time.Duration
	// deleter erases the signed-in account; nil when self-service erasure is off.
	deleter AccountDeleter
	// auditReader reads the audit log for the operator plane; nil when that plane
	// is not configured.
	auditReader AuditReader
	// auditLog records events this layer owns that no other plane covers (identity
	// unlink); nil records nothing.
	auditLog audit.Logger
	// compressor negotiates and applies the response content coding.
	compressor *compress.Compressor
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.OIDC == nil {
		return nil, errors.New("httpapi: Config.OIDC is required")
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("httpapi: Config.Issuer is required")
	}
	if cfg.Scopes == nil {
		cfg.Scopes = oauth.DefaultRegistry()
	}
	if cfg.Resource == "" {
		cfg.Resource = cfg.Issuer
	}
	if cfg.ErrorBase == "" {
		cfg.ErrorBase = "https://r0semi.dev/errors"
	}
	if cfg.Auth != nil && cfg.Sessions == nil {
		return nil, errors.New("httpapi: Config.Auth requires Config.Sessions")
	}
	if cfg.Sessions != nil && cfg.Accounts == nil {
		return nil, errors.New("httpapi: Config.Sessions requires Config.Accounts")
	}
	if cfg.Authorization != nil && cfg.Sessions == nil {
		return nil, errors.New("httpapi: Config.Authorization requires Config.Sessions")
	}
	if cfg.TokenIntrospector == nil || cfg.GrantStore == nil || cfg.DeviceStore == nil {
		return nil, errors.New("httpapi: Config.TokenIntrospector, Config.GrantStore and Config.DeviceStore are required with Config.OIDC")
	}
	if cfg.ConsentPath == "" {
		// The consent screen is a frontend route, so its default is derived from
		// where the frontend is mounted rather than invented separately. A
		// deployment that moves the app must move this with it.
		cfg.ConsentPath = webui.BasePath + "/consent"
	}
	if cfg.Admin != nil && len(cfg.Admins) == 0 {
		return nil, errors.New("httpapi: Config.Admin requires a non-empty Config.Admins")
	}
	if cfg.Admin != nil && cfg.Sessions == nil {
		return nil, errors.New("httpapi: Config.Admin requires Config.Sessions")
	}
	if cfg.Deleter != nil && cfg.Sessions == nil {
		// Erasure is session-scoped: it needs a signed-in account to erase.
		return nil, errors.New("httpapi: Config.Deleter requires Config.Sessions")
	}
	if cfg.Audit != nil && cfg.Sessions == nil {
		return nil, errors.New("httpapi: Config.Audit requires Config.Sessions")
	}
	if cfg.Audit != nil && len(cfg.Admins) == 0 {
		// The audit log describes every account. Reading it is an operator act, so
		// there must be an operator allowlist to read it through.
		return nil, errors.New("httpapi: Config.Audit requires a non-empty Config.Admins")
	}
	adminAllowed := make(map[account.UserID]bool, len(cfg.Admins))
	for _, a := range cfg.Admins {
		adminAllowed[a] = true
	}
	srv := &Server{
		issuer:         strings.TrimRight(cfg.Issuer, "/"),
		resource:       strings.TrimRight(cfg.Resource, "/"),
		errorBase:      strings.TrimRight(cfg.ErrorBase, "/"),
		scopes:         cfg.Scopes,
		sessions:       cfg.Sessions,
		accounts:       cfg.Accounts,
		auth:           cfg.Auth,
		authInteract:   cfg.Authorization,
		consent:        cfg.ConsentPath,
		federate:       cfg.Federation,
		limiter:        cfg.Limiter,
		maxInFlight:    cfg.MaxInFlight,
		secure:         cfg.Secure,
		ready:          cfg.Ready,
		metrics:        cfg.Metrics,
		frontend:       cfg.Frontend,
		trustedProxies: cfg.TrustedProxies,
		// Wrapped once, here, so every protocol-plane mount is covered by the same
		// recoverer: a panic in the provider must answer as an OAuth error, not as a
		// closed connection.
		oidc:         recoverProtocol(cfg.OIDC),
		introspector: cfg.TokenIntrospector,
		grants:       cfg.GrantStore,
		devices:      cfg.DeviceStore,
		adminSvc:     cfg.Admin,
		adminAllowed: adminAllowed,
		adminReauth:  cfg.AdminReauthWindow,
		deleter:      cfg.Deleter,
		auditReader:  cfg.Audit,
		auditLog:     cfg.AuditLog,
	}
	compressor, err := compress.New(compress.Config{
		Encodings: compress.Default(),
		// The protocol plane stays uncompressed: its responses are tiny, must not
		// be cached, and a token response must never be transformed (BREACH). The
		// business plane and the frontend assets are where compression pays.
		//
		// The predicate is the middleware's own planeOf rather than a second prefix
		// test. Two tests for one question is how /.well-known/* was eligible for
		// compression here while the plane split called it protocol plane — so a
		// client refusing every coding got a 406 rendered by the business writer on
		// an OIDC discovery URL.
		Eligible: func(r *http.Request) bool {
			return planeOf(r.URL.Path) != planeProtocol
		},
		OnNotAcceptable: func(w http.ResponseWriter, r *http.Request) {
			// The compression layer can answer before any handler runs, so it
			// has to choose the shape itself — by the same planeOf predicate the
			// rest of the service uses. A browser navigation that refuses every
			// content coding must not be handed a business problem+json object.
			switch planeOf(r.URL.Path) {
			case planeBusiness:
				srv.writeProblem(w, r, http.StatusNotAcceptable, "not_acceptable", "no acceptable content coding")
			case planeProtocol:
				// Not reachable today (the protocol plane is not eligible for
				// compression), but the shape is stated rather than inherited
				// so a future change to Eligible cannot leak the wrong body.
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusNotAcceptable)
				_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"no acceptable content coding"}`))
			default:
				http.Error(w, "no acceptable content coding", http.StatusNotAcceptable)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	srv.compressor = compressor
	return srv, nil
}

// route is one documented endpoint.
//
// The documented surface is declared as data rather than as a run of
// mux.HandleFunc calls for one reason: docs/openapi.yaml has to be checkable
// against it, in both directions. A spec that documents an endpoint which does
// not exist is worse than no spec, and one that misses an endpoint is a client
// waiting to be surprised. A test asserts the two sets are equal, so adding a
// route without documenting it fails the build.
type route struct {
	Method  string
	Pattern string
	Handler http.HandlerFunc
}

// specRoutes returns every endpoint docs/openapi.yaml is required to describe.
// Since the device verification endpoint moved under /v1, that set is exactly the
// business plane: every JSON endpoint this service has.
//
// Conditional entries mirror the mount conditions exactly: an endpoint appears
// here under the same circumstances it is reachable.
func (s *Server) specRoutes() []route {
	routes := []route{
		{http.MethodGet, "/v1/me", s.withBearer(s.handleMe)},
	}
	if s.sessions != nil {
		routes = append(routes,
			route{http.MethodGet, "/v1/sessions/current", s.handleCurrentSession},
			route{http.MethodPost, "/v1/sessions/sign_out", s.handleSignOut},
			route{http.MethodPost, "/v1/device/decision", s.handleDeviceDecision},
			// The verification page's data source. It is a business-plane endpoint
			// rather than a root one because it answers JSON with problem+json errors,
			// and "every JSON endpoint lives under /v1" is worth keeping literally
			// true. The human page it feeds is a frontend route, and the URI RFC 8628
			// hands to the user comes from oauth.Config.VerificationPath.
			route{http.MethodGet, "/v1/device/verification", s.handleDeviceVerification},
		)
	}
	if s.sessions != nil && s.authInteract != nil {
		routes = append(routes,
			route{http.MethodGet, "/v1/authorization_requests/{id}", s.handleGetAuthorizationRequest},
			route{http.MethodPost, "/v1/authorization_requests/{id}/decision", s.handleAuthorizationDecision},
		)
	}
	if s.sessions != nil {
		// The grants view. Session-scoped rather than bearer-scoped: a client
		// asking with its own token would learn about the user's other clients,
		// which is neither useful to it nor agreed to by the user.
		routes = append(routes,
			route{http.MethodGet, "/v1/grants", s.handleListGrants},
			route{http.MethodDelete, "/v1/grants/{client_id}", s.handleRevokeGrant},
		)
		// Identity management. Also session-scoped, and for the same reason: the
		// set of ways an account can sign in is not a client's business.
		routes = append(routes,
			route{http.MethodGet, "/v1/identities", s.handleListIdentities},
			route{http.MethodDelete, "/v1/identities/{id}", s.handleUnlinkIdentity},
		)
	}
	if s.sessions != nil && s.deleter != nil {
		// Account erasure. Session-scoped: only the signed-in account can erase
		// itself, and it is a write, so it carries the CSRF token and an
		// acknowledgement. The operator-plane Kill Switch is a different,
		// reversible-in-intent action and does not erase.
		routes = append(routes,
			route{http.MethodDelete, "/v1/account", s.handleDeleteAccount},
		)
	}
	if s.sessions != nil {
		// Account export. Read-only and session-scoped: it aggregates the same
		// views the grants, identities and bindings lists already return, with no
		// credentials in it.
		routes = append(routes,
			route{http.MethodGet, "/v1/account/export", s.handleExportAccount},
		)
	}
	if s.federate != nil && s.sessions != nil {
		// The bindings view, the same shape of thing as grants: what is connected
		// to this account, and the way to disconnect it.
		routes = append(routes,
			route{http.MethodGet, "/v1/bindings", s.handleListBindings},
			route{http.MethodDelete, "/v1/bindings/{game}/{source}", s.handleUnbind},
			route{http.MethodPost, "/v1/bindings/{game}/{source}/cascade_revocation", s.handleCascadeRevoke},
		)
	}
	if s.auth != nil {
		// Public: a frontend has to be able to learn how to obtain a session
		// before it has one.
		routes = append(routes, route{http.MethodGet, "/v1/idp/providers", s.handleIDPProviders})
	}
	if s.federate != nil {
		routes = append(routes,
			route{http.MethodGet, "/v1/sources", s.handleAllSources},
			route{http.MethodGet, "/v1/games/{game}/sources", s.handleGameSources},
			route{http.MethodGet, "/v1/games/{game}/sources/{source}/raw/{path...}", s.withBearer(s.handleGameRaw)},
			route{http.MethodGet, "/v1/games/{game}/{resource}", s.withBearer(s.handleGameResource)},
		)
	}
	if s.adminSvc != nil {
		// The operator plane. Its routes live under /v1 so they share the JSON
		// and problem+json conventions, and they are documented like every other
		// endpoint: an operator API that is not in the spec is a client waiting to
		// be surprised just the same.
		routes = append(routes,
			route{http.MethodGet, "/v1/admin/clients", s.handleAdminListClients},
			route{http.MethodPost, "/v1/admin/clients", s.handleAdminRegisterClient},
			route{http.MethodPost, "/v1/admin/clients/{client_id}/suspend", s.handleAdminSuspendClient},
			route{http.MethodPost, "/v1/admin/clients/{client_id}/activate", s.handleAdminActivateClient},
			route{http.MethodPost, "/v1/admin/clients/{client_id}/rotate_secret", s.handleAdminRotateClientSecret},
			route{http.MethodDelete, "/v1/admin/clients/{client_id}", s.handleAdminDeleteClient},
			route{http.MethodPost, "/v1/admin/kill_switch", s.handleAdminKillSwitch},
		)
	}
	if s.auditReader != nil {
		// The audit log's read side. Separate from the client-management routes
		// above because it is a different capability — a deployment can run the
		// operator plane without exposing the log, and vice versa is not true: this
		// needs the same allowlist, which `New` enforces.
		routes = append(routes,
			route{http.MethodGet, "/v1/admin/audit", s.handleAdminAudit},
			route{http.MethodGet, "/v1/admin/audit/verify", s.handleAdminAuditVerify},
			route{http.MethodGet, "/v1/admin/audit/head", s.handleAdminAuditHead},
		)
	}
	return routes
}
func (s *Server) Handler() http.Handler {
	root := http.NewServeMux()
	// Operational probes. They belong to no plane — an orchestrator reads the
	// status code, not the body — and are registered before the mounts below so
	// no later pattern can shadow them. They are exempt from the limiter; see
	// isProbe.
	root.HandleFunc("GET /healthz", s.handleHealth)
	root.HandleFunc("GET /readyz", s.handleReady)
	// The OP owns the protocol plane and both discovery documents. It is always
	// present (ADR-0001 P4b).
	root.Handle("GET /.well-known/oauth-authorization-server", s.oidc)
	root.Handle("GET /.well-known/openid-configuration", s.oidc)
	root.Handle("/oauth/", s.oidc)
	root.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleResourceMetadata)
	// The rest of the namespace, so an unknown path or a wrong method under
	// /.well-known answers in the protocol plane rather than falling through to the
	// business catch-all. More specific patterns still win, so the three documents
	// above keep their own handlers; this only covers what they do not.
	//
	// It matters because the plane split used to be decided by two different prefix
	// tests, one of which called /.well-known/* business plane — which is how an
	// OIDC discovery URL could answer 404 with a problem+json body.
	root.Handle("/.well-known/", s.oidc)
	root.Handle("/v1/", s.businessPlane())
	if s.auth != nil || s.bindEnabled() {
		authMux := http.NewServeMux()
		if s.auth != nil {
			s.auth.Register(authMux)
		}
		if s.bindEnabled() {
			authMux.HandleFunc("GET /auth/upstream/{game}/{source}/callback", s.handleBindCallback)
		}
		root.Handle("/auth/", authMux)
	}
	if s.bindEnabled() {
		root.HandleFunc("GET /bind", s.handleBindStart)
	}
	if s.frontend != nil {
		// Pinned to its own prefix on purpose: this handler answers unknown paths
		// with the SPA shell, so mounted at "/" it would turn every API 404 into
		// HTML. See webui.Handler.
		root.Handle(webui.BasePath+"/", webui.Handler(s.frontend))

		// The exact root, so the catch-all below is not shadowed.
		//
		// This is not decoration. The login plane's return_to defaults to "/", so
		// without it a user who signs in successfully is delivered to a 404 — the
		// one page guaranteed to make them think the login failed. A deployment
		// with no frontend keeps the 404, which is correct: there is no page there.
		//
		// The query is carried through, because it is where a failed login's reason
		// lives (`/?error=access_denied`). Dropping it would return the user to the
		// anonymous page with no explanation for a login they just watched fail.
		root.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
			target := webui.BasePath + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusFound)
		})
	}
	root.HandleFunc("/", s.handleNotFound)

	// Order, outermost first:
	//
	//	0. trace context    -- adopt or generate a trace id, so it exists for
	//	                       every log line including rejections.
	//	1. request id       -- so even a rejected request can be quoted to an
	//	                       operator. A 429 is the response most likely to be
	//	                       reported, and it never reaches a handler.
	//	2. access log       -- inside the request id, so it logs the id the caller
	//	                       was given; outside the recoverer, so a panic is
	//	                       logged as the 500 it becomes rather than as a
	//	                       request that never finished.
	//	3. panic recovery   -- so a crash answers in its plane's format.
	//	4. security headers -- including on those rejections, so a failure is
	//	                       still not frameable and still leaks no URL.
	//	5. compression      -- so every eligible response can be negotiated.
	//	6. in-flight cap    -- concurrency is the harder bound; answer before a
	//	                       rate-limited request spends a token.
	//	7. the limiter      -- shed load before sessions or handlers do any work.
	//	8. the body limit   -- cap what a handler can be made to read, which is a
	//	                       different question from how often it may ask.
	//	9. session loading  -- wraps the whole tree; /auth and /v1 both need it.
	//
	// The headers sit *outside* compression deliberately. The compressor can
	// answer on its own — a client that refuses every coding gets a 406 without
	// `next` ever running — so anything inside it is skipped for exactly that
	// response. That response is also the one whose input the caller fully
	// controls, which makes it the last one in the service that should go out
	// without nosniff, a referrer policy and a framing policy.
	//
	// The cost of the swap is that the limiter's 429 is no longer compressed. It
	// never really was: the body is well under compress.DefaultMinSize.
	var h http.Handler = root
	if s.sessions != nil {
		h = s.sessions.LoadAndSave(h)
	}
	h = s.withBodyLimit(h)
	h = s.withRateLimit(h)
	// In-flight wraps the limiter: concurrency is the harder bound, so it answers
	// before a rate-limited request spends a token.
	h = s.withInFlightLimit(h)
	if s.compressor != nil {
		h = s.compressor.Handler(h)
	}
	h = s.withSecurityHeaders(h)
	out := withTrace(withRequestID(s.withAccessLog(recoverBrowser(h))))
	if s.metrics != nil {
		// Installed outermost, so a request that never reaches a handler — a 404,
		// a rate-limit rejection, a recovered panic — is still counted. The plane
		// label is reused from planeOf rather than re-derived, so the metric and
		// the error format can never disagree about which plane a path is on.
		out = s.metrics.Middleware(func(r *http.Request) string { return planeOf(r.URL.Path).String() }, out)
	}
	return out
}

func (s *Server) businessPlane() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.specRoutes() {
		if strings.HasPrefix(rt.Pattern, "/v1/") {
			mux.HandleFunc(rt.Method+" "+rt.Pattern, rt.Handler)
		}
	}
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown resource")
	})
	return recoverBusiness(s, withNoStore(mux))
}

// withNoStore marks every business-plane response uncacheable.
//
// The rule already lived in the writers (writeJSON, writeProblem), and round 2's
// A5-4 was the finding that it had not been applied everywhere. Round 4 found the
// case that proves it still was not: the raw proxy writes its response itself, so
// it was the one authenticated body leaving the service with no cache directive at
// all — and the test that pins the rule enumerated handlers rather than the plane,
// so it could not see it.
//
// Attaching the rule to the plane instead of to each writer is what stops the next
// handler that bypasses the writers from reopening it. The writers keep setting it
// as well: their direct callers in tests do not go through this wrapper.
func withNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// handleNotFound answers a path that is on no plane at all.
//
// Plain text rather than problem+json: the business plane is /v1 and nothing
// outside it is an API, so a mistyped URL in a browser should read like a 404 page
// rather than like an API error. The /v1 subtree has its own catch-all that
// answers problem+json, which is where an API client's typo actually lands.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

// bindEnabled reports whether the source-binding flow can be served.
func (s *Server) bindEnabled() bool { return s.federate != nil && s.sessions != nil }
