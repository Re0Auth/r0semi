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
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/internal/federation"
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
	// AS is the authorization server core. Required.
	AS oauth.Service

	// Sessions, when set, enables the browser-session endpoints under /v1 and
	// wraps the whole tree with session loading.
	Sessions *auth.Manager
	// Accounts is required when Sessions is set.
	Accounts account.Store
	// Auth, when set, mounts the IdP login plane under /auth.
	Auth *auth.Handler
	// Authz, when set with Sessions, enables the authorization-interaction API
	// and turns /oauth/authorize into a real browser flow.
	Authz authz.Service
	// ConsentPath is the frontend route /oauth/authorize redirects to. It must be a
	// route the mounted frontend actually serves. Defaults to
	// webui.BasePath + "/consent".
	ConsentPath string
	// Federation, when set, mounts the data-plane endpoints under /v1/games.
	Federation federation.Service
	// Limiter, when set, caps requests per client address. It is applied to
	// both planes.
	Limiter *ratelimit.Limiter
	// Secure declares that this issuer is reached over https. It gates the HSTS
	// header only; it is the same deployment fact that makes the session cookie
	// Secure, so a deployment sets both from one switch (`server.cookie_secure`).
	Secure bool
	// Frontend, when set, is the built single-page app mounted under
	// webui.BasePath. Pass webui.FS() for an embedded build.
	Frontend fs.FS
}

// Server is the two-plane HTTP surface.
type Server struct {
	issuer    string
	resource  string
	errorBase string
	scopes    *oauth.Registry
	as        oauth.Service
	sessions  *auth.Manager
	accounts  account.Store
	auth      *auth.Handler
	authz     authz.Service
	consent   string
	federate  federation.Service
	limiter   *ratelimit.Limiter
	secure    bool
	frontend  fs.FS
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.AS == nil {
		return nil, errors.New("httpapi: Config.AS is required")
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
	if cfg.Authz != nil && cfg.Sessions == nil {
		return nil, errors.New("httpapi: Config.Authz requires Config.Sessions")
	}
	if cfg.ConsentPath == "" {
		// The consent screen is a frontend route, so its default is derived from
		// where the frontend is mounted rather than invented separately. A
		// deployment that moves the app must move this with it.
		cfg.ConsentPath = webui.BasePath + "/consent"
	}
	return &Server{
		issuer:    strings.TrimRight(cfg.Issuer, "/"),
		resource:  strings.TrimRight(cfg.Resource, "/"),
		errorBase: strings.TrimRight(cfg.ErrorBase, "/"),
		scopes:    cfg.Scopes,
		as:        cfg.AS,
		sessions:  cfg.Sessions,
		accounts:  cfg.Accounts,
		auth:      cfg.Auth,
		authz:     cfg.Authz,
		consent:   cfg.ConsentPath,
		federate:  cfg.Federation,
		limiter:   cfg.Limiter,
		secure:    cfg.Secure,
		frontend:  cfg.Frontend,
	}, nil
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
	if s.sessions != nil && s.authz != nil {
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
	return routes
}
func (s *Server) Handler() http.Handler {
	root := http.NewServeMux()
	root.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleASMetadata)
	root.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleResourceMetadata)
	root.Handle("/oauth/", s.protocolPlane())
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
		root.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, webui.BasePath+"/", http.StatusFound)
		})
	}
	root.HandleFunc("/", s.handleNotFound)

	// Order, outermost first:
	//
	//	1. request id      -- so even a rejected request can be quoted to an
	//	                      operator. A 429 is the response most likely to be
	//	                      reported, and it never reaches a handler.
	//	2. security headers -- including on those rejections, so a failure is
	//	                      still not frameable and still leaks no URL.
	//	3. the limiter      -- shed load before sessions or handlers do any work.
	//	4. the body limit   -- cap what a handler can be made to read, which is a
	//	                      different question from how often it may ask.
	//	5. session loading  -- wraps the whole tree; /auth and /v1 both need it.
	var h http.Handler = root
	if s.sessions != nil {
		h = s.sessions.LoadAndSave(h)
	}
	h = s.withBodyLimit(h)
	h = s.withRateLimit(h)
	h = s.withSecurityHeaders(h)
	return withRequestID(h)
}

func (s *Server) protocolPlane() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("POST /oauth/device_authorization", s.handleDeviceAuthorization)
	mux.HandleFunc("POST /oauth/introspect", s.handleIntrospect)
	mux.HandleFunc("POST /oauth/revoke", s.handleRevoke)
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/", func(w http.ResponseWriter, r *http.Request) {
		writeOAuthError(w, r, http.StatusNotFound, "invalid_request", "unknown OAuth endpoint")
	})
	return recoverProtocol(mux)
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
	return recoverBusiness(s, mux)
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown endpoint")
}

// bindEnabled reports whether the source-binding flow can be served.
func (s *Server) bindEnabled() bool { return s.federate != nil && s.sessions != nil }
