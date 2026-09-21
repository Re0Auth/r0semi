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
// the request-id middleware. See docs/api-design.md §1 and §6.
package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
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
	// ConsentPath is the frontend route /oauth/authorize redirects to. Defaults
	// to "/consent".
	ConsentPath string
	// Federation, when set, mounts the data-plane endpoints under /v1/games.
	Federation federation.Service
	// Limiter, when set, caps requests per client address. It is applied to
	// both planes.
	Limiter *ratelimit.Limiter
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
		cfg.ConsentPath = "/consent"
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
	}, nil
}

// Handler returns the root handler.
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
	if s.sessions != nil {
		// The RFC 8628 verification page. It needs a signed-in user, so it is
		// only mounted when the session plane exists.
		root.HandleFunc("GET /device", s.handleDeviceVerification)
	}
	root.HandleFunc("/", s.handleNotFound)

	var h http.Handler = withRequestID(root)
	if s.sessions != nil {
		h = s.sessions.LoadAndSave(h)
	}
	// Outermost: shed load before sessions or handlers do any work.
	return s.withRateLimit(h)
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
	mux.HandleFunc("GET /v1/me", s.withBearer(s.handleMe))
	if s.sessions != nil {
		mux.HandleFunc("GET /v1/sessions/current", s.handleCurrentSession)
		mux.HandleFunc("POST /v1/sessions/sign_out", s.handleSignOut)
		mux.HandleFunc("POST /v1/device/decision", s.handleDeviceDecision)
	}
	if s.sessions != nil && s.authz != nil {
		mux.HandleFunc("GET /v1/authorization_requests/{id}", s.handleGetAuthorizationRequest)
		mux.HandleFunc("POST /v1/authorization_requests/{id}/decision", s.handleAuthorizationDecision)
	}
	if s.federate != nil {
		mux.HandleFunc("GET /v1/games/{game}/sources", s.handleGameSources)
		mux.HandleFunc("GET /v1/games/{game}/sources/{source}/raw/{path...}", s.withBearer(s.handleGameRaw))
		mux.HandleFunc("GET /v1/games/{game}/{resource}", s.withBearer(s.handleGameResource))
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
