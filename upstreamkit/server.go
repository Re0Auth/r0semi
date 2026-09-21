package upstreamkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Re0Auth/r0semi/oauth"
)

// AccountInfo is what the source returns for the account.read scope.
type AccountInfo struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name,omitempty"`
}

// ConsentRequest is what the authorize endpoint knows before asking the user.
type ConsentRequest struct {
	ClientID    string
	RedirectURI string
	Scopes      []oauth.Scope
	Descriptors []oauth.Descriptor
}

// ConsentDecision is the user's answer. The source supplies the authenticated
// subject; the kit never invents one.
type ConsentDecision struct {
	Subject string
	// Approved is the accepted subset; nil means "all requested".
	Approved []oauth.Scope
	// Explicit lists the individually ticked critical scopes.
	Explicit []oauth.Scope
}

// ConsentFunc authenticates/consents the end user at the source. A real backend
// reads its own session here; a test returns a fixed subject.
type ConsentFunc func(ctx context.Context, req ConsentRequest) (ConsentDecision, error)

// ResourceHandler serves one declared resource for a subject.
type ResourceHandler func(ctx context.Context, subject string) (any, error)

// Hooks are the source-specific parts the kit delegates to.
type Hooks struct {
	// OAuth is a full OAuth 2.0 authorization server core. internal/oauth is a
	// ready-made implementation.
	OAuth oauth.Service
	// Scope is the scope registry the OAuth core was built with.
	Scope *oauth.Registry
	// Consent authenticates/consents the end user at the authorize endpoint.
	Consent ConsentFunc
	// Account resolves a subject for the account.read scope.
	Account func(ctx context.Context, subject string) (AccountInfo, error)
	// Resources maps a declared resource name to its handler.
	Resources map[string]ResourceHandler
}

// Server mounts the Re0Auth upstream protocol.
type Server struct {
	discovery Discovery
	hooks     Hooks
	byName    map[string]Resource
}

// New validates the configuration and hooks and returns a Server.
func New(cfg Config, hooks Hooks) (*Server, error) {
	discovery, err := NewDiscovery(cfg)
	if err != nil {
		return nil, err
	}
	switch {
	case hooks.OAuth == nil:
		return nil, errors.New("upstreamkit: Hooks.OAuth is required")
	case hooks.Scope == nil:
		return nil, errors.New("upstreamkit: Hooks.Scope is required")
	case hooks.Consent == nil:
		return nil, errors.New("upstreamkit: Hooks.Consent is required")
	case hooks.Account == nil:
		return nil, errors.New("upstreamkit: Hooks.Account is required")
	}
	byName := make(map[string]Resource, len(discovery.Resources))
	for _, res := range discovery.Resources {
		if _, ok := hooks.Resources[res.Name]; !ok {
			return nil, errors.New("upstreamkit: no handler for resource " + res.Name)
		}
		byName[res.Name] = res
	}
	return &Server{discovery: discovery, hooks: hooks, byName: byName}, nil
}

// Discovery returns the source's discovery document.
func (s *Server) Discovery() Discovery { return s.discovery }

// Handler returns the protocol HTTP surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/re0auth-upstream", s.handleDiscovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleOAuthMetadata)
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("POST /oauth/revoke", s.handleRevoke)
	mux.HandleFunc("GET /account", s.handleAccount)
	mux.HandleFunc("GET /resources/{name}", s.handleResource)
	return mux
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.discovery)
}

func (s *Server) handleOAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.discovery.OAuth.Issuer,
		"authorization_endpoint":                s.discovery.OAuth.AuthorizationEndpoint,
		"token_endpoint":                        s.discovery.OAuth.TokenEndpoint,
		"revocation_endpoint":                   s.discovery.OAuth.RevocationEndpoint,
		"scopes_supported":                      s.discovery.ScopesSupported,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		writeOAuthError(w, r, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}

	req := oauth.AuthorizationRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scopes:              parseScopes(q.Get("scope")),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
	details, err := s.hooks.OAuth.DescribeAuthorization(r.Context(), req)
	if err != nil {
		writeProtocolError(w, r, err)
		return
	}

	decision, err := s.hooks.Consent(r.Context(), ConsentRequest{
		ClientID:    details.Client.ID,
		RedirectURI: req.RedirectURI,
		Scopes:      req.Scopes,
		Descriptors: details.Scopes,
	})
	if err != nil {
		writeOAuthError(w, r, http.StatusForbidden, "access_denied", "consent was refused")
		return
	}
	if decision.Subject == "" {
		writeOAuthError(w, r, http.StatusForbidden, "access_denied", "no authenticated user at the source")
		return
	}

	req.Subject = decision.Subject
	req.Explicit = decision.Explicit
	if len(decision.Approved) > 0 {
		req.Scopes = decision.Approved
	}
	resp, err := s.hooks.OAuth.Authorize(r.Context(), req)
	if err != nil {
		writeProtocolError(w, r, err)
		return
	}

	http.Redirect(w, r, buildRedirect(resp.RedirectURI, map[string]string{
		"code": resp.Code, "state": resp.State,
	}), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	clientID, clientSecret := clientCredentials(r)

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		resp, err := s.hooks.OAuth.Exchange(r.Context(), oauth.CodeExchangeRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Code:         r.PostFormValue("code"),
			RedirectURI:  r.PostFormValue("redirect_uri"),
			CodeVerifier: r.PostFormValue("code_verifier"),
		})
		if err != nil {
			writeProtocolError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  resp.AccessToken,
			"token_type":    resp.TokenType,
			"expires_in":    resp.ExpiresIn,
			"refresh_token": resp.RefreshToken,
			"scope":         resp.Scope,
		})

	case "refresh_token":
		resp, err := s.hooks.OAuth.Refresh(r.Context(), oauth.RefreshRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RefreshToken: r.PostFormValue("refresh_token"),
			Scopes:       parseScopes(r.PostFormValue("scope")),
		})
		if err != nil {
			writeProtocolError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  resp.AccessToken,
			"token_type":    resp.TokenType,
			"expires_in":    resp.ExpiresIn,
			"refresh_token": resp.RefreshToken,
			"scope":         resp.Scope,
		})

	default:
		writeOAuthError(w, r, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported")
	}
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	clientID, clientSecret := clientCredentials(r)
	err := s.hooks.OAuth.Revoke(r.Context(), oauth.RevokeRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Token:        r.PostFormValue("token"),
	})
	if err != nil {
		writeProtocolError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	info, ok := s.authorize(w, r, AccountScope)
	if !ok {
		return
	}
	account, err := s.hooks.Account(r.Context(), info.Subject)
	if err != nil {
		writeProblem(w, r, http.StatusBadGateway, "upstream_unavailable", "could not resolve the account")
		return
	}
	if account.Subject == "" {
		account.Subject = info.Subject
	}
	s.writeResourceJSON(w, account)
}

func (s *Server) handleResource(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	res, ok := s.byName[name]
	if !ok {
		writeProblem(w, r, http.StatusNotFound, "not_found", "unknown resource "+name)
		return
	}
	info, ok := s.authorize(w, r, res.Scope)
	if !ok {
		return
	}
	handler := s.hooks.Resources[name]
	value, err := handler(r.Context(), info.Subject)
	if err != nil {
		writeProblem(w, r, http.StatusBadGateway, "upstream_unavailable", "could not read "+name)
		return
	}
	s.writeResourceJSON(w, value)
}

// authorize resolves the bearer token and enforces scope, writing the error
// itself when it fails.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, scope string) (oauth.TokenInfo, bool) {
	token := bearerToken(r)
	if token == "" {
		writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "an access token is required")
		return oauth.TokenInfo{}, false
	}
	info, err := s.hooks.OAuth.Introspect(r.Context(), token)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "token introspection failed")
		return oauth.TokenInfo{}, false
	}
	if !info.Active {
		writeProblem(w, r, http.StatusUnauthorized, "invalid_token", "the access token is invalid or has expired")
		return oauth.TokenInfo{}, false
	}
	if scope != "" && !hasScope(info.Scopes, scope) {
		writeProblem(w, r, http.StatusForbidden, "scope_not_granted", "the token lacks "+scope)
		return oauth.TokenInfo{}, false
	}
	return info, true
}

// writeResourceJSON emits a normalized payload with provenance, so a consumer
// always knows which source answered.
func (s *Server) writeResourceJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Re0Auth-Source", s.discovery.Source)
	writeJSON(w, http.StatusOK, value)
}

func hasScope(scopes []oauth.Scope, want string) bool {
	for _, s := range scopes {
		if s.String() == want {
			return true
		}
	}
	return false
}

func clientCredentials(r *http.Request) (id, secret string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

func parseScopes(s string) []oauth.Scope {
	if s == "" {
		return nil
	}
	fields := strings.Fields(s)
	out := make([]oauth.Scope, len(fields))
	for i, f := range fields {
		out[i] = oauth.Scope(f)
	}
	return out
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

func buildRedirect(redirectURI string, params map[string]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	body := map[string]any{
		"type":   "https://r0semi.dev/errors/" + code,
		"title":  strings.ReplaceAll(code, "_", " "),
		"status": status,
		"code":   code,
		"detail": detail,
	}
	if r != nil {
		body["instance"] = r.URL.Path
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOAuthError(w http.ResponseWriter, r *http.Request, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeProtocolError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauth.Error
	if errors.As(err, &oe) {
		status := http.StatusBadRequest
		switch oe.Code {
		case "invalid_client":
			status = http.StatusUnauthorized
		case "access_denied":
			status = http.StatusForbidden
		}
		writeOAuthError(w, r, status, oe.Code, oe.Description)
		return
	}
	writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "internal error")
}
