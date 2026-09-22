package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/safeurl"
	"github.com/Re0Auth/r0semi/oauth"
)

type federationResourceView struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
	Scope  string `json:"scope"`
}

type federationSourceView struct {
	// Game is repeated on each entry so a source is self-describing. That is what
	// lets the same shape serve both the per-game listing and the deployment-wide
	// one.
	Game        string                   `json:"game"`
	Source      string                   `json:"source"`
	DisplayName string                   `json:"display_name"`
	TokenClass  string                   `json:"token_class"`
	Status      string                   `json:"status"`
	Raw         bool                     `json:"raw"`
	Resources   []federationResourceView `json:"resources"`
}

// sourceView is the one place a source is turned into its public shape, so the
// per-game and deployment-wide listings cannot drift apart.
func sourceView(src federation.Source) federationSourceView {
	resources := make([]federationResourceView, 0, len(src.Resources))
	for _, res := range src.Resources {
		resources = append(resources, federationResourceView{Name: res.Name, Schema: res.Schema, Scope: res.Scope})
	}
	return federationSourceView{
		Game:        src.Game,
		Source:      src.Name,
		DisplayName: src.DisplayName,
		TokenClass:  src.TokenClass,
		Status:      string(src.Status),
		Raw:         src.RawBase != "",
		Resources:   resources,
	}
}

// handleAllSources lists every source this deployment offers, across games.
//
// It is what lets the account page offer something to connect to. Without it, a
// page whose job is connecting sources can only show the ones already connected,
// which is a dead end for exactly the people who need it.
//
// Public, like the per-game listing: none of this is user data.
func (s *Server) handleAllSources(w http.ResponseWriter, _ *http.Request) {
	sources := s.federate.AllSources()
	views := make([]federationSourceView, 0, len(sources))
	for _, src := range sources {
		views = append(views, sourceView(src))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": views})
}

// handleGameSources is public discovery: which sources serve a game and what
// they can do. It exposes no user data.
func (s *Server) handleGameSources(w http.ResponseWriter, r *http.Request) {
	game := r.PathValue("game")
	sources := s.federate.Sources(game)

	views := make([]federationSourceView, 0, len(sources))
	for _, src := range sources {
		views = append(views, sourceView(src))
	}
	writeJSON(w, http.StatusOK, map[string]any{"game": game, "data": views})
}

// handleGameResource proxies a normalized resource from a bound source. The
// body is the source's canonical payload, passed through untouched, with the
// answering source named in a header.
func (s *Server) handleGameResource(w http.ResponseWriter, r *http.Request, info oauth.TokenInfo) {
	game := r.PathValue("game")
	resource := r.PathValue("resource")

	scope, ok := s.federate.ResourceScope(game, resource)
	if !ok {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown game or resource")
		return
	}
	if !hasScopeString(info.Scopes, scope) {
		s.writeProblem(w, r, http.StatusForbidden, "scope_not_granted",
			"this token does not include '"+scope+"'", withRequiredScope(scope))
		return
	}

	result, err := s.federate.Fetch(r.Context(), federation.FetchRequest{
		User:     account.UserID(info.Subject),
		Game:     game,
		Resource: resource,
		Source:   r.URL.Query().Get("source"),
	})
	if err != nil {
		s.writeFederationError(w, r, err)
		return
	}

	w.Header().Set("Re0Auth-Source", result.Source)
	if result.Degraded {
		w.Header().Set("Re0Auth-Degraded", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Data)
}

func (s *Server) writeFederationError(w http.ResponseWriter, r *http.Request, err error) {
	var notBound *federation.NotBoundError
	var sourceErr *federation.SourceError

	switch {
	case errors.As(err, &notBound):
		s.writeProblem(w, r, http.StatusConflict, "source_not_bound",
			"the user has not bound this source",
			withBinding(notBound.Game, notBound.Source, s.bindURL(notBound.Game, notBound.Source, r.URL.Path)))
	case errors.As(err, &sourceErr):
		s.writeProblem(w, r, http.StatusServiceUnavailable, "source_unavailable", "the source returned an error")
	case errors.Is(err, federation.ErrUnknownGame),
		errors.Is(err, federation.ErrUnknownSource),
		errors.Is(err, federation.ErrUnknownResource):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown game, source or resource")
	case errors.Is(err, federation.ErrSourceRetired):
		s.writeProblem(w, r, http.StatusGone, "source_retired", "the source has been retired")
	case errors.Is(err, federation.ErrRawUnsupported):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "the source has no raw API")
	case errors.Is(err, federation.ErrBindUnavailable):
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "the source is not configured for binding")
	default:
		s.writeProblem(w, r, http.StatusBadGateway, "upstream_unavailable", "could not reach the source")
	}
}

// bindURL points the user at the binding flow. That endpoint is the next piece
// of the data plane; until it exists the link reports its own state.
func (s *Server) bindURL(game, source, returnTo string) string {
	q := url.Values{"game": {game}, "source": {source}}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	return s.issuer + "/bind?" + q.Encode()
}

func hasScopeString(scopes []oauth.Scope, want string) bool {
	for _, sc := range scopes {
		if sc.String() == want {
			return true
		}
	}
	return false
}

func hasAnyScope(scopes []oauth.Scope, want []string) bool {
	for _, w := range want {
		if hasScopeString(scopes, w) {
			return true
		}
	}
	return false
}

// sourceScopes returns a source's resource scopes, used as a coarse gate for
// the raw proxy. A dedicated <game>.raw.read scope is future work.
func (s *Server) sourceScopes(game, source string) ([]string, bool) {
	for _, src := range s.federate.Sources(game) {
		if src.Name == source {
			out := make([]string, 0, len(src.Resources))
			for _, res := range src.Resources {
				if res.Scope != "" {
					out = append(out, res.Scope)
				}
			}
			return out, true
		}
	}
	return nil, false
}

// handleGameRaw proxies a source's native API verbatim. The body, status and
// content type are passed through untouched, for consumers that need the
// upstream's own dialect.
func (s *Server) handleGameRaw(w http.ResponseWriter, r *http.Request, info oauth.TokenInfo) {
	game := r.PathValue("game")
	source := r.PathValue("source")

	scopes, ok := s.sourceScopes(game, source)
	if !ok {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown game or source")
		return
	}
	if len(scopes) > 0 && !hasAnyScope(info.Scopes, scopes) {
		s.writeProblem(w, r, http.StatusForbidden, "scope_not_granted", "this token does not grant access to "+game)
		return
	}

	result, err := s.federate.Raw(r.Context(), federation.RawRequest{
		User:   account.UserID(info.Subject),
		Game:   game,
		Source: source,
		Path:   r.PathValue("path"),
		Query:  r.URL.Query(),
	})
	if err != nil {
		s.writeFederationError(w, r, err)
		return
	}

	w.Header().Set("Re0Auth-Source", result.Source)
	if result.ContentType != "" {
		w.Header().Set("Content-Type", result.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
}

// handleBindStart begins the interactive binding flow: it redirects the browser
// to the source's authorization endpoint, with the flow bound to this session.
func (s *Server) handleBindStart(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to bind a source")
		return
	}
	challenge, err := s.federate.BeginBind(r.Context(), user,
		r.URL.Query().Get("game"), r.URL.Query().Get("source"),
		safeurl.RelativePath(r.URL.Query().Get("return_to")))
	if err != nil {
		s.writeFederationError(w, r, err)
		return
	}
	s.sessions.Bind(r.Context(), "bind", challenge.ID)
	http.Redirect(w, r, challenge.AuthorizeURL, http.StatusFound)
}

// handleBindCallback finishes the flow: it exchanges the code, stores the
// binding, and sends the browser back to where it started.
func (s *Server) handleBindCallback(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" || !s.sessions.Bound(r.Context(), "bind", state) {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "unknown or expired bind request")
		return
	}
	s.sessions.Unbind(r.Context(), "bind", state)

	code := r.URL.Query().Get("code")
	if r.URL.Query().Get("error") != "" {
		code = "" // the user refused upstream; force the denial path
	}

	_, flow, err := s.federate.CompleteBind(r.Context(), user, state, code)
	returnTo := safeurl.RelativePath(flow.ReturnTo)
	if err != nil {
		redirectWithError(w, r, returnTo, "bind_failed")
		return
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, returnTo, code string) {
	u, err := url.Parse(returnTo)
	if err != nil {
		http.Error(w, "bind failed", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}
