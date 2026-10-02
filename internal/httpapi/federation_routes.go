package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/safeurl"
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
//
// The authorization gate asks the federation service which sources could serve
// this read, and requires the scope of EVERY one of them. The rule used to be
// "the scope of the first source that declares the resource, in config order",
// while the read is served by whichever source candidates() picks — so the gate
// was wrong in both directions at once: it let a token holding source A's scope
// read source B's data, and it refused a token holding the scope of the source
// that actually served. A gate whose criterion is decided by a different function
// than the read is not a gate.
//
// Requiring all of them is the fail-closed direction, and it is cheap in the case
// that matters: two sources that declare the SAME scope for a resource produce one
// requirement, so a deployment whose sources agree sees no change. Pinning
// `?source=` narrows the list to that source, which is the honest way to ask for
// one source's scope.
//
// The alternative — checking the scope of the source that ends up answering —
// cannot be decided before the read, and deciding it after means fetching data the
// caller may not be allowed to see.
func (s *Server) handleGameResource(w http.ResponseWriter, r *http.Request, info oauth.TokenInfo) {
	game := r.PathValue("game")
	resource := r.PathValue("resource")
	pinned := r.URL.Query().Get("source")

	requirements, err := s.federate.ResourceRequirements(game, resource, pinned)
	if err != nil {
		s.writeFederationError(w, r, err)
		return
	}
	for _, requirement := range requirements {
		if !hasScopeString(info.Scopes, requirement.Scope) {
			s.insufficientScope(w, r, requirement.Scope,
				"this token does not include '"+requirement.Scope+"', which source '"+
					requirement.Source+"' requires for this resource")
			return
		}
	}

	result, err := s.federate.Fetch(r.Context(), federation.FetchRequest{
		User:     account.UserID(info.Subject),
		Game:     game,
		Resource: resource,
		Source:   pinned,
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
	// The body's byte reservation is held until this handler returns, not until
	// Fetch returns (Z11-2, docs/issues/P2-medium.md): the bytes are live in this
	// frame from here through w.Write, so releasing earlier would let the budget
	// admit another full-cap read while this one is still holding its slice.
	if result.Release != nil {
		defer result.Release()
	}
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
	case errors.Is(err, federation.ErrRawPathEscapes):
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request",
			"the raw path must stay under the source's base URL")
	case errors.Is(err, federation.ErrResponseTooLarge):
		// The upstream answered, so this is not "could not reach it" — but the
		// proxy will not hand back a truncated body as if it were whole, and the
		// condition is only expressible as a gateway failure.
		s.writeProblem(w, r, http.StatusBadGateway, "upstream_unavailable",
			"the source's response is larger than this proxy will pass through")
	case errors.Is(err, federation.ErrBufferBudget):
		// The data plane is already holding as much upstream response body in
		// memory as it may, so this read is shed before the bytes are allocated.
		// That direction is the point: the alternative is reaching the container's
		// memory limit and being OOM-killed, which loses every request in flight
		// rather than this one. Retry-After is the same hint the in-flight limiter
		// gives for the same reason.
		w.Header().Set("Retry-After", "1")
		s.writeProblem(w, r, http.StatusServiceUnavailable, "temporarily_unavailable",
			"too much upstream response data is being buffered right now")
	case errors.Is(err, federation.ErrBindingCooldown):
		// This binding's credential was rejected by the source on
		// bindingCooldownThreshold consecutive reads, so the data plane stopped
		// asking (Z09V-1, docs/issues/P2-medium.md). It is NOT the host breaker:
		// the source is fine and another account's binding to it keeps being
		// served, so this is deliberately not the 502 "upstream_unavailable" the
		// breaker's circuit_open maps to. It is a temporary local shed with the
		// same retry hint as the byte budget.
		w.Header().Set("Retry-After", "1")
		s.writeProblem(w, r, http.StatusServiceUnavailable, "temporarily_unavailable",
			"this account's credential for the source was rejected repeatedly; retry later or bind the source again")
	case errors.Is(err, context.DeadlineExceeded):
		// The data plane's own deadline for one request, which exists so that this
		// answer is written at all: before it, the candidate loop times the outbound
		// deadline could take longer than the server's write timeout, and the client
		// got a dropped connection instead of a status. 504 says "the gateway gave
		// up waiting", which is the truth, and distinguishes it from the 502 that
		// means the source refused us.
		s.writeProblem(w, r, http.StatusGatewayTimeout, "upstream_unavailable",
			"the source did not answer within the time this service allows for one read")
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
	return slices.Contains(scopes, oauth.Scope(want))
}

// rawScope is the explicit scope that gates a game's raw passthrough:
// `<game>.raw.read`.
//
// It exists because the raw proxy hands a source's ENTIRE native API through in
// the source's own dialect, which no resource-scoped grant covers: a token for
// `phigros.profile.read` was enough to read the same source's scores endpoint
// through raw even when the user had unchecked the scores permission on the
// consent screen (Z20-2). The normalized, resource-named endpoint already
// refused; this closes the asymmetry by naming the permission raw needs.
func rawScope(game string) oauth.Scope {
	return oauth.Scope(game + ".raw.read")
}

// rawGate resolves a game/source pair to the game's canonical name and the raw
// scope it requires. The scope is built from the REGISTRY's spelling of the game
// rather than the request's, so two spellings of one game cannot disagree about
// which permission raw needs.
func (s *Server) rawGate(game, source string) (oauth.Scope, bool) {
	for _, src := range s.federate.Sources(game) {
		if src.Name == source {
			return rawScope(src.Game), true
		}
	}
	return "", false
}

// handleGameRaw proxies a source's native API verbatim. The body, status and
// content type are passed through untouched, for consumers that need the
// upstream's own dialect.
func (s *Server) handleGameRaw(w http.ResponseWriter, r *http.Request, info oauth.TokenInfo) {
	game := r.PathValue("game")
	source := r.PathValue("source")

	// The gate is the game's explicit `<game>.raw.read` scope, and only it. The
	// old rule — "any resource scope the source declares" — let a token minted for
	// one resource read every other resource through raw, so a user who withheld
	// `scores` on the consent screen still reached it here.
	scope, ok := s.rawGate(game, source)
	if !ok {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown game or source")
		return
	}
	if !hasScopeString(info.Scopes, scope.String()) {
		s.insufficientScope(w, r, scope.String(), "this token does not grant raw access to "+game)
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
	// The body, the status and the media type stay the source's, verbatim: that
	// is this endpoint's contract. What is not left to the source is what a
	// browser may do with the response, because the media type is now attached to
	// *this* origin. A source answering text/html would be markup running beside
	// the session cookie, with no script-src to stop it — the global policy is
	// frame-ancestors only, and the SPA's script-src lives in its own document's
	// meta tag rather than in a header. So the response carries a policy stricter
	// than the global one, and a disposition that makes a browser download the
	// body instead of rendering it. An API client reads neither.
	w.Header().Set("Content-Security-Policy", cspRawProxy)
	w.Header().Set("Content-Disposition", `attachment; filename="`+rawDownloadName(game, source, r.PathValue("path"))+`"`)
	// Same as the normalized handler: the reservation travels with the body and is
	// returned after this frame's w.Write, which is where a slow-reading client
	// blocks while the slice is live (Z11-2, docs/issues/P2-medium.md).
	if result.Release != nil {
		defer result.Release()
	}
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
}

// rawDownloadName names the file a browser will save the raw response as, derived
// from the operator-configured game and source plus the request's path.
//
// Every character outside [A-Za-z0-9._-] is replaced rather than escaped, because
// the value goes inside a quoted header parameter: a source name from the
// configuration or a path from the caller could otherwise close the quote or
// inject a line break and write a header of its own.
func rawDownloadName(game, source, path string) string {
	const (
		fallback = "download"
		maxLen   = 64
	)
	name := strings.Trim(path, "/")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	raw := game + "-" + source
	if name != "" {
		raw += "-" + name
	}
	safe := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			safe = append(safe, c)
		default:
			safe = append(safe, '_')
		}
	}
	if len(safe) == 0 {
		return fallback
	}
	if len(safe) > maxLen {
		safe = safe[:maxLen]
	}
	return string(safe)
}

// handleBindStart begins the interactive binding flow: it redirects the browser
// to the source's authorization endpoint, with the flow bound to this session.
//
// It is a browser navigation, not an API, so its failures are plain text — the
// same decision /auth already follows, and the one recorded in
// docs/browser-plane-decision.md. A problem+json body here would be a format no
// consumer of this URL parses.
func (s *Server) handleBindStart(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		http.Error(w, "sign in to bind a source", http.StatusUnauthorized)
		return
	}
	challenge, err := s.federate.BeginBind(r.Context(), user,
		r.URL.Query().Get("game"), r.URL.Query().Get("source"),
		safeurl.RelativePath(r.URL.Query().Get("return_to")))
	if err != nil {
		// One generic answer on purpose. The distinctions a caller would act on
		// (unknown source, source retired, client not configured) are all "this link
		// does not work" to the person who followed it, and the detail belongs in a
		// log rather than in a navigation response.
		http.Error(w, "cannot start binding this source", http.StatusBadRequest)
		return
	}
	s.sessions.Bind(r.Context(), "bind", challenge.ID)
	// challenge.AuthorizeURL is built by the registered source's client from its
	// configured issuer (internal/federation); no request value reaches it.
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, challenge.AuthorizeURL, http.StatusFound)
}

// handleBindCallback finishes the flow: it exchanges the code, stores the
// binding, and sends the browser back to where it started.
func (s *Server) handleBindCallback(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		http.Error(w, "sign in to continue", http.StatusUnauthorized)
		return
	}
	state := r.URL.Query().Get("state")
	// Bound AND owned by this account. Both, like every other handle in this
	// service: the handle is recorded against the browser (so a relayed state
	// cannot be replayed elsewhere) *and* against the account that started it.
	//
	// The ownership check was missing here, and this is the one caller that
	// omitted it. A second account in the same browser could therefore pass the
	// browser check, consume the handle and the flow row, and leave the account
	// that started the flow unable to finish it — a cross-account denial of the
	// victim's own binding. The answer is the same 400 as an unknown handle: a
	// distinct refusal would confirm the handle exists.
	if state == "" ||
		!s.sessions.Bound(r.Context(), "bind", state) ||
		!s.sessions.OwnerMatches(r.Context(), "bind", state, user) {
		http.Error(w, "unknown or expired bind request", http.StatusBadRequest)
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
		code := "bind_failed"
		if errors.Is(err, federation.ErrBindSuperseded) {
			// Truthful copy: the source was disconnected while this bind was in
			// flight, so the browser is told the bind was superseded rather than
			// that something failed.
			code = "bind_superseded"
		}
		redirectWithError(w, r, returnTo, code)
		return
	}
	// returnTo went through safeurl.RelativePath, so it is a same-origin path.
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
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
