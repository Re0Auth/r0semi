package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/observability"
)

// bindingView is one connected data source.
type bindingView struct {
	Game   string `json:"game"`
	Source string `json:"source"`
	// DisplayName comes from this deployment's registry, not from the source, so a
	// source cannot rename itself on a page the user is asked to trust.
	DisplayName string `json:"display_name"`
	TokenClass  string `json:"token_class"`
	Status      string `json:"status"`
	HasRefresh  bool   `json:"has_refresh"`
	// Expiry is when the current upstream token lapses, when it has one.
	Expiry string `json:"expiry,omitempty"`
	// Bindable is false for a retired source. Reported rather than inferred by the
	// client, because "why is there no connect button" should not be a guess.
	Bindable bool `json:"bindable"`
	// CascadeRevocation reports whether this deployment has been told the source
	// can end a whole upstream session. It is what decides whether the account page
	// offers "sign out everywhere", so a source that cannot do it gets no button
	// rather than a button that fails.
	CascadeRevocation bool `json:"cascade_revocation"`
	// Configured is false when the binding outlives the source's entry in this
	// deployment's configuration. The connection still exists and can still be
	// removed; it just has nothing to describe it any more.
	Configured bool `json:"configured"`
}

// handleListBindings lists the data sources connected to the signed-in account.
//
// Session-scoped like the grants view, and for the same reason: this names the
// account's connections, and a client asking with its own token has no business
// knowing about the others.
func (s *Server) handleListBindings(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	bindings, err := s.federate.Bindings(r.Context(), user)
	if err != nil {
		// The wire answer is generic; the error itself (a database fault, a scan
		// failure) goes to the log, where an operator can act on it.
		slog.ErrorContext(r.Context(), "could not read bindings",
			"user", string(user), "request_id", requestID(r), "err", err)
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read bindings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": s.bindingViews(bindings)})
}

// bindingViews is the one place a binding becomes its public shape. It is shared
// with the account export deliberately: a binding carries metadata only (the
// upstream token lives in the vault), and building both responses from this one
// function is what keeps the export from ever growing a credential the list view
// does not have.
func (s *Server) bindingViews(bindings []federation.Binding) []bindingView {
	// Display metadata is looked up per game, once per game, rather than per
	// binding.
	sources := make(map[string]federation.Source)
	for _, game := range distinctGames(bindings) {
		for _, src := range s.federate.Sources(game) {
			sources[game+"\x00"+src.Name] = src
		}
	}

	views := make([]bindingView, 0, len(bindings))
	for _, b := range bindings {
		view := bindingView{
			Game:        b.Game,
			Source:      b.Source,
			DisplayName: b.Source,
			HasRefresh:  b.HasRefresh,
		}
		if !b.Expiry.IsZero() {
			view.Expiry = b.Expiry.UTC().Format(time.RFC3339)
		}
		if src, ok := sources[b.Game+"\x00"+b.Source]; ok {
			view.DisplayName = src.DisplayName
			view.TokenClass = src.TokenClass
			view.Status = string(src.Status)
			view.Bindable = src.Status != federation.StatusRetired
			view.CascadeRevocation = src.CascadeRevocationEndpoint != ""
			view.Configured = true
		}
		views = append(views, view)
	}
	return views
}

func distinctGames(bindings []federation.Binding) []string {
	seen := make(map[string]bool, len(bindings))
	out := make([]string, 0, len(bindings))
	for _, b := range bindings {
		if !seen[b.Game] {
			seen[b.Game] = true
			out = append(out, b.Game)
		}
	}
	return out
}

// unbindView reports what disconnecting managed to undo.
type unbindView struct {
	// Upstream is one of done | unsupported | unavailable | nothing. It is in the
	// response because the user has to be able to tell "the source has forgotten
	// this token" from "removed here, still live there".
	Upstream string `json:"upstream"`
	// UpstreamError is diagnostic, present only when Upstream is unavailable.
	UpstreamError string `json:"upstream_error,omitempty"`
}

// handleUnbind disconnects a data source from the signed-in account.
//
// 200 with a body rather than 204, unlike revoking a grant. There the outcome was
// uniform; here the source may be unreachable, or may hold a credential it
// declared it cannot revoke. Returning 204 would make the local half look like
// the whole story, which is exactly the kind of quiet overstatement the rest of
// this service avoids.
func (s *Server) handleUnbind(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}

	game := strings.TrimSpace(r.PathValue("game"))
	source := strings.TrimSpace(r.PathValue("source"))
	if game == "" || source == "" {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "a game and a source are required")
		return
	}

	result, err := s.federate.Unbind(r.Context(), user, game, source)
	if err != nil {
		if errors.Is(err, federation.ErrUnknownSource) {
			s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown game or source")
			return
		}
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not disconnect the source")
		return
	}
	s.metrics.ObserveRevocation(observability.RevocationBinding)
	writeJSON(w, http.StatusOK, unbindView{
		Upstream:      string(result.Upstream),
		UpstreamError: result.UpstreamError,
	})
}

// cascadeRequest is the body a cascade revocation must carry.
type cascadeRequest struct {
	// Acknowledge must name the consequence. It exists so that ending somebody's
	// sessions on every device cannot happen by accident: a caller has to write
	// down what it is about to do. The value is a constant on purpose — this is a
	// speed bump with a label, not a configurable field.
	Acknowledge string `json:"acknowledge"`
}

// cascadeAcknowledgement is the exact string the request must carry.
const cascadeAcknowledgement = "signs_out_all_devices"

// handleCascadeRevoke ends the account's upstream session at a data source.
//
// This is the loudest operation in the service and the only one whose *point* is
// to affect things outside Re0Auth. It signs the person out of every device,
// including the one in their hand, and it can only be asked for while the binding
// still exists — Re0Auth needs the token to tell the source whose session to end.
//
// Nothing is removed unless the source confirms. That is the opposite of
// disconnect, and deliberately so: see federation.CascadeRevoke.
func (s *Server) handleCascadeRevoke(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}

	var body cascadeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if body.Acknowledge != cascadeAcknowledgement {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request",
			`acknowledge must be "`+cascadeAcknowledgement+`": this signs the account out of every device`)
		return
	}

	game := strings.TrimSpace(r.PathValue("game"))
	source := strings.TrimSpace(r.PathValue("source"))
	if game == "" || source == "" {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "a game and a source are required")
		return
	}

	result, err := s.federate.CascadeRevoke(r.Context(), user, game, source)
	switch {
	case errors.Is(err, federation.ErrCascadeUnsupported):
		s.writeProblem(w, r, http.StatusConflict, "cascade_unsupported",
			"this data source cannot end the upstream session")
		return
	case errors.Is(err, federation.ErrUnknownSource):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown game or source")
		return
	case errors.Is(err, federation.ErrNotBound):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "the source is not connected")
		return
	case err != nil:
		// Nothing was removed, so the user can try again. Reporting the source's
		// failure as a 200 with an outcome would suggest the logout half-succeeded;
		// it did not succeed at all.
		//
		// The detail is deliberately generic: err.Error() can name internal hosts,
		// URL paths and network details. The real text is logged for the operator.
		slog.Warn("cascade revocation failed", "game", game, "source", source, "err", err)
		s.writeProblem(w, r, http.StatusBadGateway, "upstream_unavailable",
			"the data source could not end the session; try again or check the source's status")
		return
	}
	s.metrics.ObserveRevocation(observability.RevocationCascade)
	writeJSON(w, http.StatusOK, unbindView{Upstream: string(result.Upstream)})
}
