package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/oauth"
)

// bindingRequirementView tells the consent screen which data source must be
// connected before the requested scopes can be served, and where to connect it.
type bindingRequirementView struct {
	Game        string   `json:"game"`
	Source      string   `json:"source"`
	DisplayName string   `json:"display_name"`
	Scopes      []string `json:"scopes"`
	// BindURL is server-built and returns to this consent screen. The frontend
	// navigates to it verbatim rather than assembling it.
	BindURL string `json:"bind_url"`
}

// missingBindingViews is the bridge between the consent screen and the data
// plane's binding state. It is advisory: approval still consults oauth.Authorize,
// and every data read still checks the binding.
func (s *Server) missingBindingViews(ctx context.Context, user account.UserID, scopes []oauth.Scope, id string) ([]bindingRequirementView, error) {
	views := []bindingRequirementView{}
	if s.federate == nil {
		return views, nil
	}
	reqs, err := s.federate.MissingBindings(ctx, user, scopeStrings(scopes))
	if err != nil {
		return nil, err
	}
	// Come back to the pending consent request after the source redirects here.
	returnTo := s.consent + "?id=" + url.QueryEscape(id)
	for _, req := range reqs {
		views = append(views, bindingRequirementView{
			Game:        req.Game,
			Source:      req.Source,
			DisplayName: req.DisplayName,
			Scopes:      req.Scopes,
			BindURL:     s.bindURL(req.Game, req.Source, returnTo),
		})
	}
	return views, nil
}

// handleGetAuthorizationRequest feeds the consent screen. It requires a signed
// in user and that the handle belongs to this browser's session, so a stolen
// handle is useless in another browser.
func (s *Server) handleGetAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	id := r.PathValue("id")
	if !s.authInteract.ValidID(id) || !s.sessions.Bound(r.Context(), "authz", id) {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown authorization request")
		return
	}
	view, err := s.authInteract.DescribeAuthorization(r.Context(), id)
	if err != nil {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "authorization request expired")
		return
	}

	missing, err := s.missingBindingViews(r.Context(), user, view.Scopes, view.ID)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read data source bindings")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":               view.ID,
		"client":           map[string]string{"id": view.ClientID, "name": view.ClientName},
		"scopes":           s.scopeViews(view.Scopes),
		"missing_bindings": missing,
		"csrf_token":       s.sessions.CSRFToken(r.Context()),
	})
}

type decisionBody struct {
	Decision string   `json:"decision"`
	Scopes   []string `json:"scopes"`
	Explicit []string `json:"explicit"`
}

// handleAuthorizationDecision records the user's choice and returns the exact
// redirect the frontend must follow. The frontend never assembles the redirect
// itself.
func (s *Server) handleAuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}
	id := r.PathValue("id")
	if !s.authInteract.ValidID(id) || !s.sessions.Bound(r.Context(), "authz", id) {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown authorization request")
		return
	}

	var body decisionBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	switch body.Decision {
	case "deny":
		redirect, err := s.authInteract.DenyAuthorization(r.Context(), id)
		if err != nil {
			s.writeProblem(w, r, http.StatusNotFound, "not_found", "authorization request expired")
			return
		}
		s.sessions.Unbind(r.Context(), "authz", id)
		writeJSON(w, http.StatusOK, map[string]string{"redirect_to": redirect})

	case "approve":
		redirect, err := s.authInteract.ApproveAuthorization(r.Context(), id, string(user), toScopes(body.Scopes), toScopes(body.Explicit))
		if err != nil {
			s.writeDecisionError(w, r, err)
			return
		}
		s.sessions.Unbind(r.Context(), "authz", id)
		writeJSON(w, http.StatusOK, map[string]string{"redirect_to": redirect})

	default:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", `decision must be "approve" or "deny"`)
	}
}

func (s *Server) writeDecisionError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauth.Error
	switch {
	case errors.As(err, &oe) && oe.Code == "access_denied":
		s.writeProblem(w, r, http.StatusForbidden, "explicit_consent_required", oe.Description)
	case errors.As(err, &oe):
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", oe.Description)
	default:
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "authorization request expired")
	}
}

func (s *Server) scopeViews(scopes []oauth.Scope) []map[string]any {
	out := make([]map[string]any, 0, len(scopes))
	for _, sc := range scopes {
		d, ok := s.scopes.Get(sc)
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"scope":            sc.String(),
			"title":            d.Title,
			"description":      d.Description,
			"risk":             d.Risk.String(),
			"explicit_consent": d.ExplicitConsent,
		})
	}
	return out
}

func toScopes(in []string) []oauth.Scope {
	out := make([]oauth.Scope, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, oauth.Scope(s))
		}
	}
	return out
}
