package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/oauth"
)

// handleGetAuthorizationRequest feeds the consent screen. It requires a signed
// in user and that the handle belongs to this browser's session, so a stolen
// handle is useless in another browser.
func (s *Server) handleGetAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.User(r.Context()); !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	id := r.PathValue("id")
	if authz.InvalidID(id) || !s.sessions.Bound(r.Context(), "authz", id) {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown authorization request")
		return
	}
	req, err := s.authz.Get(r.Context(), id)
	if err != nil {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "authorization request expired")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         req.ID,
		"client":     map[string]string{"id": req.ClientID, "name": req.ClientName},
		"scopes":     s.scopeViews(req.Scopes),
		"csrf_token": s.sessions.CSRFToken(r.Context()),
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
	if authz.InvalidID(id) || !s.sessions.Bound(r.Context(), "authz", id) {
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
		req, err := s.authz.Deny(r.Context(), id)
		if err != nil {
			s.writeProblem(w, r, http.StatusNotFound, "not_found", "authorization request expired")
			return
		}
		s.sessions.Unbind(r.Context(), "authz", id)
		writeJSON(w, http.StatusOK, map[string]string{
			"redirect_to": buildRedirect(req.RedirectURI, map[string]string{
				"error": "access_denied", "state": req.State,
			}),
		})

	case "approve":
		resp, err := s.authz.Approve(r.Context(), id, string(user), toScopes(body.Scopes), toScopes(body.Explicit))
		if err != nil {
			s.writeDecisionError(w, r, err)
			return
		}
		s.sessions.Unbind(r.Context(), "authz", id)
		writeJSON(w, http.StatusOK, map[string]string{
			"redirect_to": buildRedirect(resp.RedirectURI, map[string]string{
				"code": resp.Code, "state": resp.State,
			}),
		})

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
	case errors.Is(err, authz.ErrScopeNotRequested):
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "approved scope was not requested")
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
