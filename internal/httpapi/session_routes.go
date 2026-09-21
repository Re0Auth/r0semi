package httpapi

import (
	"net/http"
)

type identityView struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	LinkedAt    string `json:"linked_at"`
}

// handleCurrentSession is the frontend's bootstrap call: who is signed in, what
// identities are linked, and the CSRF token for subsequent writes.
func (s *Server) handleCurrentSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := s.sessions.User(ctx)
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	record, err := s.accounts.GetUser(ctx, user)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "account lookup failed")
		return
	}
	identities, err := s.accounts.Identities(ctx, user)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "identity lookup failed")
		return
	}
	views := make([]identityView, len(identities))
	for i, ident := range identities {
		views[i] = identityView{
			ID:          string(ident.ID),
			Provider:    string(ident.Provider),
			DisplayName: ident.DisplayName,
			Email:       ident.Email,
			AvatarURL:   ident.AvatarURL,
			LinkedAt:    ident.LinkedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":             string(record.ID),
		"primary_identity_id": string(record.PrimaryIdentity),
		"csrf_token":          s.sessions.CSRFToken(ctx),
		"identities":          views,
	})
}

// handleSignOut destroys the session. It is a write, so it requires the CSRF
// token issued by handleCurrentSession.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}
	if err := s.sessions.SignOut(r.Context()); err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "sign out failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
