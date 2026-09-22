package httpapi

import (
	"net/http"
	"strings"
	"time"
)

// grantView is one client's live access to the signed-in account.
type grantView struct {
	ClientID   string           `json:"client_id"`
	ClientName string           `json:"client_name"`
	Scopes     []map[string]any `json:"scopes"`
	// HasRefresh is the difference between "this will lapse" and "this will keep
	// working", which is the thing someone reading this list wants to know.
	HasRefresh bool   `json:"has_refresh"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
}

// handleListGrants lists what each client can still do as the signed-in user.
//
// Session-scoped rather than bearer-scoped, which is a change from what the
// design document first sketched (`account.id`). A bearer token would let one
// client enumerate the user's *other* clients — information it has no use for and
// the user never agreed to hand over. The only consumer is the account page,
// which already has the session.
func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	grants, err := s.grants.Grants(r.Context(), string(user))
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read grants")
		return
	}

	views := make([]grantView, 0, len(grants))
	for _, g := range grants {
		views = append(views, grantView{
			ClientID:   g.ClientID,
			ClientName: g.ClientName,
			Scopes:     s.scopeViews(g.Scopes),
			HasRefresh: g.HasRefresh,
			IssuedAt:   g.IssuedAt.UTC().Format(time.RFC3339),
			ExpiresAt:  g.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": views})
}

// handleRevokeGrant removes every token a client holds for the signed-in user.
//
// It answers 204 whether or not anything was there, because revoking is
// idempotent and "nothing to revoke" is success.
//
// What it does *not* do matters as much as what it does, and the UI has to say so:
// this is the local revocation. No data-source binding is removed and no upstream
// credential changes, so the player's other clients keep working and nothing at
// the source notices. Unbinding is a separate action with a separate consequence.
func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}

	clientID := strings.TrimSpace(r.PathValue("client_id"))
	if clientID == "" {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "a client id is required")
		return
	}
	if err := s.grants.RevokeGrant(r.Context(), string(user), clientID); err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not revoke the grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
