package httpapi

import (
	"net/http"

	"github.com/Re0Auth/r0semi/oauth"
)

// handleMe returns the authenticated account. It is the smallest business-plane
// endpoint and exists to prove the plane separation end to end.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, info oauth.TokenInfo) {
	if !s.requireScope(w, r, info, oauth.ScopeAccountID) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":        info.Subject,
		"client_id": info.ClientID,
		"scopes":    scopeStrings(info.Scopes),
	})
}

func scopeStrings(scopes []oauth.Scope) []string {
	out := make([]string, len(scopes))
	for i, s := range scopes {
		out[i] = s.String()
	}
	return out
}
