package httpapi

import (
	"net/http"
)

// idpProviderView is one offered identity provider.
//
// DisplayName is operator configuration, not a UI translation: the deployment
// names its providers (GitHub; a self-hosted "Authentik") and the frontend shows
// exactly that. The service does not invent English strings for its own UI.
type idpProviderView struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	StartURL    string `json:"start_url"`
}

// handleIDPProviders lists the identity providers this deployment offers.
//
// Without it a frontend can only guess, and a guessed button leads to a 404 from
// the login plane — the sort of dead end that looks like a bug in the login
// rather than a provider that was never configured.
//
// It is public on purpose: the set of login options is visible on any sign-in
// page anyway, and requiring a session to learn how to get one would be
// circular.
func (s *Server) handleIDPProviders(w http.ResponseWriter, _ *http.Request) {
	providers := s.auth.Providers()
	views := make([]idpProviderView, 0, len(providers))
	for _, p := range providers {
		views = append(views, idpProviderView{
			ID:          string(p),
			DisplayName: s.auth.ProviderLabel(p),
			// Same origin, and relative to the issuer so that a deployment behind
			// a path prefix is described correctly.
			StartURL: s.issuer + "/auth/" + string(p) + "/start",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": views})
}
