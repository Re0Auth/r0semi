package httpapi

import "net/http"

// handleResourceMetadata implements RFC 9728 protected resource metadata.
func (s *Server) handleResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"scopes_supported":         s.scopeCatalog(),
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *Server) scopeCatalog() []string {
	descriptors := s.scopes.Descriptors()
	out := make([]string, len(descriptors))
	for i, d := range descriptors {
		out[i] = d.Scope.String()
	}
	return out
}
