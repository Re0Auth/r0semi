package httpapi

import "net/http"

// handleASMetadata implements RFC 8414 authorization server metadata.
func (s *Server) handleASMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/oauth/authorize",
		"token_endpoint":                        s.issuer + "/oauth/token",
		"revocation_endpoint":                   s.issuer + "/oauth/revoke",
		"introspection_endpoint":                s.issuer + "/oauth/introspect",
		"device_authorization_endpoint":         s.issuer + "/oauth/device_authorization",
		"scopes_supported":                      s.scopeCatalog(),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

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
