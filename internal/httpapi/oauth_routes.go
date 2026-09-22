package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/oauth"
)

type tokenResponseBody struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	clientID, clientSecret := oauth.ClientCredentials(r)

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		resp, err := s.as.Exchange(r.Context(), oauth.CodeExchangeRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Code:         r.PostFormValue("code"),
			RedirectURI:  r.PostFormValue("redirect_uri"),
			CodeVerifier: r.PostFormValue("code_verifier"),
		})
		if err != nil {
			s.writeTokenError(w, r, err)
			return
		}
		s.writeToken(w, resp)

	case "refresh_token":
		resp, err := s.as.Refresh(r.Context(), oauth.RefreshRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RefreshToken: r.PostFormValue("refresh_token"),
			Scopes:       parseScopes(r.PostFormValue("scope")),
		})
		if err != nil {
			s.writeTokenError(w, r, err)
			return
		}
		s.writeToken(w, resp)

	case "urn:ietf:params:oauth:grant-type:device_code":
		resp, err := s.as.PollDeviceAuthorization(r.Context(), oauth.DeviceCodeExchangeRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			DeviceCode:   r.PostFormValue("device_code"),
		})
		if err != nil {
			s.writeTokenError(w, r, err)
			return
		}
		s.writeToken(w, resp)

	default:
		writeOAuthError(w, r, http.StatusBadRequest, "unsupported_grant_type",
			"supported grants: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:device_code")
	}
}

func (s *Server) writeToken(w http.ResponseWriter, resp oauth.TokenResponse) {
	// RFC 6749 §5.1 requires these on every token response.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponseBody{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		RefreshToken: resp.RefreshToken,
		Scope:        resp.Scope,
	})
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	clientID, clientSecret := oauth.ClientCredentials(r)
	if err := s.as.AuthenticateClient(r.Context(), clientID, clientSecret); err != nil {
		s.writeProtocolError(w, r, err)
		return
	}

	info, err := s.as.Introspect(r.Context(), r.PostFormValue("token"))
	if err != nil {
		writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "introspection failed")
		return
	}
	// RFC 7662: an inactive token is reported as {"active": false}, not an error.
	body := map[string]any{"active": info.Active}
	if info.Active {
		body["sub"] = info.Subject
		body["client_id"] = info.ClientID
		body["scope"] = joinScopes(info.Scopes)
		body["token_type"] = "Bearer"
		body["exp"] = info.ExpiresAt.Unix()
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	clientID, clientSecret := oauth.ClientCredentials(r)
	err := s.as.Revoke(r.Context(), oauth.RevokeRequest{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Token:         r.PostFormValue("token"),
		TokenTypeHint: r.PostFormValue("token_type_hint"),
	})
	if err != nil {
		s.writeProtocolError(w, r, err)
		return
	}
	// RFC 7009: revocation always succeeds with 200, even for an unknown token.
	w.WriteHeader(http.StatusOK)
}

// handleAuthorize is the protocol-plane controller. It validates nothing by
// itself: it captures the request into a server-side handle (authz.Begin) and
// redirects the browser to the consent UI, so every security decision stays on
// the server.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.authz == nil {
		writeOAuthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable",
			"the authorization endpoint is not yet available")
		return
	}
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		writeOAuthError(w, r, http.StatusBadRequest, "unsupported_response_type",
			"only response_type=code is supported")
		return
	}

	req, err := s.authz.Begin(r.Context(), authz.BeginInput{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scopes:              parseScopes(q.Get("scope")),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	})
	if err != nil {
		s.writeAuthorizeError(w, r, q.Get("redirect_uri"), q.Get("state"), err)
		return
	}

	s.sessions.Bind(r.Context(), "authz", req.ID)
	http.Redirect(w, r, s.consent+"?id="+url.QueryEscape(req.ID), http.StatusFound)
}

// writeAuthorizeError redirects scope/consent failures back to the client (the
// redirect_uri has already been validated at that point) and reports everything
// else as a JSON OAuth error, never redirecting to an unvalidated URI.
func (s *Server) writeAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state string, err error) {
	var oe *oauth.Error
	if errors.As(err, &oe) {
		if redirectURI != "" && (oe.Code == "invalid_scope" || oe.Code == "access_denied") {
			redirectOAuthError(w, r, redirectURI, state, oe.Code, oe.Description)
			return
		}
		writeOAuthError(w, r, oauthStatus(oe.Code), oe.Code, oe.Description)
		return
	}
	writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "internal error")
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	params := map[string]string{"error": code, "state": state}
	if description != "" {
		params["error_description"] = description
	}
	http.Redirect(w, r, oauth.BuildRedirect(redirectURI, params), http.StatusFound)
}

func parseScopes(s string) []oauth.Scope {
	if s == "" {
		return nil
	}
	fields := strings.Fields(s)
	out := make([]oauth.Scope, len(fields))
	for i, f := range fields {
		out[i] = oauth.Scope(f)
	}
	return out
}

func joinScopes(scopes []oauth.Scope) string {
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = s.String()
	}
	return strings.Join(parts, " ")
}

func (s *Server) writeProtocolError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauth.Error
	if errors.As(err, &oe) {
		writeOAuthError(w, r, oauthStatus(oe.Code), oe.Code, oe.Description)
		return
	}
	writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "internal error")
}

// writeTokenError maps a token-endpoint error. RFC 6749 §5.2 makes every token
// error a 400 except invalid_client, which is 401. RFC 8628 device-flow errors
// (authorization_pending, slow_down, access_denied, expired_token) ride that same
// response shape, which is why access_denied is 400 here and not 403.
func (s *Server) writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauth.Error
	if errors.As(err, &oe) {
		status := http.StatusBadRequest
		if oe.Code == "invalid_client" {
			status = http.StatusUnauthorized
		}
		writeOAuthError(w, r, status, oe.Code, oe.Description)
		return
	}
	writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "internal error")
}

func oauthStatus(code string) int {
	switch code {
	case "invalid_client":
		return http.StatusUnauthorized
	case "access_denied":
		return http.StatusForbidden
	case "temporarily_unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}
