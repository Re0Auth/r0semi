package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Re0Auth/r0semi/oauth"
)

// deviceBindKind namespaces the browser session binding for device approvals.
const deviceBindKind = "device"

// handleDeviceAuthorization implements RFC 8628 §3.1/§3.2. The client asks for
// a device_code and receives the user_code and verification URI to show the
// user. The device_code is returned exactly once and never again.
func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	clientID, _ := oauth.ClientCredentials(r)
	resp, err := s.as.BeginDeviceAuthorization(r.Context(), oauth.DeviceAuthorizationRequest{
		ClientID: clientID,
		Scopes:   parseScopes(r.PostFormValue("scope")),
	})
	if err != nil {
		s.writeProtocolError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               resp.DeviceCode,
		"user_code":                 resp.UserCode,
		"verification_uri":          resp.VerificationURI,
		"verification_uri_complete": resp.VerificationURIComplete,
		"expires_in":                resp.ExpiresIn,
		"interval":                  resp.Interval,
	})
}

// handleDeviceVerification is the browser page the user reaches after entering
// the user_code. It requires a signed-in user and binds the code to this
// browser's session, so a code relayed by an attacker cannot be approved from
// somewhere else.
func (s *Server) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.User(r.Context()); !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		// The frontend renders a code entry form; nothing is bound yet.
		writeJSON(w, http.StatusOK, map[string]any{"state": "awaiting_code"})
		return
	}

	auth, err := s.as.DescribeDeviceAuthorization(r.Context(), userCode)
	switch {
	case errors.Is(err, oauth.ErrDeviceNotFound):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown or expired user code")
		return
	case err != nil:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	s.sessions.Bind(r.Context(), deviceBindKind, auth.UserCode)
	writeJSON(w, http.StatusOK, map[string]any{
		"state":      "pending",
		"user_code":  auth.UserCode,
		"client":     map[string]string{"id": auth.Client.ID, "name": auth.Client.Name},
		"scopes":     s.scopeViews(uniqueScopes(auth.Scopes)),
		"expires_at": auth.ExpiresAt,
		"csrf_token": s.sessions.CSRFToken(r.Context()),
	})
}

type deviceDecisionBody struct {
	UserCode string   `json:"user_code"`
	Decision string   `json:"decision"`
	Scopes   []string `json:"scopes"`
	Explicit []string `json:"explicit"`
}

// handleDeviceDecision records the user's approval or denial for a user code
// they loaded in this browser.
func (s *Server) handleDeviceDecision(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}
	var body deviceDecisionBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if !s.sessions.Bound(r.Context(), deviceBindKind, body.UserCode) {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown user code")
		return
	}

	err := s.as.DecideDeviceAuthorization(r.Context(), body.UserCode, string(user),
		body.Decision == "approve", toScopes(body.Scopes), toScopes(body.Explicit))
	switch {
	case errors.Is(err, oauth.ErrDeviceNotFound):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown or expired user code")
		return
	case err != nil:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"state": map[bool]string{true: "approved", false: "denied"}[body.Decision == "approve"],
	})
}

func uniqueScopes(descriptors []oauth.Descriptor) []oauth.Scope {
	out := make([]oauth.Scope, 0, len(descriptors))
	for _, d := range descriptors {
		out = append(out, d.Scope)
	}
	return out
}
