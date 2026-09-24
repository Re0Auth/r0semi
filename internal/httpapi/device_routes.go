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

	auth, err := s.devices.DescribeDeviceAuthorization(r.Context(), userCode)
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
	// Both conditions, one answer: the code must have been loaded by this session,
	// and — since loading it requires a signed-in user — by this same account. A
	// code loaded before an account switch is not approvable afterwards, for the
	// same reason a consent handle is not (see consentHandle).
	if !s.sessions.Bound(r.Context(), deviceBindKind, body.UserCode) ||
		!s.sessions.OwnerMatches(r.Context(), deviceBindKind, body.UserCode, user) {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown user code")
		return
	}

	err := s.devices.DecideDeviceAuthorization(r.Context(), body.UserCode, string(user),
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
