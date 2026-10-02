package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/oauth"
)

// deviceBindKind namespaces the browser session binding for device approvals.
const deviceBindKind = "device"

// deviceProblem classifies an error from the device engine into the business
// plane's answer. It is a pure function so the one property that matters — an
// internal fault never carries its text to the caller — is testable without
// standing up the server. The problem code stays "invalid_request" for every
// protocol error on purpose: the closed catalogue does not contain the OAuth
// codes (invalid_scope, access_denied), and widening it would break the
// server/spec/frontend equality test.
func deviceProblem(err error) (status int, code, detail string) {
	var oauthErr *oauth.Error
	switch {
	case errors.Is(err, oauth.ErrDeviceNotFound), errors.Is(err, oauth.ErrClientNotFound):
		return http.StatusNotFound, "not_found", "unknown or expired user code"
	case errors.As(err, &oauthErr):
		return http.StatusBadRequest, "invalid_request", oauthErr.Description
	default:
		return http.StatusInternalServerError, "internal_error", "could not complete the request"
	}
}

// writeDeviceProblem renders a device-engine failure. Only the internal case is
// logged here; the two client-facing cases are the caller's own fault and carry
// their own description.
func (s *Server) writeDeviceProblem(w http.ResponseWriter, r *http.Request, err error) {
	status, code, detail := deviceProblem(err)
	if status == http.StatusInternalServerError {
		slog.ErrorContext(r.Context(), "device request failed", "request_id", requestID(r), "err", err)
	}
	s.writeProblem(w, r, status, code, detail)
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
	// The lookup is case- and separator-insensitive (oauth.NormalizeUserCode), so
	// the caller's exact bytes must never become the session handle: the
	// verification page used to bind the spelling it was sent, which made the
	// bound id as long as the request line. Normalise before looking up and bind
	// only what comes back (Z07-3).
	userCode := oauth.NormalizeUserCode(r.URL.Query().Get("user_code"))
	if userCode == "" {
		// The frontend renders a code entry form; nothing is bound yet.
		writeJSON(w, http.StatusOK, map[string]any{"state": "awaiting_code"})
		return
	}

	auth, err := s.devices.DescribeDeviceAuthorization(r.Context(), userCode)
	if err != nil {
		s.writeDeviceProblem(w, r, err)
		return
	}

	s.sessions.Bind(r.Context(), deviceBindKind, auth.UserCode)
	// No-transform: this body carries the session's CSRF token, so it must not be
	// compressed (S10-4).
	writeJSONNoTransform(w, http.StatusOK, map[string]any{
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
	if !s.decodeJSONBody(w, r, &body, 1<<20) {
		return
	}
	// The handle was bound under the normalised spelling, so the decision must be
	// looked up under it too. Without this, a browser that entered the code the
	// device printed (hyphenated) could never decide the grant the page had just
	// shown as pending, and two spellings of one code disagreed about whether the
	// handle exists (Z07-3).
	body.UserCode = oauth.NormalizeUserCode(body.UserCode)
	// Both conditions, one answer: the code must have been loaded by this session,
	// and — since loading it requires a signed-in user — by this same account. A
	// code loaded before an account switch is not approvable afterwards, for the
	// same reason a consent handle is not (see consentHandle).
	if !s.sessions.Bound(r.Context(), deviceBindKind, body.UserCode) ||
		!s.sessions.OwnerMatches(r.Context(), deviceBindKind, body.UserCode, user) {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown user code")
		return
	}

	// The decision is a closed enum on the wire, so anything else is refused
	// before the code is touched. It used to be read as `approve == (decision ==
	// "approve")`, which turned a typo into a denial — and consumed the user code
	// doing it, so the browser could neither approve nor retry the grant it had
	// just been shown (Z08-7). This is the same whitelist the consent endpoint
	// applies to its own `decision`.
	switch body.Decision {
	case "approve", "deny":
	default:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", `decision must be "approve" or "deny"`)
		return
	}

	err := s.devices.DecideDeviceAuthorization(r.Context(), body.UserCode, string(user),
		body.Decision == "approve", toScopes(body.Scopes), toScopes(body.Explicit))
	if err != nil {
		// A code the store no longer knows is a dead handle, so it is released
		// rather than left in the session; anything else may be retried against the
		// same handle.
		if errors.Is(err, oauth.ErrDeviceNotFound) {
			s.sessions.Unbind(r.Context(), deviceBindKind, body.UserCode)
		}
		s.writeDeviceProblem(w, r, err)
		return
	}
	// Consumed. The consent screen releases its handle the same way; a device
	// handle used to outlive its decision, and nothing ever removed it — every
	// code a browser had ever loaded stayed in the session for the life of the
	// cookie.
	s.sessions.Unbind(r.Context(), deviceBindKind, body.UserCode)
	decision := observability.DeviceDenied
	if body.Decision == "approve" {
		decision = observability.DeviceApproved
	}
	s.metrics.ObserveDeviceDecision(decision)
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
