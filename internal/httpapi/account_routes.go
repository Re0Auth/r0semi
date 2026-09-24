package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/Re0Auth/r0semi/internal/lifecycle"
)

// deleteAccountRequest is the body a deletion must carry.
type deleteAccountRequest struct {
	// Acknowledge must name the consequence, exactly as the cascade revocation
	// requires. Deletion cannot be undone, so it cannot happen because a client
	// sent a DELETE with nothing else in it: the caller has to write down what it
	// is about to do. The value is a constant on purpose — a speed bump with a
	// label, not a configurable field.
	Acknowledge string `json:"acknowledge"`
}

// deleteAccountAcknowledgement is the exact string the request must carry.
const deleteAccountAcknowledgement = "deletes_my_account"

// handleDeleteAccount erases the signed-in account across every store.
//
// Session-scoped with CSRF, like every other write on the account. The response
// is a body describing what was removed rather than a 204: the account is gone
// and its sessions are dropped, so the caller has no way to check for itself, and
// a silent success would be the only record it ever sees.
func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}

	var body deleteAccountRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if body.Acknowledge != deleteAccountAcknowledgement {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request",
			`acknowledge must be "`+deleteAccountAcknowledgement+`": this erases the account and cannot be undone`)
		return
	}

	result, err := s.deleter.DeleteAccount(r.Context(), user, user)
	if err != nil {
		// The stores are idempotent, so a failure is retryable and the message
		// says so rather than implying the account is in an unknown state.
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error",
			"the account could not be erased; it is safe to try again")
		return
	}

	// The session is gone as of the erasure, so destroy the cookie for this
	// response: without this the browser keeps a cookie pointing at a row that no
	// longer exists. SignOut also clears the session→subject index entry.
	if err := s.sessions.SignOut(r.Context()); err != nil {
		// The erasure succeeded; only the local cookie cleanup failed. The session
		// row is already deleted by the erasure itself, so the practical effect is
		// nil, and turning the whole request into a 500 would tell the caller the
		// deletion failed when it did not.
		slog.Warn("could not clear the session after account erasure", "user", string(user), "err", err)
	}
	writeJSON(w, http.StatusOK, deleteAccountView{
		Result: result,
	})
}

// deleteAccountView is the response body: what was removed, per store, so the
// caller is told the shape of the erasure rather than only that it happened.
type deleteAccountView struct {
	Result lifecycle.Result `json:"result"`
}
