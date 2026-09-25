package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
)

// handleListIdentities lists the external identities linked to the signed-in
// account.
//
// Session-scoped like the grants and bindings views: an identity is part of how
// an account logs in, and a downstream client asking with its own token has no
// business enumerating the user's other login methods.
func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	identities, err := s.accounts.Identities(r.Context(), user)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "identity lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": identityViews(identities)})
}

// handleUnlinkIdentity removes one linked identity.
//
// It is a write, so it needs the CSRF token, and it is the one operation that can
// lock a user out of their own account: account.Store enforces I-2, so removing
// the last identity fails with 409 rather than orphaning the account.
//
// The response is 204: unlike disconnecting a source, there is no second half
// that could have gone differently.
func (s *Server) handleUnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}

	id := account.IdentityID(r.PathValue("id"))
	if id == "" {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "an identity id is required")
		return
	}

	switch err := s.accounts.UnlinkIdentity(r.Context(), user, id); {
	case err == nil:
		s.recordUnlinkAudit(r.Context(), string(user), string(id))
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, account.ErrLastIdentity):
		// I-2. Reaching this means the UI offered a button it should not have,
		// or a caller constructed the request by hand; either way the account is
		// untouched and the message says why.
		s.writeProblem(w, r, http.StatusConflict, "last_identity",
			"the last linked identity cannot be removed: it is the only way to sign in")
	case errors.Is(err, account.ErrNotFound):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown identity")
	default:
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not unlink the identity")
	}
}

// recordUnlinkAudit records an identity unlink. A write failure is logged, not
// returned: the identity is already gone, and a 500 over a missing audit line
// would report a completed action as failed.
func (s *Server) recordUnlinkAudit(ctx context.Context, subject, identityID string) {
	if s.auditLog == nil {
		return
	}
	if err := s.auditLog.Record(ctx, audit.Event{
		Time:    time.Now().UTC(),
		Action:  "auth.identity.unlink",
		Subject: subject,
		Outcome: audit.OutcomeOK,
		Detail:  map[string]string{"identity_id": identityID},
	}); err != nil {
		slog.Error("audit record failed", "action", "auth.identity.unlink", "err", err)
	}
}
