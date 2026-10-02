package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/authorization"
	"github.com/Re0Auth/r0semi/oauth"
)

// bindingRequirementView tells the consent screen which data source must be
// connected before the requested scopes can be served, and where to connect it.
type bindingRequirementView struct {
	Game        string   `json:"game"`
	Source      string   `json:"source"`
	DisplayName string   `json:"display_name"`
	Scopes      []string `json:"scopes"`
	// BindURL is server-built and returns to this consent screen. The frontend
	// navigates to it verbatim rather than assembling it.
	BindURL string `json:"bind_url"`
}

// missingBindingViews is the bridge between the consent screen and the data
// plane's binding state. It is advisory: approval still consults oauth.Authorize,
// and every data read still checks the binding.
func (s *Server) missingBindingViews(ctx context.Context, user account.UserID, scopes []oauth.Scope, id string) ([]bindingRequirementView, error) {
	views := []bindingRequirementView{}
	if s.federate == nil {
		return views, nil
	}
	reqs, err := s.federate.MissingBindings(ctx, user, scopeStrings(scopes))
	if err != nil {
		return nil, err
	}
	// Come back to the pending consent request after the source redirects here.
	returnTo := s.consent + "?id=" + url.QueryEscape(id)
	for _, req := range reqs {
		views = append(views, bindingRequirementView{
			Game:        req.Game,
			Source:      req.Source,
			DisplayName: req.DisplayName,
			Scopes:      req.Scopes,
			BindURL:     s.bindURL(req.Game, req.Source, returnTo),
		})
	}
	return views, nil
}

// authzBindKind namespaces the browser session binding for consent handles. It
// must be the same value the login hook binds with (cmd/re0auth).
const authzBindKind = "authz"

// consentHandle reports whether this browser may act on the handle in the path.
//
// Two conditions, and the caller answers both with the same 404, so a handle that
// belongs to another account is indistinguishable from one that does not exist:
//
//   - the session created it (Bound);
//   - and, when it was created while an account was signed in, that same account
//     still holds the session (OwnerMatches). A handle created before anyone signed
//     in has no owner and is usable by whoever signs in — that is the flow's normal
//     shape, not a gap.
//
// The second condition is what stops account A's request from being approved by
// account B after B signs in on the same browser. Rotating the session id on
// sign-in keeps the session's values on purpose, so without it the handle follows
// the browser rather than the account.
func (s *Server) consentHandle(r *http.Request, user account.UserID) (string, bool) {
	id := r.PathValue("id")
	if !s.authInteract.ValidID(id) || !s.sessions.Bound(r.Context(), authzBindKind, id) {
		return "", false
	}
	if !s.sessions.OwnerMatches(r.Context(), authzBindKind, id, user) {
		return "", false
	}
	return id, true
}

// handleGetAuthorizationRequest feeds the consent screen. It requires a signed
// in user and that the handle belongs to this browser's session, so a stolen
// handle is useless in another browser.
func (s *Server) handleGetAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	id, ok := s.consentHandle(r, user)
	if !ok {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown authorization request")
		return
	}
	view, err := s.authInteract.DescribeAuthorization(r.Context(), id)
	if err != nil {
		s.writeAuthorizationError(w, r, user, "describe", err)
		return
	}

	missing, err := s.missingBindingViews(r.Context(), user, view.Scopes, view.ID)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read data source bindings")
		return
	}

	// No-transform: this body carries the session's CSRF token, so it must not be
	// compressed (S10-4).
	writeJSONNoTransform(w, http.StatusOK, map[string]any{
		"id":               view.ID,
		"client":           map[string]string{"id": view.ClientID, "name": view.ClientName},
		"scopes":           s.scopeViews(view.Scopes),
		"missing_bindings": missing,
		"csrf_token":       s.sessions.CSRFToken(r.Context()),
	})
}

type decisionBody struct {
	Decision string   `json:"decision"`
	Scopes   []string `json:"scopes"`
	Explicit []string `json:"explicit"`
}

// handleAuthorizationDecision records the user's choice and returns the exact
// redirect the frontend must follow. The frontend never assembles the redirect
// itself.
func (s *Server) handleAuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return
	}
	id, ok := s.consentHandle(r, user)
	if !ok {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown authorization request")
		return
	}

	var body decisionBody
	if !s.decodeJSONBody(w, r, &body, 1<<20) {
		return
	}

	switch body.Decision {
	case "deny":
		redirect, err := s.authInteract.DenyAuthorization(r.Context(), id)
		if err != nil {
			s.writeAuthorizationError(w, r, user, "deny", err)
			return
		}
		s.sessions.Unbind(r.Context(), authzBindKind, id)
		writeJSON(w, http.StatusOK, map[string]string{"redirect_to": redirect})

	case "approve":
		redirect, err := s.authInteract.ApproveAuthorization(r.Context(), id, string(user), toScopes(body.Scopes), toScopes(body.Explicit))
		if err != nil {
			s.writeDecisionError(w, r, user, err)
			return
		}
		s.sessions.Unbind(r.Context(), authzBindKind, id)
		writeJSON(w, http.StatusOK, map[string]string{"redirect_to": redirect})

	default:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", `decision must be "approve" or "deny"`)
	}
}

func (s *Server) writeDecisionError(w http.ResponseWriter, r *http.Request, user account.UserID, err error) {
	var oe *oauth.Error
	switch {
	case errors.Is(err, authorization.ErrRequestExpired):
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request",
			"the authorization request is unknown or expired")
	case errors.As(err, &oe) && oe.Code == "access_denied":
		s.writeProblem(w, r, http.StatusForbidden, "explicit_consent_required", oe.Description)
	case errors.As(err, &oe):
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", oe.Description)
	default:
		s.recordAuthorizationFault(w, r, user, "decision", err)
	}
}

// writeAuthorizationError classifies a failure from the interaction seam's read
// paths (DescribeAuthorization, DenyAuthorization).
//
// The two answers a browser can receive are deliberately far apart (S04-7):
//
//   - the engine no longer holds the request (ErrRequestExpired) is the caller's
//     situation, answered as invalid_request — the same code the protocol plane
//     uses for a request that cannot be served;
//   - anything else is an engine fault. It is answered 500 with a generic detail
//     (the error text stays in the log and the audit row, never on the wire) and
//     recorded, because a consent screen that is broken for everyone has to be
//     visible to an operator, not disguised as "your link expired".
func (s *Server) writeAuthorizationError(w http.ResponseWriter, r *http.Request, user account.UserID, op string, err error) {
	if errors.Is(err, authorization.ErrRequestExpired) {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request",
			"the authorization request is unknown or expired")
		return
	}
	s.recordAuthorizationFault(w, r, user, op, err)
}

// recordAuthorizationFault logs an interaction-seam failure and writes the 500.
// The audit row names the operation and the account, never the error text: the
// subject is the account this consent screen was serving, and the detail is a
// closed set of step names.
func (s *Server) recordAuthorizationFault(w http.ResponseWriter, r *http.Request, user account.UserID, op string, err error) {
	slog.ErrorContext(r.Context(), "authorization interaction failed",
		"request_id", requestID(r), "operation", op, "err", err)
	if s.auditLog != nil {
		if rerr := s.auditLog.Record(r.Context(), audit.Event{
			Time:    time.Now().UTC(),
			Action:  "auth.authorization.fault",
			Subject: string(user),
			Outcome: audit.OutcomeError,
			Detail:  map[string]string{"operation": op},
		}); rerr != nil {
			slog.Error("audit record failed", "action", "auth.authorization.fault", "err", rerr)
		}
	}
	s.writeProblem(w, r, http.StatusInternalServerError, "internal_error",
		"the authorization request could not be served")
}

// scopeViews renders the scopes a consent screen displays.
//
// The displayed set must be a SUPERSET of the set the decision will grant
// (A-FE-3). A scope the catalogue does not describe used to be skipped, which
// silently removed it from the screen while the server still carried it through
// to the grant — the screen showed less than it granted. Every granted scope is
// rendered now; the ones with no descriptor get an explicit system-required
// placeholder rather than being dropped or silently granted.
func (s *Server) scopeViews(scopes []oauth.Scope) []map[string]any {
	out := make([]map[string]any, 0, len(scopes))
	for _, sc := range scopes {
		d, ok := s.scopes.Get(sc)
		if !ok {
			out = append(out, map[string]any{
				"scope":            sc.String(),
				"title":            "系统必需",
				"description":      "此项由授权服务器要求，权限目录中未单独描述。",
				"risk":             oauth.RiskLow.String(),
				"explicit_consent": false,
			})
			continue
		}
		out = append(out, map[string]any{
			"scope":            sc.String(),
			"title":            d.Title,
			"description":      d.Description,
			"risk":             d.Risk.String(),
			"explicit_consent": d.ExplicitConsent,
		})
	}
	return out
}

// toScopes converts wire scope strings. A nil input stays nil, because the
// difference between "the field was omitted" and "the field was an empty array"
// is part of the consent contract: omitted means grant the full request, empty
// means the caller explicitly approved nothing and is refused.
func toScopes(in []string) []oauth.Scope {
	if in == nil {
		return nil
	}
	out := make([]oauth.Scope, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, oauth.Scope(s))
		}
	}
	return out
}
