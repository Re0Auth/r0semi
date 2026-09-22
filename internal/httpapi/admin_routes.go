package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/oauth"
)

// adminClientView is the operator's view of a registration. It never carries the
// secret: only a hash is stored, so there is nothing to show even to an operator.
type adminClientView struct {
	ClientID      string   `json:"client_id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Status        string   `json:"status"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	CreatedAt     string   `json:"created_at"`
}

func newAdminClientView(c oauth.Client) adminClientView {
	status := string(c.Status)
	if status == "" {
		status = string(oauth.ClientActive)
	}
	scopes := make([]string, 0, len(c.AllowedScopes))
	for _, sc := range c.AllowedScopes {
		scopes = append(scopes, sc.String())
	}
	uris := c.RedirectURIs
	if uris == nil {
		uris = []string{}
	}
	return adminClientView{
		ClientID:      c.ID,
		Name:          c.Name,
		Type:          string(c.Type),
		Status:        status,
		RedirectURIs:  uris,
		AllowedScopes: scopes,
		CreatedAt:     c.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// requireAdmin authenticates the caller and checks the allowlist.
//
// A signed-in non-admin is answered 404, not 403: the operator plane is not
// advertised to people who cannot use it, and whether it exists is not something
// an ordinary account needs to learn.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.sessions == nil {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown resource")
		return false
	}
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return false
	}
	if !s.adminAllowed[user] {
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown resource")
		return false
	}
	return true
}

// requireAdminWrite is requireAdmin plus the CSRF check every mutating admin
// endpoint needs. Both conditions produce a documented problem code.
func (s *Server) requireAdminWrite(w http.ResponseWriter, r *http.Request) bool {
	if !s.requireAdmin(w, r) {
		return false
	}
	if !s.sessions.ValidCSRF(r) {
		s.writeProblem(w, r, http.StatusForbidden, "invalid_request", "missing or invalid CSRF token")
		return false
	}
	return true
}

func (s *Server) handleAdminListClients(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	clients, err := s.adminSvc.ListClients(r.Context())
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not list clients")
		return
	}
	views := make([]adminClientView, 0, len(clients))
	for _, c := range clients {
		views = append(views, newAdminClientView(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":       views,
		"csrf_token": s.sessions.CSRFToken(r.Context()),
	})
}

type adminRegisterRequest struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
}

// handleAdminRegisterClient registers a downstream application. The plaintext
// secret is returned exactly once, here; a later read cannot recover it.
func (s *Server) handleAdminRegisterClient(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminWrite(w, r) {
		return
	}
	var body adminRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	typ := oauth.ClientType(body.Type)
	if typ == "" {
		typ = oauth.ClientPublic
	}
	user, _ := s.sessions.User(r.Context())
	reg, err := s.adminSvc.Register(r.Context(), string(user), admin.RegisterRequest{
		Name:          body.Name,
		Type:          typ,
		RedirectURIs:  body.RedirectURIs,
		AllowedScopes: toScopes(body.Scopes),
	})
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	resp := map[string]any{"client": newAdminClientView(reg.Client)}
	if reg.Secret != "" {
		resp["client_secret"] = reg.Secret
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleAdminSuspendClient(w http.ResponseWriter, r *http.Request) {
	s.adminSetClientStatus(w, r, true)
}

func (s *Server) handleAdminActivateClient(w http.ResponseWriter, r *http.Request) {
	s.adminSetClientStatus(w, r, false)
}

func (s *Server) adminSetClientStatus(w http.ResponseWriter, r *http.Request, suspend bool) {
	if !s.requireAdminWrite(w, r) {
		return
	}
	clientID := r.PathValue("client_id")
	user, _ := s.sessions.User(r.Context())

	var err error
	if suspend {
		err = s.adminSvc.SuspendClient(r.Context(), string(user), clientID)
	} else {
		err = s.adminSvc.ActivateClient(r.Context(), string(user), clientID)
	}
	switch {
	case errors.Is(err, admin.ErrNotFound):
		s.writeProblem(w, r, http.StatusNotFound, "not_found", "unknown client")
	case err != nil:
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not change the client status")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleAdminDeleteClient(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminWrite(w, r) {
		return
	}
	user, _ := s.sessions.User(r.Context())
	if err := s.adminSvc.DeleteClient(r.Context(), string(user), r.PathValue("client_id")); err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not delete the client")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type killSwitchRequest struct {
	Target   string `json:"target"`
	ClientID string `json:"client_id"`
	Subject  string `json:"subject"`
}

// handleAdminKillSwitch revokes tokens (and, deployment-wide, sessions) in bulk.
// The response reports what was actually cut rather than a bare 204, because the
// number is the thing an incident responder needs.
func (s *Server) handleAdminKillSwitch(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminWrite(w, r) {
		return
	}
	var body killSwitchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	var target admin.Target
	switch body.Target {
	case "all":
		target.All = true
	case "client":
		target.ClientID = body.ClientID
	case "subject":
		target.Subject = body.Subject
	case "bindings":
		target.Bindings = true
	default:
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", `target must be "all", "client", "subject" or "bindings"`)
		return
	}

	user, _ := s.sessions.User(r.Context())
	report, err := s.adminSvc.KillSwitch(r.Context(), string(user), target)
	switch {
	case errors.Is(err, admin.ErrInvalidTarget):
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "the target is incomplete")
	case errors.Is(err, admin.ErrBindingsUnavailable):
		s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "this deployment has no data sources to revoke")
	case err != nil:
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "the kill switch could not complete")
	default:
		writeJSON(w, http.StatusOK, report)
	}
}
