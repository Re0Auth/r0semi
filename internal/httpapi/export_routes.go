package httpapi

import (
	"fmt"
	"net/http"
	"time"
)

// accountExport is the whole of GET /v1/account/export: everything Re0Auth holds
// about the signed-in account, in one document.
//
// It is assembled from the same view builders the list endpoints use, not from a
// second set of structs. That is the point: a credential that never appears in
// GET /v1/bindings or GET /v1/grants cannot appear here either, because there is
// only one function that turns each record into its public shape.
type accountExport struct {
	ExportedAt string `json:"exported_at"`
	Profile    struct {
		UserID          string `json:"user_id"`
		PrimaryIdentity string `json:"primary_identity_id"`
		CreatedAt       string `json:"created_at"`
	} `json:"profile"`
	Identities []identityView `json:"identities"`
	Bindings   []bindingView  `json:"bindings"`
	Grants     []grantView    `json:"grants"`
	// Notice states, in the document itself, what is deliberately not here and
	// why. A data export that silently omits something looks complete; this one
	// says what it left out.
	Notice exportNotice `json:"notice"`
}

// exportNotice is the machine-readable counterpart of docs/api-design.md §4
// ("账号数据导出"). It records that the omission of credentials was a decision,
// not an oversight.
type exportNotice struct {
	// CredentialsExcluded is always true. It is a field rather than a comment so
	// a reader of the file can tell the omission was deliberate.
	CredentialsExcluded bool   `json:"credentials_excluded"`
	Reason              string `json:"reason"`
}

const exportCredentialsReason = "Upstream credentials (access and refresh tokens) are not included: " +
	"they are live secrets whose disclosure would let anyone act as this account at the source. " +
	"Re0Auth holds no password or platform credential to export. " +
	"To revoke a source's access, disconnect the binding instead."

// handleExportAccount returns the signed-in account's data as a downloadable
// document.
//
// Session-scoped and read-only, so no CSRF token is required: it changes
// nothing. Like the grants and bindings views it is session-scoped rather than
// bearer-scoped, and for the same reason — the answer names the user's other
// clients and connections, which a client asking with its own token has no claim
// to.
func (s *Server) handleExportAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessions.User(r.Context())
	if !ok {
		s.writeProblem(w, r, http.StatusUnauthorized, "unauthenticated", "no active session")
		return
	}
	ctx := r.Context()

	record, err := s.accounts.GetUser(ctx, user)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "account lookup failed")
		return
	}
	identities, err := s.accounts.Identities(ctx, user)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "identity lookup failed")
		return
	}
	grants, err := s.grants.Grants(ctx, string(user))
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read grants")
		return
	}

	var out accountExport
	out.ExportedAt = time.Now().UTC().Format(time.RFC3339)
	out.Profile.UserID = string(record.ID)
	out.Profile.PrimaryIdentity = string(record.PrimaryIdentity)
	out.Profile.CreatedAt = record.CreatedAt.UTC().Format(time.RFC3339)
	out.Identities = identityViews(identities)
	out.Grants = s.grantViews(grants)
	out.Notice = exportNotice{CredentialsExcluded: true, Reason: exportCredentialsReason}

	// Bindings come from the federation service, which is optional. A deployment
	// without data sources exports an empty list rather than omitting the section,
	// so the document's shape does not depend on the deployment.
	out.Bindings = []bindingView{}
	if s.federate != nil {
		bindings, err := s.federate.Bindings(ctx, user)
		if err != nil {
			s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read bindings")
			return
		}
		out.Bindings = s.bindingViews(bindings)
	}

	// The filename names the account, so two exports from one browser do not
	// overwrite each other ambiguously.
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "re0auth-account-"+string(user)+".json"))
	writeJSON(w, http.StatusOK, out)
}
