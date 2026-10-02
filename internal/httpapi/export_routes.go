package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// accountExport is GET /v1/account/export: the account's profile, its linked
// identities, its connected data sources and the grants it has issued, in one
// document.
//
// It is assembled from the same view builders the list endpoints use, not from a
// second set of structs. That is the point: a credential that never appears in
// GET /v1/bindings or GET /v1/grants cannot appear here either, because there is
// only one function that turns each record into its public shape.
//
// It is deliberately not "everything Re0Auth holds". Browser sessions, the tokens
// the account has issued to clients, and the audit history about it are left out,
// and the notice below says so rather than letting the document look complete
// (S11-8).
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
// ("账号数据导出"). It records that the omissions were a decision, not an
// oversight.
type exportNotice struct {
	// CredentialsExcluded is always true. It is a field rather than a comment so
	// a reader of the file can tell the omission was deliberate.
	CredentialsExcluded bool `json:"credentials_excluded"`
	// Reason enumerates every deliberate omission, not only the credentials one:
	// a notice that named credentials alone implied the rest of the document was
	// the whole record, which it is not (S11-8).
	Reason string `json:"reason"`
}

const exportCredentialsReason = "Upstream credentials (access and refresh tokens) are not included: " +
	"they are live secrets whose disclosure would let anyone act as this account at the source. " +
	"Re0Auth holds no password or platform credential to export. " +
	"To revoke a source's access, disconnect the binding instead. " +
	"Also deliberately absent, and not an oversight: browser sessions, the access and refresh " +
	"tokens this account has issued to clients, and the audit history recorded about the account. " +
	"Sessions and issued tokens are live credentials of the same kind as the ones above, and the " +
	"audit history is pseudonymised operator data, not a copy of the account's own record. " +
	"This document is therefore the account's profile, linked identities, connected sources and " +
	"issued grants — not every record the service holds about it."

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
		s.writeAccountError(w, r, err, "account lookup failed")
		return
	}
	identities, err := s.accounts.Identities(ctx, user)
	if err != nil {
		s.writeAccountError(w, r, err, "identity lookup failed")
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

	// The export leaves the service with a complete copy of one account's personal
	// data, so it is recorded: the account is the subject (a live one, so the sink
	// can pseudonymise it), and the counts describe the shape without carrying any
	// of the data.
	s.recordAudit(ctx, "account.export", string(user), map[string]string{
		"identities": strconv.Itoa(len(out.Identities)),
		"bindings":   strconv.Itoa(len(out.Bindings)),
		"grants":     strconv.Itoa(len(out.Grants)),
	})

	// The filename names the account, so two exports from one browser do not
	// overwrite each other ambiguously.
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "re0auth-account-"+string(user)+".json"))
	writeJSON(w, http.StatusOK, out)
}
