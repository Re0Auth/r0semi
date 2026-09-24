package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// auditEntryView is one audit record as an operator sees it.
type auditEntryView struct {
	ID int64 `json:"id"`
	// Time is when the emitting component said the event happened, which is a
	// caller-supplied clock. Entries are ordered by ID, not by this, so a skewed or
	// backdated timestamp cannot reorder history.
	Time     string `json:"time"`
	Action   string `json:"action"`
	Provider string `json:"provider"`
	Outcome  string `json:"outcome"`
	// Subject is the pseudonym the log stores, never the account id. It links one
	// account's events to each other and to nothing else — and after that account is
	// erased, not even that.
	Subject string            `json:"subject,omitempty"`
	Detail  map[string]string `json:"detail"`
}

// auditVerifyView is the chain check's outcome.
type auditVerifyView struct {
	OK      bool `json:"ok"`
	Chained int  `json:"chained"`
	// Legacy counts rows written before the chain existed. They are reported, not
	// hidden: a verification that silently skipped them would overstate its reach.
	Legacy     int    `json:"legacy"`
	FirstBadID int64  `json:"first_bad_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// handleAdminAudit reads the audit log. Operator-only: it can see every account's
// activity, which is exactly why it is not on the user-facing surface.
func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	query := r.URL.Query()

	q := audit.Query{
		Subject: strings.TrimSpace(query.Get("subject")),
		Action:  strings.TrimSpace(query.Get("action")),
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
			return
		}
		q.Limit = limit
	}
	if raw := strings.TrimSpace(query.Get("cursor")); raw != "" {
		before, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || before < 1 {
			s.writeProblem(w, r, http.StatusBadRequest, "invalid_request", "cursor is not a value this endpoint issued")
			return
		}
		q.Before = before
	}
	for _, f := range []struct {
		name   string
		target *time.Time
	}{
		{"since", &q.Since},
		{"until", &q.Until},
	} {
		raw := strings.TrimSpace(query.Get(f.name))
		if raw == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			s.writeProblem(w, r, http.StatusBadRequest, "invalid_request",
				f.name+" must be an RFC 3339 timestamp")
			return
		}
		// A value that parses to Go's zero time (e.g. 0001-01-01T00:00:00Z) is
		// refused rather than dropped. The reader treats the zero time as "no
		// bound", so accepting it silently would widen the result set to the whole
		// log while the caller believed they had narrowed it — and `until` is the
		// direction that leaks more than was asked for. A filter that cannot be
		// honoured is refused, not ignored.
		if parsed.IsZero() {
			s.writeProblem(w, r, http.StatusBadRequest, "invalid_request",
				f.name+" is out of range")
			return
		}
		*f.target = parsed
	}

	page, err := s.auditReader.Query(r.Context(), q)
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read the audit log")
		return
	}

	views := make([]auditEntryView, 0, len(page.Entries))
	for _, e := range page.Entries {
		detail := e.Detail
		if detail == nil {
			detail = map[string]string{}
		}
		views = append(views, auditEntryView{
			ID:       e.ID,
			Time:     e.Time.UTC().Format(time.RFC3339),
			Action:   e.Action,
			Provider: e.Provider,
			Outcome:  e.Outcome,
			Subject:  e.Subject,
			Detail:   detail,
		})
	}

	body := map[string]any{
		"data":       views,
		"pagination": map[string]any{"limit": page.Limit},
	}
	if page.NextBefore > 0 {
		body["pagination"].(map[string]any)["next_cursor"] = strconv.FormatInt(page.NextBefore, 10)
	}
	writeJSON(w, http.StatusOK, body)
}

// handleAdminAuditVerify walks the record chain and reports the first row that
// does not hold up. Read-only, but operator-only: it is a statement about the
// integrity of the whole log, including accounts the caller does not own.
func (s *Server) handleAdminAuditVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	v, err := s.auditReader.Verify(r.Context())
	if err != nil {
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not verify the audit log")
		return
	}
	writeJSON(w, http.StatusOK, auditVerifyView{
		OK:         v.OK,
		Chained:    v.Chained,
		Legacy:     v.Legacy,
		FirstBadID: v.FirstBadID,
		Reason:     v.Reason,
	})
}
