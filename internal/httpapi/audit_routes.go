package httpapi

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/observability"
)

// recordAudit writes one event this layer owns. A write failure is logged, not
// returned: the action already happened, and a 500 over a missing audit line
// would report a completed action as failed.
func (s *Server) recordAudit(ctx context.Context, action, subject string, detail map[string]string) {
	s.recordAuditOutcome(ctx, action, subject, audit.OutcomeOK, detail)
}

// recordAuditOutcome is recordAudit with an explicit outcome, for the reads whose
// own failure is the event worth recording (the two audit walks).
func (s *Server) recordAuditOutcome(ctx context.Context, action, subject, outcome string, detail map[string]string) {
	if s.auditLog == nil {
		return
	}
	if err := s.auditLog.Record(ctx, audit.Event{
		Time:    time.Now().UTC(),
		Action:  action,
		Subject: subject,
		Outcome: outcome,
		Detail:  detail,
	}); err != nil {
		slog.Error("audit record failed", "action", action, "err", err)
	}
}

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

	// Opening this window is itself auditable: it is the widest read of personal
	// data the service offers, and before this nothing recorded that it happened.
	// The subject is the OPERATOR (a live account), never the queried subject — a
	// raw id in the record for a subject whose pseudonym key was destroyed would
	// make the sink mint a fresh key and re-link the erased account. The filters
	// are recorded as shapes, not values.
	if caller, ok := s.sessions.User(r.Context()); ok {
		s.recordAudit(r.Context(), "admin.audit.read", string(caller), map[string]string{
			"subject_filter": strconv.FormatBool(q.Subject != ""),
			"action_filter":  strconv.FormatBool(q.Action != ""),
			"entries":        strconv.Itoa(len(page.Entries)),
		})
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
	// One walk at a time. Verify reads the whole chain on a single pooled
	// connection and can take tens of seconds, so N concurrent callers are N
	// long-lived pool acquisitions: enough of them starve the rest of the service.
	// The second caller is refused promptly and told when to come back rather than
	// being queued, which would just move the pile-up to the queue.
	if !s.auditVerifyBusy.CompareAndSwap(false, true) {
		w.Header().Set("Retry-After", "5")
		s.writeProblem(w, r, http.StatusServiceUnavailable, "temporarily_unavailable",
			"an audit verification is already running")
		return
	}
	defer s.auditVerifyBusy.Store(false)
	v, err := s.auditReader.Verify(r.Context())
	if err != nil {
		s.metrics.ObserveAuditVerify(observability.VerifyError)
		// The walk itself is audited, failure and success alike. Verify reads
		// every account's history; it is the widest read the service offers, and
		// the paged read was the only one that left a record (Z10-6).
		if caller, ok := s.sessions.User(r.Context()); ok {
			s.recordAuditOutcome(r.Context(), "admin.audit.verify", string(caller), audit.OutcomeError, nil)
		}
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not verify the audit log")
		return
	}
	result := observability.VerifyOK
	if !v.OK {
		result = observability.VerifyFailed
	}
	s.metrics.ObserveAuditVerify(result)
	if caller, ok := s.sessions.User(r.Context()); ok {
		detail := map[string]string{
			"ok":      strconv.FormatBool(v.OK),
			"chained": strconv.Itoa(v.Chained),
			"legacy":  strconv.Itoa(v.Legacy),
		}
		if v.FirstBadID != 0 {
			detail["first_bad_id"] = strconv.FormatInt(v.FirstBadID, 10)
		}
		s.recordAuditOutcome(r.Context(), "admin.audit.verify", string(caller), audit.OutcomeOK, detail)
	}
	writeJSON(w, http.StatusOK, auditVerifyView{
		OK:         v.OK,
		Chained:    v.Chained,
		Legacy:     v.Legacy,
		FirstBadID: v.FirstBadID,
		Reason:     v.Reason,
	})
}

// handleAdminAuditHead returns the chain's current head hash, for an external
// anchor to publish. Verifying the chain in place cannot detect rows deleted from
// the end — the tail is simply shorter and every remaining link still holds — so
// the anchor is the missing piece: a copy of the head kept where this database
// cannot reach. A deployment that never publishes it has exactly the protection it
// had before, and the read API is what a SIEM tails for the export half.
func (s *Server) handleAdminAuditHead(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	head, err := s.auditReader.Head(r.Context())
	if err != nil {
		if caller, ok := s.sessions.User(r.Context()); ok {
			s.recordAuditOutcome(r.Context(), "admin.audit.head", string(caller), audit.OutcomeError, nil)
		}
		s.writeProblem(w, r, http.StatusInternalServerError, "internal_error", "could not read the audit chain head")
		return
	}
	// Publishing the anchor is an operator act about the whole log, so it is
	// recorded like the paged read and the walk (Z10-6).
	if caller, ok := s.sessions.User(r.Context()); ok {
		s.recordAuditOutcome(r.Context(), "admin.audit.head", string(caller), audit.OutcomeOK,
			map[string]string{"bytes": strconv.Itoa(len(head))})
	}
	writeJSON(w, http.StatusOK, map[string]any{"head": hex.EncodeToString(head)})
}
