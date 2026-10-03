//go:build audit7

package z07authsessionlifecycle

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// failingPseudonyms is the erasure's last step failing: the audit sink cannot
// destroy the key that links the erased account to its history.
type failingPseudonyms struct{ err error }

func (f failingPseudonyms) Destroy(context.Context, string) error { return f.err }

// okPseudonyms records what it was asked to destroy.
type okPseudonyms struct {
	mu        sync.Mutex
	destroyed []string
}

func (o *okPseudonyms) Destroy(_ context.Context, subject string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.destroyed = append(o.destroyed, subject)
	return nil
}

func (o *okPseudonyms) calls() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.destroyed...)
}

const deleteBody = `{"acknowledge":"deletes_my_account"}`

func deleteHeaders(csrf string) map[string]string {
	return map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf}
}

// deleteEvents filters the log down to the erasure's own record.
func deleteEvents(events []audit.Event) []audit.Event {
	out := make([]audit.Event, 0, 1)
	for _, e := range events {
		if e.Action == "account.delete" {
			out = append(out, e)
		}
	}
	return out
}

// TestZ07ErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable.
//
// The erasure's last step destroys the key that makes an account's audit history
// computable. lifecycle.DeleteAccount writes its success `account.delete` record
// *before* that step — deliberately, because the record is itself about the
// account and moving it below Destroy would make the sink mint a fresh subject
// key — and a failing Destroy must therefore not leave that success record as the
// run's last word. The fixed failure branch (lifecycle.go) resets
// pseudonym_destroyed and appends a SECOND `account.delete` with outcome=error and
// failed_at=pseudonym, so the LAST record for the subject tells the truth about
// the run that returned the 500, and the endpoint's promise that "the audit log
// records the step that failed" (internal/httpapi/account_routes.go:62) holds.
//
// The old round-6/7 shape of this probe failed on `len(events) != 1`: it was a
// finding confirmation for the era when the failure branch wrote nothing. On the
// fixed code there are deliberately TWO records on the failure path, so the guard
// locates the last record for the subject instead of counting records.
func TestZ07ErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable(t *testing.T) {
	sentinel := errors.New("pseudonym store unavailable")
	env := newProbeEnv(t, probeOptions{Pseudonyms: failingPseudonyms{err: sentinel}})

	b := env.newBrowser()
	user := b.signIn(probeProvider)
	csrf := b.csrf()

	resp := b.do(http.MethodDelete, "/v1/account", deleteBody, deleteHeaders(csrf))
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("DELETE /v1/account = %d (%s), want 500: the last step failed", resp.StatusCode, body)
	}
	if !strings.Contains(body, "could not be fully erased") {
		t.Fatalf("the 500 does not say the erasure was incomplete: %s", body)
	}
	if !strings.Contains(body, "the audit log records the step that failed") {
		t.Logf("the 500 no longer promises an audit line for the failed step: %s", body)
	}

	events := deleteEvents(env.audit.Events())
	if len(events) == 0 {
		t.Fatalf("the erasure wrote no account.delete record at all: %+v", env.audit.Events())
	}
	// The last record about the subject is the one that describes the run that
	// returned the 500; the earlier success record (kept above Destroy on purpose)
	// must not be the last word.
	var last *audit.Event
	for i := range events {
		if events[i].Subject == user {
			last = &events[i]
		}
	}
	if last == nil {
		t.Fatalf("no account.delete record names the erased account %q: %+v", user, events)
	}
	if last.Outcome == audit.OutcomeOK {
		t.Errorf("the LAST record of this erasure reports outcome=%q although the erasure returned an "+
			"error and the account's audit history is still linkable (detail %+v)", last.Outcome, last.Detail)
	}
	if got := last.Detail["failed_at"]; got != "pseudonym" {
		t.Errorf("the last record's failed_at = %q, want %q: the failure record must name the step that "+
			"stopped the erasure (detail %+v)", got, "pseudonym", last.Detail)
	}
	if got := last.Detail["pseudonym_destroyed"]; got == "true" {
		t.Errorf("the last record reports pseudonym_destroyed=%q for a run where the destroy failed (detail %+v)",
			got, last.Detail)
	}
	// The account really is gone, so this is not "the erasure did nothing".
	if _, err := env.accounts.GetUser(context.Background(), accountUserID(user)); err == nil {
		t.Logf("the account row still exists, so the run stopped before the last step")
	}
}

// TestZ07ErasureWithAWorkingDestroyIsRecorded is the control: the destroy really
// ran and left exactly one `outcome=ok` record marked `pseudonym=pending`, so the
// failure probe above is not satisfied by a log that records nothing. S08-3 changed
// the field semantics: the pre-destroy record cannot claim `destroyed=true` (it is
// written while the key still exists), so success is "pending and no error record".
func TestZ07ErasureWithAWorkingDestroyIsRecorded(t *testing.T) {
	pseudo := &okPseudonyms{}
	env := newProbeEnv(t, probeOptions{Pseudonyms: pseudo})

	b := env.newBrowser()
	user := b.signIn(probeProvider)
	csrf := b.csrf()

	resp := b.do(http.MethodDelete, "/v1/account", deleteBody, deleteHeaders(csrf))
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /v1/account = %d (%s), want 200", resp.StatusCode, body)
	}
	if got := pseudo.calls(); len(got) != 1 || got[0] != user {
		t.Fatalf("destroyed = %v, want the erased account %q", got, user)
	}
	events := deleteEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("account.delete records = %+v, want one", events)
	}
	if events[0].Outcome != audit.OutcomeOK ||
		events[0].Detail["pseudonym"] != "pending" ||
		events[0].Detail["pseudonym_destroyed"] != "false" {
		t.Fatalf("a successful erasure is not reported as one: %+v", events[0])
	}
	if events[0].Detail["failed_at"] != "" {
		t.Fatalf("a successful erasure carries failed_at: %+v", events[0])
	}
}

// TestZ07ErasureFailureLeavesTheOtherSessionAnswering500.
//
// The memory development store has no session revoker (lifecycle.Config.Sessions
// is nil, and Result.SessionScoped=false says so), so an erasure deletes the
// account row but leaves a *second* browser session of the same account alive.
// Every session-scoped endpoint then answers 500 "account lookup failed" instead
// of dropping the session and answering 401 — the "who is this" endpoint becomes
// a server error for a session the service itself invalidated.
func TestZ07ErasureFailureLeavesTheOtherSessionAnswering500(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	first := env.newBrowser()
	second := env.newBrowser()

	// Two sessions, one account: the same external identity resolves to the same
	// usr_ id.
	user := first.signIn(probeProvider)
	if other := second.signIn(probeProvider); other != user {
		t.Fatalf("the two browsers signed in as %q and %q, want one account", user, other)
	}
	csrf := first.csrf()

	resp := first.do(http.MethodDelete, "/v1/account", deleteBody, deleteHeaders(csrf))
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("erasure = %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"SessionScoped":false`) {
		t.Logf("the response does not report SessionScoped=false: %s", body)
	}

	// The second browser's session outlived the account it names.
	for _, target := range []string{"/v1/sessions/current", "/v1/account/export"} {
		got := second.status(http.MethodGet, target, "", nil)
		if got == http.StatusInternalServerError {
			t.Errorf("GET %s from a session whose account row is gone = 500; the service holds a live "+
				"session for an account it deleted and answers a server fault instead of dropping it (401)", target)
		} else {
			t.Logf("GET %s = %d", target, got)
		}
	}
	// The zombie session can still reach a write endpoint; it fails closed, but
	// it is not signed out.
	if got := second.status(http.MethodPost, "/v1/sessions/sign_out", "", nil); got != http.StatusForbidden {
		t.Logf("POST sign_out from the zombie session = %d", got)
	}
}

// TestZ07ConcurrentErasuresOfOneAccountAreBothRecorded.
//
// The erasure endpoint is session-scoped and the erasure revokes the account's
// sessions only part-way through, so two requests that both loaded the session
// before either ran can both proceed. Every store step is idempotent, so both
// answer 200 — which is the intended idempotence, but it also means the audit log
// carries two `account.delete` records for one erasure. This records the shape so
// a change that makes it silent would be visible.
func TestZ07ConcurrentErasuresOfOneAccountAreBothRecorded(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	first := env.newBrowser()
	second := env.newBrowser()

	user := first.signIn(probeProvider)
	if other := second.signIn(probeProvider); other != user {
		t.Fatalf("two accounts, want one: %q vs %q", user, other)
	}
	c1, c2 := first.csrf(), second.csrf()

	var wg sync.WaitGroup
	codes := make([]int, 2)
	bodies := make([]string, 2)
	for i, br := range []*browser{first, second} {
		wg.Add(1)
		go func(i int, br *browser, csrf string) {
			defer wg.Done()
			resp := br.do(http.MethodDelete, "/v1/account", deleteBody, deleteHeaders(csrf))
			codes[i] = resp.StatusCode
			bodies[i] = bodyOf(t, resp)
		}(i, br, []string{c1, c2}[i])
	}
	wg.Wait()

	t.Logf("concurrent erasures: %d (%s) / %d", codes[0], strings.TrimSpace(bodies[0]), codes[1])
	events := deleteEvents(env.audit.Events())
	t.Logf("account.delete records written: %d", len(events))
	for _, e := range events {
		if e.Outcome != audit.OutcomeOK {
			t.Errorf("an erasure attempt was recorded as %q: %+v", e.Outcome, e)
		}
		if e.Subject != user {
			t.Errorf("an erasure attempt names the wrong subject: %+v", e)
		}
	}
	if _, err := env.accounts.GetUser(context.Background(), accountUserID(user)); err == nil {
		t.Errorf("the account still exists after two successful erasures")
	}
}
