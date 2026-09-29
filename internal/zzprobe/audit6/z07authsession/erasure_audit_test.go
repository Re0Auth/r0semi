//go:build audit6

package z07authsession

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// failingPseudonyms is the erasure's last step failing: the audit sink cannot
// destroy the key that links the erased account to its history.
type failingPseudonyms struct{ err error }

func (f failingPseudonyms) Destroy(context.Context, string) error { return f.err }

// okPseudonyms records what it was asked to destroy.
type okPseudonyms struct{ destroyed []string }

func (o *okPseudonyms) Destroy(_ context.Context, subject string) error {
	o.destroyed = append(o.destroyed, subject)
	return nil
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

// TestProbeErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable.
//
// The erasure's last step destroys the key that makes an account's audit history
// computable. lifecycle.DeleteAccount writes its success `account.delete` record
// *before* that step — deliberately, because the record is itself about the
// account and moving it below Destroy would make the sink mint a fresh subject
// key — and a failing Destroy must therefore not leave that success record as the
// run's last word. The fixed failure branch writes a SECOND `account.delete` with
// outcome=error and failed_at=pseudonym, so the LAST record for the subject tells
// the truth about the run that returned the 500, and the endpoint's promise that
// "the audit log records the step that failed" holds.
//
// The old round-6 shape failed on `len(events) != 1`: it was a finding
// confirmation for the era when the failure branch wrote nothing. On the fixed
// code there are deliberately TWO records on the failure path, so the guard
// locates the last record for the subject instead of counting records.
func TestProbeErasureAuditRecordClaimsSuccessWhileTheHistoryStaysLinkable(t *testing.T) {
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
	// The caller is told the erasure may be incomplete, which is true.
	if !strings.Contains(body, "could not be fully erased") {
		t.Fatalf("the 500 does not say the erasure was incomplete: %s", body)
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
		t.Errorf("the LAST record of this erasure reports outcome=%q although the erasure returned an error "+
			"and the account's audit history is still linkable (detail %+v)", last.Outcome, last.Detail)
	}
	if got := last.Detail["failed_at"]; got != "pseudonym" {
		t.Errorf("the last record's failed_at = %q, want %q: the failure record must name the step that "+
			"stopped the erasure (detail %+v)", got, "pseudonym", last.Detail)
	}
	if got := last.Detail["pseudonym_destroyed"]; got == "true" {
		t.Errorf("the last record reports pseudonym_destroyed=%q for a run where the destroy failed (detail %+v)",
			got, last.Detail)
	}
}

// TestProbeErasureWithAWorkingDestroyRecordsSuccess is the control: the same
// fields are present and true when the last step works, so the probe above is
// not satisfied by a log that records nothing.
func TestProbeErasureWithAWorkingDestroyRecordsSuccess(t *testing.T) {
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
	if len(pseudo.destroyed) != 1 || pseudo.destroyed[0] != user {
		t.Fatalf("destroyed = %v, want the erased account %q", pseudo.destroyed, user)
	}
	events := deleteEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("account.delete records = %+v, want one", events)
	}
	if events[0].Outcome != audit.OutcomeOK || events[0].Detail["pseudonym_destroyed"] != "true" {
		t.Fatalf("a successful erasure is not reported as one: %+v", events[0])
	}
}
