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
// computable. lifecycle.DeleteAccount writes its `account.delete` record *before*
// that step — deliberately, because the record is itself about the account — and
// the failure branch returns without writing a second one. The record that
// survives therefore states `outcome=ok` and `pseudonym_destroyed=true` for an
// erasure whose history is still linkable, and no row in the log names the step
// that failed. The endpoint's own 500 tells the caller the opposite ("the audit
// log records the step that failed").
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
	if len(events) != 1 {
		t.Fatalf("the audit log has %d account.delete records, want exactly 1: %+v", len(events), events)
	}
	e := events[0]
	if e.Subject != user {
		t.Errorf("the record's subject = %q, want the erased account %q", e.Subject, user)
	}
	// What the log says about the run, versus what happened.
	if e.Outcome == audit.OutcomeOK {
		t.Errorf("the only record of this erasure reports outcome=%q although the erasure returned an error "+
			"and the account's audit history is still linkable (detail %+v)", e.Outcome, e.Detail)
	}
	if got := e.Detail["pseudonym_destroyed"]; got == "true" {
		t.Errorf("the record reports pseudonym_destroyed=%q for a run where the destroy failed (detail %+v)",
			got, e.Detail)
	}
	if _, ok := e.Detail["failed_at"]; !ok {
		t.Errorf("no record names the step that failed, and the 500 promised the audit log would (detail %+v)",
			e.Detail)
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
