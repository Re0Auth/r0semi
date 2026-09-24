// Guards for the findings of the second adversarial audit (docs/security-audit-2.md).
//
// Each of these failed before its fix and passes now. They live together so the
// audit and its guards stay in one place, and each test names the finding it pins.
package lifecycle

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// Finding A5-1: the erasure's own audit row carries the erased account id in
// `detail["actor"]`, where destroying the pseudonym key cannot reach it.
//
// `DeleteAccount(actor, subject)` records `"actor": string(actor)` in Detail. On a
// self-erasure the caller passes the same value for both, so the row that
// documents the erasure names the erased person in the clear — while
// `Destroy` only removes the key that would resolve the (pseudonymised) Subject
// column. The whole point of the mechanism is that after erasure nothing connects
// the account to its history; this row is the exception, and it is the one row
// guaranteed to be about that account.
func TestAdversarialErasureLeavesTheAccountIdInTheAuditDetail(t *testing.T) {
	var calls []string
	r := func() recorder { return recorder{calls: &calls} }
	logger := audit.NewMemoryLogger()
	d, err := New(Config{
		Accounts:   fakeAccounts{recorder: r()},
		Tokens:     fakeTokens{recorder: r()},
		Vault:      fakeVault{recorder: r()},
		Pseudonyms: &fakePseudonyms{},
		Audit:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A self-erasure: the actor is the subject, which is what the HTTP handler does.
	const subject = "usr_target"
	if _, err := d.DeleteAccount(context.Background(), subject, subject); err != nil {
		t.Fatal(err)
	}

	events := logger.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	// Only `detail` is asserted. The memory sink does not pseudonymise the Subject
	// column — it is a bounded ring buffer with no key store, which is documented —
	// but the DURABLE sink does pseudonymise Subject while storing Detail verbatim
	// (internal/store/postgres/audit.go), so an id here survives both the
	// pseudonymisation and the key destruction.
	for k, v := range e.Detail {
		if v == subject {
			t.Errorf("detail[%q] carries the erased account id %q, which the pseudonym "+
				"key destruction cannot reach", k, subject)
		}
	}
}
