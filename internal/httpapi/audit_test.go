package httpapi

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// The unlink audit lives on the Server, so it is exercised directly: the event
// must carry the subject and the identity, and a nil logger must be a no-op
// rather than a panic.
func TestUnlinkIsAudited(t *testing.T) {
	log := audit.NewMemoryLogger()
	s := &Server{auditLog: log}
	s.recordUnlinkAudit(context.Background(), "usr_1", "idn_7")

	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	e := events[0]
	if e.Action != "auth.identity.unlink" || e.Subject != "usr_1" || e.Detail["identity_id"] != "idn_7" {
		t.Fatalf("event = %+v", e)
	}

	// No logger: nothing to record, and no panic.
	(&Server{}).recordUnlinkAudit(context.Background(), "usr_1", "idn_7")
}
