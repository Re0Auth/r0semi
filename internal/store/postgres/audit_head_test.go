package postgres

import (
	"bytes"
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// The head starts empty and advances by exactly one link per record — the value an
// external anchor publishes, changing on every append and never on its own.
func TestAuditHeadAdvancesWithEachRecord(t *testing.T) {
	db := openTestDB(t)
	logger, err := db.Audit(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	head, err := logger.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(head) != 0 {
		t.Fatalf("a fresh log's head is non-empty (%d bytes), want the genesis", len(head))
	}

	if err := logger.Record(ctx, audit.Event{
		Action: "test.event", Subject: "usr_1", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatal(err)
	}
	next, err := logger.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) == 0 {
		t.Fatal("the head did not advance after a record")
	}
	if bytes.Equal(next, head) {
		t.Fatal("the head is unchanged after a record")
	}
}
