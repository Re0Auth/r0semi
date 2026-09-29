//go:build audit7

// Zone-10 DB-gated probe: what the operator read API can say about an admin
// action once the log pseudonymises the subject column.
package z10adminauditprivacy

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
	"github.com/Re0Auth/r0semi/oauth"
)

// TestZ10AdminActionRowsDoNotSayWhichClientTheyAreAbout.
//
// The audit sink stores every non-empty Subject as a per-subject pseudonym, and
// every admin.* event uses the client id as its Subject (admin.Target.auditSubject
// / the Register/Suspend/Delete/rotate calls). A client id is not an account:
// nothing ever destroys its pseudonym key, so the pseudonymisation buys no privacy
// there, and the Detail map carries no client id to compensate — SuspendClient
// records {"actor", "tokens_revoked"}, Register records {"type"}. An operator
// reading the log for "which client did we just suspend" therefore sees an opaque
// handle, and can only recover it by guessing a client id and querying
// `?subject=` one at a time.
func TestZ10AdminActionRowsDoNotSayWhichClientTheyAreAbout(t *testing.T) {
	dsn := probeDSN(t)
	ctx := context.Background()
	resetAuditTables(t, ctx, dsn)

	db, err := postgres.Open(ctx, dsn, postgres.DefaultPoolOptions())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	logger, err := db.Audit(probeAuditKey())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	// A client for the operator plane to act on, through the same registry the
	// composition root passes.
	clients := db.Clients()
	const clientID = "cli_suspended0001"
	client, err := oauth.NewClient(clientID, "Suspended App", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	svc, err := admin.New(admin.Config{
		Clients: clients,
		Tokens:  db.Tokens(),
		Audit:   logger,
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	const actor = "usr_operator000000000000"
	if err := svc.SuspendClient(ctx, actor, clientID); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	page, err := logger.Query(ctx, audit.Query{Action: "admin.client.suspend"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("admin.client.suspend rows = %d, want 1 (control: %+v)", len(page.Entries), page.Entries)
	}
	entry := page.Entries[0]

	// The value an incident responder needs.
	if entry.Subject == clientID {
		t.Fatalf("control is stale: the row stores the client id verbatim, so there is nothing to report")
	}
	if got := entry.Detail["client_id"]; got != clientID {
		t.Errorf("the audit row for suspending client %q has subject=%q (a pseudonym) and no client_id in its "+
			"detail (%+v): the operator read API can list the action but cannot say which client it is about, "+
			"and the pseudonymisation buys no privacy for a client id (no key is ever destroyed for one). "+
			"Record it in Detail the way oidc.token already records client_id.", clientID, entry.Subject, entry.Detail)
	}
}
