package admin

// P3 probes for the operator plane (batch S11-2/3/4, Z10-4, Z10-8, Z10V-1, k6).
//
// Red against the code as it was before the fix, green after it; no build tag,
// so `go test ./internal/admin/ -count=1` covers them.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

// failingSessions is a session port that always fails, which is what puts the
// Kill Switch on its sessions failure path (Z10V-1 / S11-4).
type failingSessions struct{}

func (failingSessions) RevokeAllSessions(context.Context) (int64, error) {
	return 0, errors.New("probe: session store down")
}

func (failingSessions) RevokeSubjectSessions(context.Context, string) (int64, error) {
	return 0, errors.New("probe: session store down")
}

// failingAdminAudit fails every write, which is what puts record on its
// slog.Error branch (k6).
type failingAdminAudit struct{}

func (failingAdminAudit) Record(context.Context, audit.Event) error {
	return errors.New("probe: audit sink down")
}

// lastDetail returns the Detail of the most recently recorded event.
func lastDetail(t *testing.T, logger *audit.MemoryLogger) map[string]string {
	t.Helper()
	events := logger.Events()
	if len(events) == 0 {
		t.Fatal("no audit event was recorded")
	}
	last := events[len(events)-1]
	if last.Detail == nil {
		t.Fatalf("the last event has no Detail: %+v", last)
	}
	return last.Detail
}

// mustConfidential registers a confidential client and returns it.
func mustConfidential(t *testing.T, svc Service) oauth.Client {
	t.Helper()
	reg, err := svc.Register(context.Background(), "usr_admin", RegisterRequest{
		Name:          "App",
		Type:          oauth.ClientConfidential,
		RedirectURIs:  []string{"https://app.example/cb"},
		AllowedScopes: []oauth.Scope{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg.Client
}

// ---------------------------------------------------------------------------
// S11-2 / Z10-4
// ---------------------------------------------------------------------------

// TestP3S112AndZ104KillSwitchMarksSessionsUnavailable.
//
// With no session revoker the sessions half is skipped entirely and the report
// says `sessions_revoked: 0` — the same shape as "this account had no sessions".
// The bindings half already has an unavailable marker; sessions must have one
// too, in the report and in the audit Detail.
func TestP3S112AndZ104KillSwitchMarksSessionsUnavailable(t *testing.T) {
	ctx := context.Background()

	// No Sessions port.
	svc, _, tokens, logger := newTestService(t)
	saveTokens(t, tokens, "cli_a", "usr_1")
	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.TokensRevoked == 0 {
		t.Fatal("anti-vacuous: no tokens were revoked, so the report was not exercised")
	}
	if rep.SessionsRevoked != 0 {
		t.Fatalf("sessions_revoked = %d, want 0 (no revoker is wired)", rep.SessionsRevoked)
	}
	if got := lastDetail(t, logger)["sessions_unavailable"]; got != "true" {
		t.Errorf("KillSwitch(all) on a deployment with no session revoker recorded %v: "+
			"sessions_revoked=0 stays indistinguishable from 'nobody was signed in'",
			lastDetail(t, logger))
	}
	if !rep.SessionsUnavailable {
		t.Errorf("Report.SessionsUnavailable = false on a target with a session dimension and no port: %+v", rep)
	}

	// The subject target has the same dimension.
	svcSub, _, tokensSub, loggerSub := newTestService(t)
	saveTokens(t, tokensSub, "cli_a", "usr_2")
	if _, err := svcSub.KillSwitch(ctx, "usr_admin", Target{Subject: "usr_2"}); err != nil {
		t.Fatal(err)
	}
	if got := lastDetail(t, loggerSub)["sessions_unavailable"]; got != "true" {
		t.Errorf("KillSwitch(subject) with no session revoker recorded %v, want sessions_unavailable=true",
			lastDetail(t, loggerSub))
	}

	// Control: with a revoker wired the marker is absent, so the two states are
	// distinct.
	withPort := audit.NewMemoryLogger()
	svcPort, err := New(Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: oauth.NewMemoryStore(),
		Sessions: &fakeSessions{remaining: 1}, Audit: withPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	repPort, err := svcPort.KillSwitch(ctx, "usr_admin", Target{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if repPort.SessionsRevoked != 1 {
		t.Fatalf("control: sessions_revoked = %d, want 1", repPort.SessionsRevoked)
	}
	if got := lastDetail(t, withPort)["sessions_unavailable"]; got != "" {
		t.Errorf("a deployment WITH a session revoker recorded sessions_unavailable=%q", got)
	}
	if repPort.SessionsUnavailable {
		t.Errorf("Report.SessionsUnavailable = true even though the sweep ran: %+v", repPort)
	}
}

// ---------------------------------------------------------------------------
// S11-3
// ---------------------------------------------------------------------------

// TestP3S113KillSwitchAllMarksFlowsUnavailable.
//
// The flow port is subject-scoped: `all` cannot enumerate accounts, so an
// `all` sweep leaves every in-flight bind flow alive — a pending flow can create
// a new binding and upstream token after the sweep. The report must say the flow
// half did not run instead of reporting a zero that reads as "there were none".
func TestP3S113KillSwitchAllMarksFlowsUnavailable(t *testing.T) {
	ctx := context.Background()
	flows := &fakeFlows{purged: 2}
	tokens := oauth.NewMemoryStore()
	logger := audit.NewMemoryLogger()
	svc, err := New(Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: tokens, Flows: flows, Audit: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	saveTokens(t, tokens, "cli_a", "usr_1")

	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.TokensRevoked == 0 {
		t.Fatal("anti-vacuous: no tokens were revoked, so the sweep did not run")
	}
	if rep.FlowsPurged != 0 {
		t.Fatalf("flows_purged = %d, want 0 for an all-target", rep.FlowsPurged)
	}
	if flows.subject != "" {
		t.Errorf("an all-target asked the subject-scoped purger about %q", flows.subject)
	}
	if got := lastDetail(t, logger)["flows_unavailable"]; got != "true" {
		t.Errorf("KillSwitch(all) recorded %v, so a responder cannot tell that in-flight bind flows survived the sweep",
			lastDetail(t, logger))
	}
	if !rep.FlowsUnavailable {
		t.Errorf("Report.FlowsUnavailable = false for an all-target even though no flow port can enumerate accounts: %+v", rep)
	}

	// The same silent zero on a deployment with no flow port at all.
	svcNoPort, _, tokensNoPort, loggerNoPort := newTestService(t)
	saveTokens(t, tokensNoPort, "cli_a", "usr_1")
	if _, err := svcNoPort.KillSwitch(ctx, "usr_admin", Target{Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if got := lastDetail(t, loggerNoPort)["flows_unavailable"]; got != "true" {
		t.Errorf("a subject sweep with no flow port recorded %v, want flows_unavailable=true",
			lastDetail(t, loggerNoPort))
	}

	// Control: a subject sweep with the port wired reports the count and no marker.
	flowsOK := &fakeFlows{purged: 3}
	loggerOK := audit.NewMemoryLogger()
	tokensOK := oauth.NewMemoryStore()
	svcOK, err := New(Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: tokensOK, Flows: flowsOK, Audit: loggerOK,
	})
	if err != nil {
		t.Fatal(err)
	}
	saveTokens(t, tokensOK, "cli_a", "usr_3")
	repOK, err := svcOK.KillSwitch(ctx, "usr_admin", Target{Subject: "usr_3"})
	if err != nil {
		t.Fatal(err)
	}
	if repOK.FlowsPurged != 3 {
		t.Fatalf("control: flows_purged = %d, want 3", repOK.FlowsPurged)
	}
	if got := lastDetail(t, loggerOK)["flows_unavailable"]; got != "" {
		t.Errorf("a subject sweep that purged flows recorded flows_unavailable=%q", got)
	}
	if repOK.FlowsUnavailable {
		t.Errorf("Report.FlowsUnavailable = true even though the subject sweep purged flows: %+v", repOK)
	}
}

// ---------------------------------------------------------------------------
// Z10V-1 / S11-4 (durable-record half)
// ---------------------------------------------------------------------------

// TestP3Z10V1KillSwitchFailureDetailCarriesTheCounts.
//
// The sessions failure path writes a Detail literal with tokens_revoked and
// nothing else, so the sessions already cut (and, in general, the partial
// summary) never reaches the durable record. Failure paths must carry the same
// Detail shape as the success path.
func TestP3Z10V1KillSwitchFailureDetailCarriesTheCounts(t *testing.T) {
	ctx := context.Background()
	tokens := oauth.NewMemoryStore()
	logger := audit.NewMemoryLogger()
	svc, err := New(Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: tokens,
		Sessions: failingSessions{}, Audit: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	saveTokens(t, tokens, "cli_a", "usr_1")

	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{All: true})
	if err == nil {
		t.Fatal("the failing session revoker was not propagated")
	}
	if rep.TokensRevoked == 0 {
		t.Fatal("anti-vacuous: no tokens were revoked before the failure")
	}

	events := logger.Events()
	if len(events) == 0 {
		t.Fatal("the failure was not audited at all")
	}
	last := events[len(events)-1]
	if last.Outcome != audit.OutcomeError {
		t.Fatalf("failure row outcome = %q, want %q", last.Outcome, audit.OutcomeError)
	}
	detail := last.Detail
	if detail["tokens_revoked"] == "" {
		t.Errorf("the failure row dropped tokens_revoked, discarding what was already cut: %v", detail)
	}
	if _, ok := detail["sessions_revoked"]; !ok {
		t.Errorf("the failure row has no sessions_revoked, so the durable record cannot say how many sessions "+
			"the sweep had already cut: %v", detail)
	}
	if detail["scope"] != "all" {
		t.Errorf("the failure row does not name the scope it acted on: %v", detail)
	}
}

// ---------------------------------------------------------------------------
// Z10-8
// ---------------------------------------------------------------------------

// TestP3Z108AdminAuditDetailNamesTheClient.
//
// The audit sink stores Subject as a keyed pseudonym for every subject shape,
// client ids included, and admin.* Details carried no compensating field — so a
// reader of the log cannot answer "which client". The client id must ride in
// Detail, the way oidc.token already does.
func TestP3Z108AdminAuditDetailNamesTheClient(t *testing.T) {
	ctx := context.Background()
	svc, clients, tokens, logger := newTestService(t)
	mustClient(t, clients, "cli_a")
	saveTokens(t, tokens, "cli_a", "usr_1")

	if err := svc.SuspendClient(ctx, "usr_admin", "cli_a"); err != nil {
		t.Fatal(err)
	}
	if got := lastDetail(t, logger)["client_id"]; got != "cli_a" {
		t.Errorf("admin.client.suspend recorded %v, so the read API cannot say which client was suspended",
			lastDetail(t, logger))
	}

	client := mustConfidential(t, svc)
	if got := lastDetail(t, logger)["client_id"]; got != client.ID {
		t.Errorf("admin.client.register recorded %v, want client_id=%q", lastDetail(t, logger), client.ID)
	}

	if _, err := svc.RotateClientSecret(ctx, "usr_admin", client.ID); err != nil {
		t.Fatal(err)
	}
	if got := lastDetail(t, logger)["client_id"]; got != client.ID {
		t.Errorf("admin.client.rotate_secret recorded %v, want client_id=%q", lastDetail(t, logger), client.ID)
	}

	if _, err := svc.KillSwitch(ctx, "usr_admin", Target{ClientID: client.ID}); err != nil {
		t.Fatal(err)
	}
	if got := lastDetail(t, logger)["client_id"]; got != client.ID {
		t.Errorf("admin.kill_switch (client target) recorded %v, want client_id=%q", lastDetail(t, logger), client.ID)
	}
}

// ---------------------------------------------------------------------------
// k6
// ---------------------------------------------------------------------------

// TestP3K6AdminAuditFailureLogCarriesNoAccountID: the operator's raw usr_ must
// not reach the process log when the audit write fails.
func TestP3K6AdminAuditFailureLogCarriesNoAccountID(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	clients := oauth.NewMemoryClientRegistry()
	tokens := oauth.NewMemoryStore()
	svc, err := New(Config{Clients: clients, Tokens: tokens, Audit: failingAdminAudit{}})
	if err != nil {
		t.Fatal(err)
	}
	mustClient(t, clients, "cli_a")
	saveTokens(t, tokens, "cli_a", "usr_1")

	if err := svc.SuspendClient(context.Background(), "usr_admin_secret", "cli_a"); err != nil {
		t.Fatal(err)
	}

	logged := buf.String()
	if !strings.Contains(logged, "admin audit record failed") {
		t.Fatalf("the audit write failure was not logged; the probe would be vacuous: %q", logged)
	}
	if strings.Contains(logged, "usr_admin_secret") {
		t.Errorf("the process log carried the operator's account id: %q", logged)
	}
}
