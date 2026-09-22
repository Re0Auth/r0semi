package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

func newTestService(t *testing.T) (Service, *oauth.MemoryClientRegistry, *oauth.MemoryStore, *audit.MemoryLogger) {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	tokens := oauth.NewMemoryStore()
	logger := audit.NewMemoryLogger()
	svc, err := New(Config{Clients: clients, Tokens: tokens, Audit: logger})
	if err != nil {
		t.Fatal(err)
	}
	return svc, clients, tokens, logger
}

func mustClient(t *testing.T, reg *oauth.MemoryClientRegistry, id string) {
	t.Helper()
	c, err := oauth.NewClient(id, id, oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func saveTokens(t *testing.T, s *oauth.MemoryStore, clientID, subject string) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveAccess(ctx, clientID+"-at-"+subject,
		oauth.AccessToken{ClientID: clientID, Subject: subject, Scopes: []oauth.Scope{"openid"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRefresh(ctx, clientID+"-rt-"+subject,
		oauth.RefreshToken{ClientID: clientID, Subject: subject, Scopes: []oauth.Scope{"openid"}}); err != nil {
		t.Fatal(err)
	}
}

func countTokens(t *testing.T, s *oauth.MemoryStore, subject string) int {
	t.Helper()
	recs, err := s.ListBySubject(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

// The secret exists only in the registration response. What is stored accepts it
// and nothing can read it back.
func TestRegisterReturnsTheSecretOnlyOnce(t *testing.T) {
	ctx := context.Background()
	svc, clients, _, _ := newTestService(t)

	reg, err := svc.Register(ctx, "usr_admin", RegisterRequest{
		Name:          "App",
		Type:          oauth.ClientConfidential,
		RedirectURIs:  []string{"https://app.example/cb"},
		AllowedScopes: []oauth.Scope{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reg.Secret == "" {
		t.Fatal("a confidential registration returned no secret")
	}
	if reg.Client.ID == "" || reg.Client.Status != oauth.ClientActive {
		t.Fatalf("client = %+v", reg.Client)
	}
	stored, err := clients.Get(ctx, reg.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Authenticate(reg.Secret) {
		t.Fatal("the stored client does not accept the issued secret")
	}
}

// Suspension hides the client from the protocol plane and revokes only that
// client's tokens; a neighbouring client is untouched.
func TestSuspendHidesClientAndRevokesOnlyItsTokens(t *testing.T) {
	ctx := context.Background()
	svc, clients, tokens, _ := newTestService(t)
	mustClient(t, clients, "cli_a")
	mustClient(t, clients, "cli_b")
	saveTokens(t, tokens, "cli_a", "usr_1")
	saveTokens(t, tokens, "cli_b", "usr_2")

	if err := svc.SuspendClient(ctx, "usr_admin", "cli_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := clients.Get(ctx, "cli_a"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("suspended client Get = %v, want ErrClientNotFound", err)
	}
	if n := countTokens(t, tokens, "usr_1"); n != 0 {
		t.Fatalf("suspended client still holds %d tokens", n)
	}
	if n := countTokens(t, tokens, "usr_2"); n != 2 {
		t.Fatalf("neighbouring client holds %d tokens, want 2", n)
	}

	// Activating brings the registration back but not the revoked tokens.
	if err := svc.ActivateClient(ctx, "usr_admin", "cli_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := clients.Get(ctx, "cli_a"); err != nil {
		t.Fatalf("reactivated client: %v", err)
	}
	if n := countTokens(t, tokens, "usr_1"); n != 0 {
		t.Fatalf("activation restored %d tokens; it must not", n)
	}
}

type fakeSessions struct{ remaining int64 }

func (f *fakeSessions) RevokeAllSessions(context.Context) (int64, error) {
	n := f.remaining
	f.remaining = 0
	return n, nil
}

func TestKillSwitchAllRevokesEverythingAndDropsSessions(t *testing.T) {
	ctx := context.Background()
	clients := oauth.NewMemoryClientRegistry()
	tokens := oauth.NewMemoryStore()
	sessions := &fakeSessions{remaining: 3}
	svc, err := New(Config{Clients: clients, Tokens: tokens, Sessions: sessions, Audit: audit.NewMemoryLogger()})
	if err != nil {
		t.Fatal(err)
	}
	saveTokens(t, tokens, "cli_a", "usr_1")
	saveTokens(t, tokens, "cli_b", "usr_2")

	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.TokensRevoked != 4 {
		t.Fatalf("tokens_revoked = %d, want 4", rep.TokensRevoked)
	}
	if rep.SessionsRevoked != 3 {
		t.Fatalf("sessions_revoked = %d, want 3", rep.SessionsRevoked)
	}
	if countTokens(t, tokens, "usr_1")+countTokens(t, tokens, "usr_2") != 0 {
		t.Fatal("tokens remain after an all-target kill switch")
	}
}

func TestKillSwitchRequiresExactlyOneTarget(t *testing.T) {
	ctx := context.Background()
	svc, _, tokens, _ := newTestService(t)
	saveTokens(t, tokens, "cli_a", "usr_1")
	saveTokens(t, tokens, "cli_b", "usr_2")

	if _, err := svc.KillSwitch(ctx, "usr_admin", Target{}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("empty target = %v, want ErrInvalidTarget", err)
	}
	if _, err := svc.KillSwitch(ctx, "usr_admin", Target{All: true, ClientID: "cli_a"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ambiguous target = %v, want ErrInvalidTarget", err)
	}

	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{Subject: "usr_1"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.TokensRevoked != 2 {
		t.Fatalf("subject tokens_revoked = %d, want 2", rep.TokensRevoked)
	}
	if countTokens(t, tokens, "usr_2") != 2 {
		t.Fatal("the other subject was touched")
	}
}

func TestActionsAreAudited(t *testing.T) {
	ctx := context.Background()
	svc, clients, tokens, logger := newTestService(t)
	mustClient(t, clients, "cli_a")
	saveTokens(t, tokens, "cli_a", "usr_1")

	if err := svc.SuspendClient(ctx, "usr_admin", "cli_a"); err != nil {
		t.Fatal(err)
	}
	events := logger.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Action != "admin.client.suspend" || e.Outcome != audit.OutcomeOK {
		t.Fatalf("event = %+v", e)
	}
	if e.Detail["actor"] != "usr_admin" {
		t.Fatalf("actor = %q, want the caller", e.Detail["actor"])
	}
}
