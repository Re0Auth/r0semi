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

// A deployment with no session revoker — memory mode — cannot reach its own
// sessions at all: scs keeps them as opaque cookies and its in-memory store has no
// listing API, so there is nothing to iterate even for `all`. docs/admin.md §4.2
// used to say the no-index fallback was "clear every session"; the code never did
// that, and the honest report is the reason this matters — the number says zero.
func TestKillSwitchTouchesNoSessionsWithoutARevoker(t *testing.T) {
	svc, _, tokens, _ := newTestService(t)
	saveTokens(t, tokens, "cli", "usr_1")

	rep, err := svc.KillSwitch(context.Background(), "usr_admin", Target{All: true})
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuous: the dimensions that *can* run must have run, so a zero below
	// is the session one and not an untouched report.
	if rep.TokensRevoked == 0 {
		t.Fatal("no tokens were revoked; this test would pass without exercising anything")
	}
	if rep.SessionsRevoked != 0 {
		t.Fatalf("sessions_revoked = %d, want 0: with no revoker there is nothing to reach", rep.SessionsRevoked)
	}
}

// An unredeemed authorization code is a redeemable capability. If the Kill
// Switch leaves it in the token store, the holder exchanges it after the operator
// has been told the account is contained — so bulk revocation has to remove codes
// along with tokens.
func TestKillSwitchRevokesOutstandingAuthorizationCode(t *testing.T) {
	ctx := context.Background()
	svc, _, tokens, _ := newTestService(t)
	saveTokens(t, tokens, "cli", "usr_1")
	if err := tokens.SaveCode(ctx, "code-live", oauth.AuthorizationCode{
		ClientID: "cli", Subject: "usr_1", Scopes: []oauth.Scope{"openid"},
	}); err != nil {
		t.Fatal(err)
	}

	// Anti-vacuous: the code is redeemable before the switch.
	if _, err := tokens.ConsumeCode(ctx, "code-live"); err != nil {
		t.Fatalf("the code was not redeemable before the switch: %v", err)
	}
	if err := tokens.SaveCode(ctx, "code-live", oauth.AuthorizationCode{
		ClientID: "cli", Subject: "usr_1", Scopes: []oauth.Scope{"openid"},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.KillSwitch(ctx, "usr_admin", Target{Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.ConsumeCode(ctx, "code-live"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("ConsumeCode after Kill Switch = %v, want ErrTokenNotFound", err)
	}
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

type fakeSessions struct {
	remaining int64
	subjects  []string
}

func (f *fakeSessions) RevokeAllSessions(context.Context) (int64, error) {
	n := f.remaining
	f.remaining = 0
	return n, nil
}

func (f *fakeSessions) RevokeSubjectSessions(_ context.Context, subject string) (int64, error) {
	f.subjects = append(f.subjects, subject)
	n := f.remaining
	f.remaining = 0
	return n, nil
}

// A subject target now clears that account's sessions too, which is what makes
// "everything for this account" true.
func TestKillSwitchSubjectClearsThatAccountsSessions(t *testing.T) {
	ctx := context.Background()
	tokens := oauth.NewMemoryStore()
	sessions := &fakeSessions{remaining: 2}
	svc, err := New(Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: tokens,
		Sessions: sessions, Audit: audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	saveTokens(t, tokens, "cli_a", "usr_1")

	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{Subject: "usr_1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions.subjects) != 1 || sessions.subjects[0] != "usr_1" {
		t.Fatalf("subject sessions revoked = %v", sessions.subjects)
	}
	if rep.SessionsRevoked != 2 {
		t.Fatalf("sessions_revoked = %d, want 2", rep.SessionsRevoked)
	}
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

type fakeBindings struct {
	all          BindingOutcome
	subject      BindingOutcome
	allCalls     int
	subjectCalls []string
}

func (f *fakeBindings) RevokeAllBindings(context.Context) (BindingOutcome, error) {
	f.allCalls++
	return f.all, nil
}

func (f *fakeBindings) RevokeSubjectBindings(_ context.Context, subject string) (BindingOutcome, error) {
	f.subjectCalls = append(f.subjectCalls, subject)
	return f.subject, nil
}

func withBindingsService(t *testing.T, bindings Bindings) (Service, *oauth.MemoryStore) {
	t.Helper()
	tokens := oauth.NewMemoryStore()
	svc, err := New(Config{
		Clients: oauth.NewMemoryClientRegistry(), Tokens: tokens,
		Bindings: bindings, Audit: audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, tokens
}

// The bindings-only target must cut bindings and nothing else: no token is
// revoked, nobody is signed out.
func TestKillSwitchBindingsTargetTouchesOnlyBindings(t *testing.T) {
	ctx := context.Background()
	bindings := &fakeBindings{all: BindingOutcome{Total: 2, Revoked: 2}}
	svc, tokens := withBindingsService(t, bindings)
	saveTokens(t, tokens, "cli_a", "usr_1")

	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{Bindings: true})
	if err != nil {
		t.Fatal(err)
	}
	if bindings.allCalls != 1 || len(bindings.subjectCalls) != 0 {
		t.Fatalf("sweep calls = all:%d subject:%v", bindings.allCalls, bindings.subjectCalls)
	}
	if rep.Bindings == nil || rep.Bindings.Total != 2 {
		t.Fatalf("bindings = %+v, want the sweep outcome", rep.Bindings)
	}
	if rep.TokensRevoked != 0 {
		t.Fatalf("a bindings-only switch revoked %d tokens", rep.TokensRevoked)
	}
	if n := countTokens(t, tokens, "usr_1"); n != 2 {
		t.Fatalf("tokens were touched: %d remain", n)
	}
}

// `all` grows a binding sweep; `subject` sweeps that account's bindings.
func TestKillSwitchAllAndSubjectSweepBindings(t *testing.T) {
	ctx := context.Background()
	bindings := &fakeBindings{all: BindingOutcome{Total: 3, Revoked: 3}, subject: BindingOutcome{Total: 1, Revoked: 1}}
	svc, tokens := withBindingsService(t, bindings)
	saveTokens(t, tokens, "cli_a", "usr_1")

	rep, err := svc.KillSwitch(ctx, "usr_admin", Target{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if bindings.allCalls != 1 || rep.Bindings == nil || rep.Bindings.Total != 3 {
		t.Fatalf("all: calls=%d report=%+v", bindings.allCalls, rep.Bindings)
	}

	rep, err = svc.KillSwitch(ctx, "usr_admin", Target{Subject: "usr_1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings.subjectCalls) != 1 || bindings.subjectCalls[0] != "usr_1" {
		t.Fatalf("subject sweep calls = %v", bindings.subjectCalls)
	}
	if rep.Bindings == nil || rep.Bindings.Total != 1 {
		t.Fatalf("subject report = %+v", rep.Bindings)
	}
}

// A deployment with no bindings wired refuses the bindings-only target rather
// than reporting a hollow success.
func TestKillSwitchBindingsTargetNeedsThePort(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	if _, err := svc.KillSwitch(context.Background(), "usr_admin", Target{Bindings: true}); !errors.Is(err, ErrBindingsUnavailable) {
		t.Fatalf("= %v, want ErrBindingsUnavailable", err)
	}
}
