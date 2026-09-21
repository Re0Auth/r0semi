package authz

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
)

type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newTestService(t *testing.T, clock *fakeClock, allowed []oauth.Scope) (Service, oauth.Service) {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "Phi CLI", oauth.ClientPublic, "", []string{"https://app.example/cb"}, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://auth.test",
		Scopes: oauth.DefaultRegistry(),
		Now:    clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(as, NewMemoryStore(), Config{TTL: time.Minute, Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	return svc, as
}

func beginInput(scopes []oauth.Scope, verifier string) BeginInput {
	return BeginInput{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		Scopes:              scopes,
		State:               "st-1",
		CodeChallenge:       s256(verifier),
		CodeChallengeMethod: "S256",
	}
}

func TestBeginAndGet(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, _ := newTestService(t, clock, []oauth.Scope{oauth.ScopeAccountID})
	ctx := context.Background()

	req, err := svc.Begin(ctx, beginInput([]oauth.Scope{oauth.ScopeAccountID}, "verifier"))
	if err != nil {
		t.Fatal(err)
	}
	if req.ID == "" || req.ClientName != "Phi CLI" || len(req.Scopes) != 1 {
		t.Fatalf("request = %+v", req)
	}
	if !req.ExpiresAt.After(req.CreatedAt) {
		t.Fatalf("expiry not set: %+v", req)
	}
	got, err := svc.Get(ctx, req.ID)
	if err != nil || got.ID != req.ID {
		t.Fatalf("get = %+v, %v", got, err)
	}
}

func TestBeginRejectsBadRequests(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, _ := newTestService(t, clock, []oauth.Scope{oauth.ScopeAccountID})
	ctx := context.Background()

	in := beginInput([]oauth.Scope{oauth.ScopeAccountID}, "verifier")
	in.ClientID = "nope"
	if _, err := svc.Begin(ctx, in); !isOAuthCode(err, "invalid_client") {
		t.Fatalf("unknown client: %v", err)
	}

	in = beginInput([]oauth.Scope{oauth.ScopePhigrosScore}, "verifier")
	if _, err := svc.Begin(ctx, in); !isOAuthCode(err, "invalid_scope") {
		t.Fatalf("disallowed scope: %v", err)
	}

	in = beginInput([]oauth.Scope{oauth.ScopeAccountID}, "verifier")
	in.CodeChallenge = ""
	if _, err := svc.Begin(ctx, in); !isOAuthCode(err, "invalid_request") {
		t.Fatalf("missing PKCE: %v", err)
	}
}

func TestApproveIssuesUsableCode(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, as := newTestService(t, clock, []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	ctx := context.Background()
	const verifier = "verifier-verifier-verifier-verifier-verifier"

	req, err := svc.Begin(ctx, beginInput([]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore}, verifier))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Approve(ctx, req.ID, "usr_1", []oauth.Scope{oauth.ScopeAccountID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code == "" || resp.State != "st-1" || resp.RedirectURI != "https://app.example/cb" {
		t.Fatalf("response = %+v", resp)
	}

	tok, err := as.Exchange(ctx, oauth.CodeExchangeRequest{
		ClientID: "cli", Code: resp.Code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("code not usable: %v", err)
	}
	if tok.Scope != "account.id" {
		t.Fatalf("scope = %q, want the narrowed set", tok.Scope)
	}
}

func TestApproveCannotWidenScope(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, _ := newTestService(t, clock, []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	ctx := context.Background()

	req, _ := svc.Begin(ctx, beginInput([]oauth.Scope{oauth.ScopeAccountID}, "verifier"))
	if _, err := svc.Approve(ctx, req.ID, "usr_1", []oauth.Scope{oauth.ScopePhigrosScore}, nil); !errors.Is(err, ErrScopeNotRequested) {
		t.Fatalf("err = %v, want ErrScopeNotRequested", err)
	}
}

func TestApproveIsSingleUse(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, _ := newTestService(t, clock, []oauth.Scope{oauth.ScopeAccountID})
	ctx := context.Background()

	req, _ := svc.Begin(ctx, beginInput([]oauth.Scope{oauth.ScopeAccountID}, "verifier"))
	if _, err := svc.Approve(ctx, req.ID, "usr_1", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, req.ID, "usr_1", nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second approve = %v, want ErrNotFound", err)
	}
}

// A critical scope must be individually consented to, and authz passes that
// through to the authorization server.
func TestApproveEnforcesExplicitConsent(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, _ := newTestService(t, clock, []oauth.Scope{oauth.ScopeTapTapStoken})
	ctx := context.Background()

	req, _ := svc.Begin(ctx, beginInput([]oauth.Scope{oauth.ScopeTapTapStoken}, "verifier"))
	if _, err := svc.Approve(ctx, req.ID, "usr_1", []oauth.Scope{oauth.ScopeTapTapStoken}, nil); !isOAuthCode(err, "access_denied") {
		t.Fatalf("without explicit consent: %v", err)
	}
	if _, err := svc.Approve(ctx, req.ID, "usr_1", []oauth.Scope{oauth.ScopeTapTapStoken}, []oauth.Scope{oauth.ScopeTapTapStoken}); err != nil {
		t.Fatalf("with explicit consent: %v", err)
	}
}

func TestDenyReturnsRequest(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, _ := newTestService(t, clock, []oauth.Scope{oauth.ScopeAccountID})
	ctx := context.Background()

	req, _ := svc.Begin(ctx, beginInput([]oauth.Scope{oauth.ScopeAccountID}, "verifier"))
	denied, err := svc.Deny(ctx, req.ID)
	if err != nil || denied.ID != req.ID || denied.State != "st-1" {
		t.Fatalf("deny = %+v, %v", denied, err)
	}
	if _, err := svc.Get(ctx, req.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("request survived deny: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc, _ := newTestService(t, clock, []oauth.Scope{oauth.ScopeAccountID})
	ctx := context.Background()

	req, _ := svc.Begin(ctx, beginInput([]oauth.Scope{oauth.ScopeAccountID}, "verifier"))
	clock.advance(time.Minute)
	if _, err := svc.Get(ctx, req.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func isOAuthCode(err error, code string) bool {
	var oe *oauth.Error
	return errors.As(err, &oe) && oe.Code == code
}

func TestInvalidID(t *testing.T) {
	if InvalidID("arq_" + strings.Repeat("a", 32)) {
		t.Fatal("a valid-shaped id was rejected")
	}
	for _, bad := range []string{"", "arq_", "usr_1", "arq_short"} {
		if !InvalidID(bad) {
			t.Errorf("InvalidID(%q) = false, want true", bad)
		}
	}
}
