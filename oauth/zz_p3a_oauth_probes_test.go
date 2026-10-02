package oauth

// P3 batch "oauth-a" probes: S01-4, S01-5, S01-7, S01-8, S01-9, S01-11, S01-12,
// S04-2, S04-4 (S01-10 is NEEDS-DECISION and has no probe here).
//
// Every test below is written so that it FAILS on the pre-fix code it names and
// PASSES on the fixed code. The pre-fix failure mode is stated on each test.
//
// They live in one file so the batch can be run and, where needed, re-run against
// a reverted copy of a single source file through `go test -overlay` without
// touching the working tree:
//
//	go test ./oauth/ -run 'TestP3A_' -count=1

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// ---------------------------------------------------------------------------
// S01-4 — token issuance left a live access token in the store when the refresh
// save failed. Pre-fix: SaveRefresh fails, DeleteAccess is never called, the
// access row stays live and introspectable -> probe fails.
// ---------------------------------------------------------------------------

// p3aFaultStore wraps a MemoryStore and can make the refresh write fail while
// recording exactly which access value was saved and deleted.
type p3aFaultStore struct {
	*MemoryStore
	failRefresh  bool
	savedAccess  []string
	removedAcces []string
}

func (s *p3aFaultStore) SaveAccess(ctx context.Context, value string, t AccessToken) error {
	s.savedAccess = append(s.savedAccess, value)
	return s.MemoryStore.SaveAccess(ctx, value, t)
}

func (s *p3aFaultStore) SaveRefresh(ctx context.Context, value string, t RefreshToken) error {
	if s.failRefresh {
		return errors.New("p3a: refresh write failed")
	}
	return s.MemoryStore.SaveRefresh(ctx, value, t)
}

func (s *p3aFaultStore) DeleteAccess(ctx context.Context, value string) error {
	s.removedAcces = append(s.removedAcces, value)
	return s.MemoryStore.DeleteAccess(ctx, value)
}

func TestP3A_S01_4_IssueRollsBackAccessWhenRefreshSaveFails(t *testing.T) {
	ctx := context.Background()
	store := &p3aFaultStore{MemoryStore: NewMemoryStore(), failRefresh: true}
	svc, err := NewService(NewMemoryClientRegistry(), store, audit.NewMemoryLogger(), Config{
		Issuer: "https://auth.test", Scopes: DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := svc.(*service)

	if _, err := s.issue(ctx, "app", "user-1", []Scope{ScopeAccountID}, ""); err == nil {
		t.Fatal("issue succeeded although the refresh write failed")
	}
	if len(store.savedAccess) != 1 {
		t.Fatalf("SaveAccess called %d times, want 1", len(store.savedAccess))
	}
	if len(store.removedAcces) != 1 || store.removedAcces[0] != store.savedAccess[0] {
		t.Fatalf("access rollback = %v, want exactly [%s]", store.removedAcces, store.savedAccess[0])
	}
	if _, err := store.MemoryStore.GetAccess(ctx, store.savedAccess[0]); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("undeliverable access token is still live: GetAccess = %v", err)
	}

	// Control: with the refresh write working, the pair survives — the rollback
	// must not have turned successful issuance into a delete.
	ok := &p3aFaultStore{MemoryStore: NewMemoryStore()}
	svcOK, err := NewService(NewMemoryClientRegistry(), ok, audit.NewMemoryLogger(), Config{
		Issuer: "https://auth.test", Scopes: DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svcOK.(*service).issue(ctx, "app", "user-1", []Scope{ScopeAccountID}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ok.MemoryStore.GetAccess(ctx, resp.AccessToken); err != nil {
		t.Fatalf("successful issuance lost its access token: %v", err)
	}
}

// ---------------------------------------------------------------------------
// S04-2 — BeginDeviceAuthorization admitted a confidential client without
// authenticating it. Pre-fix: a request carrying only client_id succeeded ->
// probe fails.
// ---------------------------------------------------------------------------

func TestP3A_S04_2_ConfidentialDeviceClientMustAuthenticate(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "conf", ClientConfidential, "s3cret", []Scope{ScopeAccountID})
	registerClient(t, clients, "pub", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "conf", Scopes: []Scope{ScopeAccountID},
	}); protocolCode(t, err) != "invalid_client" {
		t.Fatalf("anonymous confidential start: %v", err)
	}
	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "conf", ClientSecret: "wrong", Scopes: []Scope{ScopeAccountID},
	}); protocolCode(t, err) != "invalid_client" {
		t.Fatalf("confidential start with a wrong secret: %v", err)
	}
	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "conf", ClientSecret: "s3cret", Scopes: []Scope{ScopeAccountID},
	}); err != nil {
		t.Fatalf("confidential start with the right secret: %v", err)
	}
	// A public client keeps the "none" method: it has no secret to send.
	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "pub", Scopes: []Scope{ScopeAccountID},
	}); err != nil {
		t.Fatalf("public start without a secret: %v", err)
	}
}

// ---------------------------------------------------------------------------
// S01-5 — an unknown client and a wrong secret were distinguishable through
// error_description. Pre-fix: "unknown client" vs "invalid client credentials"
// -> probe fails.
// ---------------------------------------------------------------------------

func TestP3A_S01_5_UnknownClientAndWrongSecretShareOneAnswer(t *testing.T) {
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientConfidential, "right-secret", []Scope{ScopeAccountID})
	ctx := context.Background()

	_, errUnknown := svc.Exchange(ctx, CodeExchangeRequest{ClientID: "ghost", ClientSecret: "x"})
	_, errWrong := svc.Exchange(ctx, CodeExchangeRequest{ClientID: "app", ClientSecret: "wrong"})

	var u, w *Error
	if !errors.As(errUnknown, &u) || !errors.As(errWrong, &w) {
		t.Fatalf("errs = %v / %v, want two *oauth.Error", errUnknown, errWrong)
	}
	if u.Code != "invalid_client" || w.Code != "invalid_client" {
		t.Fatalf("codes = %q / %q, want invalid_client", u.Code, w.Code)
	}
	if u.Description != w.Description {
		t.Fatalf("the refusal tells an unknown client from a wrong secret: %q vs %q", u.Description, w.Description)
	}
}

// ---------------------------------------------------------------------------
// S01-7 — RotateSecret accepted a digest of any length while RestoreClient
// demands sha256.Size, silently bricking the client on the next restart.
// Pre-fix: the short hash was stored, so the original secret stopped
// authenticating -> probe fails.
// ---------------------------------------------------------------------------

func TestP3A_S01_7_RotateSecretRefusesWrongLengthDigest(t *testing.T) {
	reg := NewMemoryClientRegistry()
	ctx := context.Background()
	c, err := NewClient("cli", "App", ClientConfidential, "original-secret", []string{"https://a.example/cb"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(ctx, c); err != nil {
		t.Fatal(err)
	}

	for _, bad := range [][]byte{[]byte("0123456789abcdef"), []byte("short"), bytes.Repeat([]byte{0x5a}, 33)} {
		if err := reg.RotateSecret(ctx, "cli", bad); err == nil {
			t.Fatalf("rotation accepted a %d-byte digest", len(bad))
		}
		got, err := reg.Get(ctx, "cli")
		if err != nil {
			t.Fatal(err)
		}
		if !got.Authenticate("original-secret") {
			t.Fatalf("a refused %d-byte rotation still locked the client out", len(bad))
		}
	}
	// The shape RestoreClient demands is exactly what RotateSecret accepts.
	if err := reg.RotateSecret(ctx, "cli", NewSecretHash("new-secret")); err != nil {
		t.Fatalf("a %d-byte digest was refused: %v", len(NewSecretHash("x")), err)
	}
	got, err := reg.Get(ctx, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Authenticate("new-secret") {
		t.Fatal("a valid rotation did not take effect")
	}
	if _, err := RestoreClientWithStatus("cli", "App", ClientConfidential, ClientActive, got.SecretHash(),
		[]string{"https://a.example/cb"}, nil, got.CreatedAt); err != nil {
		t.Fatalf("the stored digest cannot be restored: %v", err)
	}
}

// ---------------------------------------------------------------------------
// S01-8 — Revoke could not reach a spent refresh token's tombstone, so RFC 7009
// revocation of a rotated token was a false success. Pre-fix: the tombstone
// survived and #presenting the value again reported a reuse -> probe fails.
// ---------------------------------------------------------------------------

func TestP3A_S01_8_RevokeClearsSpentRefreshTombstone(t *testing.T) {
	svc, clients, tokens, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientConfidential, "sec", []Scope{ScopeAccountID})
	ctx := context.Background()

	resp, err := svc.(*service).issue(ctx, "app", "user-1", []Scope{ScopeAccountID}, "")
	if err != nil {
		t.Fatal(err)
	}
	// Rotate once: the presented value is now spent and only a tombstone remains.
	if _, err := tokens.ConsumeRefresh(ctx, resp.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if owner, err := tokens.SpentRefreshOwner(ctx, resp.RefreshToken); err != nil || owner != "app" {
		t.Fatalf("spent value owner = %q, %v; want app", owner, err)
	}

	if err := svc.Revoke(ctx, RevokeRequest{ClientID: "app", ClientSecret: "sec", Token: resp.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.SpentRefreshOwner(ctx, resp.RefreshToken); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("tombstone survived the revocation: SpentRefreshOwner = %v", err)
	}
	// The replay signal is gone too: the value is now an ordinary unknown, not a
	// theft report the caller would answer by revoking the whole family.
	if _, err := tokens.ConsumeRefresh(ctx, resp.RefreshToken); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("post-revocation replay = %v, want ErrTokenNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// S01-9 — an audit write failure was discarded with `_ =`. Pre-fix: no log line
// at all -> probe fails.
// ---------------------------------------------------------------------------

type p3aFailingAudit struct{ calls int }

func (l *p3aFailingAudit) Record(context.Context, audit.Event) error {
	l.calls++
	return errors.New("p3a: audit sink down")
}

func TestP3A_S01_9_AuditFailureIsLogged(t *testing.T) {
	logger := &p3aFailingAudit{}
	svc, err := NewService(NewMemoryClientRegistry(), NewMemoryStore(), logger, Config{
		Issuer: "https://auth.test", Scopes: DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := svc.(*service)

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	s.record(context.Background(), "oauth.p3a.probe", "", "cli", audit.OutcomeOK)

	if logger.calls != 1 {
		t.Fatalf("audit logger called %d times, want 1", logger.calls)
	}
	if !strings.Contains(buf.String(), "oauth audit record failed") {
		t.Fatalf("a failed audit record left no trace in the log: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "oauth.p3a.probe") {
		t.Fatalf("the log does not name the action that failed: %q", buf.String())
	}
}

// ---------------------------------------------------------------------------
// S01-11 — every token operation, reads included, contended on one Mutex.
// Pre-fix: mu was a sync.Mutex (this test does not compile) and GetAccess took
// the write lock, so the read below blocked behind the held read lock -> fails.
// ---------------------------------------------------------------------------

func TestP3A_S01_11_TokenReadsShareTheStoreReadLock(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.SaveAccess(ctx, "at", AccessToken{ClientID: "c", Scopes: []Scope{ScopeAccountID}}); err != nil {
		t.Fatal(err)
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	done := make(chan error, 1)
	go func() {
		_, err := store.GetAccess(ctx, "at")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GetAccess blocked behind a held read lock: introspection still needs the write lock (S01-11)")
	}
}

// ---------------------------------------------------------------------------
// S01-12 — a returned record's Scopes slice aliased the stored backing array.
// Pre-fix: the mutation below was visible through the next read -> fails.
// ---------------------------------------------------------------------------

func TestP3A_S01_12_ReturnedScopesDoNotAliasStoredState(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	field := []Scope{ScopeAccountID}
	if err := store.SaveAccess(ctx, "at", AccessToken{ClientID: "c", Subject: "u", Scopes: field}); err != nil {
		t.Fatal(err)
	}
	// The caller keeping and mutating the slice it passed must not reach the store.
	field[0] = ScopePhigrosScore

	got, err := store.GetAccess(ctx, "at")
	if err != nil {
		t.Fatal(err)
	}
	got.Scopes[0] = ScopePhigrosScore
	again, err := store.GetAccess(ctx, "at")
	if err != nil {
		t.Fatal(err)
	}
	if again.Scopes[0] != ScopeAccountID {
		t.Fatalf("mutating a returned AccessToken rewrote stored scopes: %v", again.Scopes)
	}

	if err := store.SaveRefresh(ctx, "rt", RefreshToken{ClientID: "c", Subject: "u", Scopes: []Scope{ScopeAccountID}}); err != nil {
		t.Fatal(err)
	}
	records, err := store.ListBySubject(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		r.Scopes[0] = ScopePhigrosScore
	}
	after, err := store.ListBySubject(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range after {
		if r.Scopes[0] != ScopeAccountID {
			t.Fatalf("mutating a returned GrantRecord rewrote stored scopes: %v", r.Scopes)
		}
	}

	// Introspect forwards the access record's scopes to the caller (as.go).
	svc, clients, _, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	resp, err := svc.(*service).issue(ctx, "app", "user-1", []Scope{ScopeAccountID}, "")
	if err != nil {
		t.Fatal(err)
	}
	info, err := svc.Introspect(ctx, resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	info.Scopes[0] = ScopePhigrosScore
	info2, err := svc.Introspect(ctx, resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info2.Scopes[0] != ScopeAccountID {
		t.Fatalf("mutating TokenInfo.Scopes rewrote stored authorization state: %v", info2.Scopes)
	}
}

// ---------------------------------------------------------------------------
// S04-4 — the grants page's full-map scan took the store's one mutex.
// Pre-fix: ListBySubject took the write lock (single Mutex), so the scan below
// blocked behind the held read lock -> fails.
// ---------------------------------------------------------------------------

func TestP3A_S04_4_GrantsScanSharesTheStoreReadLock(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.SaveAccess(ctx, "at", AccessToken{ClientID: "c", Subject: "u", Scopes: []Scope{ScopeAccountID}}); err != nil {
		t.Fatal(err)
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	done := make(chan error, 1)
	go func() {
		_, err := store.ListBySubject(ctx, "u")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the grants scan blocked behind a held read lock: ListBySubject still serialises every token read (S04-4)")
	}
}
