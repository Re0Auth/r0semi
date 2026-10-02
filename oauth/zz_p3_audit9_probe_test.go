package oauth

// Probes for the P3 batch (S01-4/5/7/8/9/11/12/13, S04-2/4/5/6/8/9, Z18-3,
// Z18v-1, N-03, KIT-8). Each test is written to FAIL against the pre-fix code:
// every assertion names the property the fix establishes, so a regression turns
// the probe red rather than merely logging.
//
// They are in the default build on purpose: `go test ./oauth/ -count=1` runs
// them. The concurrent ones (S04-8) need `-race` to observe the defect.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// p3FailingLogger is an audit.Logger whose Record always fails. It is the
// sink-outage half of S01-9/N-03.
type p3FailingLogger struct{}

func (p3FailingLogger) Record(context.Context, audit.Event) error {
	return errors.New("audit sink down")
}

// p3FailSaveRefreshStore fails SaveRefresh and delegates everything else, so a
// token issuance can be made to fail after SaveAccess succeeded (S01-4).
type p3FailSaveRefreshStore struct {
	Store
	err error
}

func (s *p3FailSaveRefreshStore) SaveRefresh(context.Context, string, RefreshToken) error {
	return s.err
}

// p3FaultDeviceStore makes the user-code uniqueness read fail with something
// other than ErrDeviceNotFound (S04-5).
type p3FaultDeviceStore struct {
	DeviceStore
	err error
}

func (s *p3FaultDeviceStore) GetDeviceByUserCode(context.Context, string) (DeviceAuthorizationRecord, error) {
	return DeviceAuthorizationRecord{}, s.err
}

func newP3Service(t *testing.T, logger audit.Logger, devices DeviceStore, pollInterval time.Duration) (Service, *MemoryClientRegistry, *MemoryStore, *fakeClock) {
	t.Helper()
	if logger == nil {
		logger = audit.NewMemoryLogger()
	}
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	clients := NewMemoryClientRegistry()
	tokens := NewMemoryStore()
	svc, err := NewService(clients, tokens, logger, Config{
		Issuer:             "https://auth.test",
		Scopes:             testRegistry(t),
		AccessTokenTTL:     time.Hour,
		RefreshTokenTTL:    24 * time.Hour,
		CodeTTL:            time.Minute,
		Devices:            devices,
		DevicePollInterval: pollInterval,
		Now:                clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, clients, tokens, clock
}

// p3Grant runs the authorization-code flow once and returns the pair.
func p3Grant(t *testing.T, svc Service, clientID string) TokenResponse {
	t.Helper()
	const redirect = "https://app.example/cb"
	verifier := "p3-verifier-p3-verifier-p3-verifier-x"
	auth, err := svc.Authorize(context.Background(), AuthorizationRequest{
		ClientID: clientID, RedirectURI: redirect, Subject: "usr_p3",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Exchange(context.Background(), CodeExchangeRequest{
		ClientID: clientID, Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// S01-7: RotateSecret stored a digest of any length while RestoreClient demands
// sha256.Size, so a bad rotation locked the client out at the next restart. The
// wrong length must be refused, and the refusal must leave the old secret live.
func TestP3S017RotateSecretRejectsWrongLengthHash(t *testing.T) {
	reg := NewMemoryClientRegistry()
	ctx := context.Background()
	c, err := NewClient("cli", "App", ClientConfidential, "old-secret", []string{"https://a.example/cb"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(ctx, c); err != nil {
		t.Fatal(err)
	}

	for _, bad := range [][]byte{[]byte("short"), make([]byte, sha256.Size+1)} {
		if err := reg.RotateSecret(ctx, "cli", bad); err == nil {
			t.Fatalf("RotateSecret accepted a %d-byte hash; RestoreClient demands %d", len(bad), sha256.Size)
		}
	}
	got, err := reg.Get(ctx, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Authenticate("old-secret") {
		t.Fatal("a refused rotation silently locked the client out")
	}
	// The well-formed path still works.
	if err := reg.RotateSecret(ctx, "cli", NewSecretHash("new-secret")); err != nil {
		t.Fatal(err)
	}
}

// S04-8: Register wrote the scope map while Get/Resolve/Descriptors read it.
// Run with -race: the concurrent registration below is a data race before the
// mutex was added.
func TestP3S048RegistryConcurrentRegisterAndResolve(t *testing.T) {
	r := DefaultRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_ = r.Register(Descriptor{
				Scope: Scope(fmt.Sprintf("p3.race%d.x", i)), Title: "race probe",
			})
		}(i)
		go func() {
			defer wg.Done()
			_, _ = r.Resolve([]Scope{ScopeAccountID}, "cli")
			_ = r.Descriptors()
			_, _ = r.Get(ScopeAccountID)
		}()
	}
	wg.Wait()
}

// S01-12/Z18-3: a record returned by a Store read aliased the stored Scopes
// backing array, so a caller mutating it rewrote the live token's authorization.
// Save* must also copy: the caller's own slice must not reach into the store.
func TestP3S0112StoreReadsDoNotAliasStoredScopes(t *testing.T) {
	ctx := context.Background()
	exp := time.Unix(1_700_000_000, 0).Add(time.Hour)
	store := NewMemoryStore()

	t.Run("access", func(t *testing.T) {
		in := []Scope{ScopeAccountID}
		if err := store.SaveAccess(ctx, "at", AccessToken{ClientID: "c", Subject: "s", Scopes: in, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
		in[0] = ScopePhigrosScore
		got, err := store.GetAccess(ctx, "at")
		if err != nil {
			t.Fatal(err)
		}
		if got.Scopes[0] != ScopeAccountID {
			t.Fatalf("SaveAccess kept the caller's backing array: %v", got.Scopes)
		}
		got.Scopes[0] = ScopePhigrosB30
		again, err := store.GetAccess(ctx, "at")
		if err != nil {
			t.Fatal(err)
		}
		if again.Scopes[0] != ScopeAccountID {
			t.Fatalf("GetAccess returned an alias of the stored scopes: %v", again.Scopes)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		in := []Scope{ScopeAccountID}
		if err := store.SaveRefresh(ctx, "rt", RefreshToken{ClientID: "c", Subject: "s", Scopes: in, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
		in[0] = ScopePhigrosScore
		got, err := store.GetRefresh(ctx, "rt")
		if err != nil {
			t.Fatal(err)
		}
		if got.Scopes[0] != ScopeAccountID {
			t.Fatalf("SaveRefresh kept the caller's backing array: %v", got.Scopes)
		}
		got.Scopes[0] = ScopePhigrosB30
		again, err := store.GetRefresh(ctx, "rt")
		if err != nil {
			t.Fatal(err)
		}
		if again.Scopes[0] != ScopeAccountID {
			t.Fatalf("GetRefresh returned an alias of the stored scopes: %v", again.Scopes)
		}
	})

	t.Run("code", func(t *testing.T) {
		in := []Scope{ScopeAccountID}
		if err := store.SaveCode(ctx, "cd", AuthorizationCode{ClientID: "c", Subject: "s", Scopes: in, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
		in[0] = ScopePhigrosScore
		got, err := store.GetCode(ctx, "cd")
		if err != nil {
			t.Fatal(err)
		}
		if got.Scopes[0] != ScopeAccountID {
			t.Fatalf("SaveCode kept the caller's backing array: %v", got.Scopes)
		}
		got.Scopes[0] = ScopePhigrosB30
		again, err := store.GetCode(ctx, "cd")
		if err != nil {
			t.Fatal(err)
		}
		if again.Scopes[0] != ScopeAccountID {
			t.Fatalf("GetCode returned an alias of the stored scopes: %v", again.Scopes)
		}
	})
}

// Z18v-1: the second Store read entrances — ListBySubject's GrantRecord.Scopes
// and Introspect's TokenInfo.Scopes — carry the same alias.
func TestP3Z18v1GrantScopesDoNotAliasStoredState(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	exp := time.Unix(1_700_000_000, 0).Add(time.Hour)
	if err := store.SaveAccess(ctx, "at", AccessToken{
		ClientID: "c", Subject: "usr_p3", Scopes: []Scope{ScopeAccountID}, ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}

	recs, err := store.ListBySubject(ctx, "usr_p3")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	recs[0].Scopes[0] = ScopePhigrosB30
	again, err := store.ListBySubject(ctx, "usr_p3")
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Scopes[0] != ScopeAccountID {
		t.Fatalf("ListBySubject returned an alias of the stored scopes: %v", again[0].Scopes)
	}

	// Introspect is the service-level entrance the finding cites.
	svc, clients, _, _ := newP3Service(t, nil, nil, 0)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	tok := p3Grant(t, svc, "app")
	info, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	info.Scopes[0] = ScopePhigrosB30
	info2, err := svc.Introspect(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info2.Scopes[0] != ScopeAccountID {
		t.Fatalf("Introspect returned an alias of the stored scopes: %v", info2.Scopes)
	}
}

// S01-8: RFC 7009 revocation of a spent refresh value returned the uniform
// success without clearing the tombstone DeleteRefresh documents it clears. The
// owner's revocation must reach the tombstone; a foreign client's must not.
func TestP3S018RevokeClearsSpentRefreshTombstone(t *testing.T) {
	ctx := context.Background()

	t.Run("owner", func(t *testing.T) {
		svc, clients, store, _ := newP3Service(t, nil, nil, 0)
		registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
		tok := p3Grant(t, svc, "app")
		if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if err := svc.Revoke(ctx, RevokeRequest{ClientID: "app", Token: tok.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ConsumeRefresh(ctx, tok.RefreshToken); !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("after the owner revoked a spent refresh token, its tombstone is %v; want ErrTokenNotFound", err)
		}
	})

	t.Run("foreign", func(t *testing.T) {
		svc, clients, store, _ := newP3Service(t, nil, nil, 0)
		registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
		registerClient(t, clients, "other", ClientPublic, "", []Scope{ScopeAccountID})
		tok := p3Grant(t, svc, "app")
		if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if err := svc.Revoke(ctx, RevokeRequest{ClientID: "other", Token: tok.RefreshToken}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ConsumeRefresh(ctx, tok.RefreshToken); !errors.Is(err, ErrRefreshTokenReused) {
			t.Fatalf("a foreign client cleared another owner's replay tombstone: %v", err)
		}
	})
}

// S01-4: a failure after SaveAccess left a live, undeliverable access token. The
// failing SaveRefresh must roll the access write back, leaving only the token
// that was already handed out.
func TestP3S014FailedRefreshSaveRollsBackAccessToken(t *testing.T) {
	boom := errors.New("refresh store down")
	svc, clients, base, _ := newP3Service(t, nil, nil, 0)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	tok := p3Grant(t, svc, "app")

	svcImpl := svc.(*service)
	svcImpl.tokens = &p3FailSaveRefreshStore{Store: base, err: boom}

	if _, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: tok.RefreshToken}); !errors.Is(err, boom) {
		t.Fatalf("the failed issuance was reported as %v, want the store error", err)
	}
	// Only the original access token may remain: the failed mint's access token
	// was rolled back.
	n, err := base.RevokeTokens(ctx, TokenFilter{Subject: "usr_p3"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("after a failed issuance %d token records were live, want the 1 already delivered", n)
	}
}

// S01-9/N-03: an audit failure was discarded with `_ =`. It must leave a log
// line (the OP store's shape), because the token/revocation already happened and
// a vanished audit record is the outcome this project does not accept.
func TestP3S019AuditFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	svc, clients, _, _ := newP3Service(t, p3FailingLogger{}, nil, 0)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	p3Grant(t, svc, "app")

	if !strings.Contains(buf.String(), "oauth audit record failed") {
		t.Fatalf("an audit failure left no trace; log = %q", buf.String())
	}
}

// S01-5: an unknown client and a wrong secret are the same invalid_client with
// the same description, so neither the text nor (with the dummy comparison) the
// path enumerates registered client ids.
func TestP3S015UnknownClientAndWrongSecretAreIndistinguishable(t *testing.T) {
	svc, clients, _, _ := newP3Service(t, nil, nil, 0)
	registerClient(t, clients, "conf", ClientConfidential, "s3cret", []Scope{ScopeAccountID})
	ctx := context.Background()

	describe := func(err error) string {
		t.Helper()
		var oe *Error
		if !errors.As(err, &oe) {
			t.Fatalf("err = %v, want *oauth.Error", err)
		}
		if oe.Code != "invalid_client" {
			t.Fatalf("code = %q, want invalid_client", oe.Code)
		}
		return oe.Description
	}

	unknown := describe(svc.AuthenticateClient(ctx, "ghost", "whatever"))
	wrong := describe(svc.AuthenticateClient(ctx, "conf", "wrong"))
	if unknown != wrong {
		t.Fatalf("an unknown client answers %q while a wrong secret answers %q", unknown, wrong)
	}
}

// S01-11: MemoryStore reads were serialised on one Mutex with every other token
// operation. The lock is now a RWMutex so a read takes the shared lock; the two
// assertions are the type guard and the behaviour it buys (a read proceeds while
// another reader holds the lock).
func TestP3S011MemoryStoreReadsTakeTheReadLock(t *testing.T) {
	store := NewMemoryStore()
	if got := reflect.TypeOf(&store.mu).Elem().String(); got != "sync.RWMutex" {
		t.Fatalf("MemoryStore.mu is %s; a read must take a shared lock or it queues behind every scan", got)
	}

	ctx := context.Background()
	store.mu.RLock()
	defer store.mu.RUnlock()
	done := make(chan error, 1)
	go func() {
		_, err := store.GetAccess(ctx, "anything")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("GetAccess = %v, want ErrTokenNotFound", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetAccess blocked behind a concurrent reader: reads still serialise")
	}
}

// S04-2: the device authorization endpoint must authenticate a confidential
// client. An anonymous start used to render that client's name on the consent
// screen; the correct secret must still work, and a public client keeps "none".
func TestP3S042DeviceAuthorizationAuthenticatesConfidentialClient(t *testing.T) {
	svc, clients, _, _ := newP3Service(t, nil, nil, 0)
	registerClient(t, clients, "conf", ClientConfidential, "s3cret", []Scope{ScopeAccountID})
	registerClient(t, clients, "pub", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		req  DeviceAuthorizationRequest
	}{
		{"anonymous", DeviceAuthorizationRequest{ClientID: "conf", Scopes: []Scope{ScopeAccountID}}},
		{"wrong secret", DeviceAuthorizationRequest{ClientID: "conf", ClientSecret: "wrong", Scopes: []Scope{ScopeAccountID}}},
	} {
		_, err := svc.BeginDeviceAuthorization(ctx, tc.req)
		if err == nil {
			t.Fatalf("%s: an unauthenticated confidential device request was accepted", tc.name)
		}
		if got := protocolCode(t, err); got != "invalid_client" {
			t.Fatalf("%s: code = %q, want invalid_client", tc.name, got)
		}
	}
	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "conf", ClientSecret: "s3cret", Scopes: []Scope{ScopeAccountID},
	}); err != nil {
		t.Fatalf("the correct confidential credentials were refused: %v", err)
	}
	if _, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{
		ClientID: "pub", Scopes: []Scope{ScopeAccountID},
	}); err != nil {
		t.Fatalf("a public client was refused: %v", err)
	}
}

// S04-9: a device authorization with no scopes must be refused, not stored and
// redeemed into a scope-less token pair.
func TestP3S049DeviceAuthorizationRejectsEmptyScopes(t *testing.T) {
	svc, clients, _, _ := newP3Service(t, nil, nil, 0)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()

	for _, scopes := range [][]Scope{nil, {}} {
		_, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: scopes})
		if err == nil {
			t.Fatalf("a device authorization with scopes=%v was accepted", scopes)
		}
		if got := protocolCode(t, err); got != "invalid_scope" {
			t.Fatalf("code = %q, want invalid_scope", got)
		}
	}
}

// S04-5: freeUserCode treated every store error as a collision. A store failure
// must surface as itself, not as "could not allocate a unique user code".
func TestP3S045DeviceStoreFailureIsPropagated(t *testing.T) {
	boom := errors.New("device store down")
	svc, clients, _, _ := newP3Service(t, nil, &p3FaultDeviceStore{DeviceStore: NewMemoryDeviceStore(), err: boom}, 0)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})

	_, err := svc.BeginDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{
		ClientID: "cli", Scopes: []Scope{ScopeAccountID},
	})
	if !errors.Is(err, boom) {
		t.Fatalf("the store failure was reported as %v, want the store error", err)
	}
}

// S04-6 (first half): a decided request reports its terminal status even to a
// poll that arrives before the advertised interval; previously slow_down hid it.
func TestP3S046DeviceTerminalStatusBeatsSlowDown(t *testing.T) {
	ctx := context.Background()

	for _, approve := range []bool{false, true} {
		svc, clients, _, _ := newP3Service(t, nil, nil, 0)
		registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
		start, err := svc.BeginDeviceAuthorization(ctx, DeviceAuthorizationRequest{ClientID: "cli", Scopes: []Scope{ScopeAccountID}})
		if err != nil {
			t.Fatal(err)
		}
		// First poll is pending and stamps LastPoll.
		if _, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode}); protocolCode(t, err) != "authorization_pending" {
			t.Fatalf("first poll = %v, want authorization_pending", err)
		}
		if err := svc.DecideDeviceAuthorization(ctx, start.UserCode, "usr_p3", approve, nil, nil); err != nil {
			t.Fatal(err)
		}
		// Poll again immediately: the decision is already terminal.
		tok, err := svc.PollDeviceAuthorization(ctx, DeviceCodeExchangeRequest{ClientID: "cli", DeviceCode: start.DeviceCode})
		if approve {
			if err != nil {
				t.Fatalf("an approved request answered %v to an immediate poll, want tokens", err)
			}
			if tok.AccessToken == "" {
				t.Fatal("an approved request minted no access token")
			}
			continue
		}
		if err == nil {
			t.Fatal("a denied request minted tokens")
		}
		if got := protocolCode(t, err); got != "access_denied" {
			t.Fatalf("a denied request answered %q to an immediate poll, want access_denied", got)
		}
	}
}

// S04-6 (second half): the advertised interval is rounded up, so 2500ms is 3
// seconds rather than a truncated 2 that the server then punishes.
func TestP3S046AdvertisedIntervalIsRoundedUp(t *testing.T) {
	svc, clients, _, _ := newP3Service(t, nil, nil, 2500*time.Millisecond)
	registerClient(t, clients, "cli", ClientPublic, "", []Scope{ScopeAccountID})
	start, err := svc.BeginDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{
		ClientID: "cli", Scopes: []Scope{ScopeAccountID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if start.Interval != 3 {
		t.Fatalf("interval = %d for a 2500ms poll interval, want 3 (round up)", start.Interval)
	}
}

// S01-13/KIT-8: a chunked body over the cap surfaces as *http.MaxBytesError from
// ParseForm, not ErrBodyTooLarge. IsBodyTooLarge is the shared classification the
// three ParseForm call sites need to answer 413. NOTE: the call sites live in
// upstreamkit/ and internal/httpapi/, outside this batch's oauth/** scope, so this
// probe pins the oauth-side helper only; see the report.
func TestP3S0113IsBodyTooLargeClassifiesParseFormOverflow(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(strings.Repeat("x", MaxFormBytes+1)))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	if err := LimitFormBody(rec, req); err != nil {
		t.Fatalf("LimitFormBody on an unknown-length body = %v, want nil", err)
	}
	err := req.ParseForm()
	if err == nil {
		t.Fatal("an over-cap chunked body parsed without error")
	}
	if !IsBodyTooLarge(err) {
		t.Fatalf("ParseForm's overflow (%T: %v) was not classified as too large", err, err)
	}
	// A different parse failure must not be swept into the 413 bucket.
	if IsBodyTooLarge(errors.New("malformed form body")) {
		t.Fatal("IsBodyTooLarge accepted an ordinary parse error")
	}
}
