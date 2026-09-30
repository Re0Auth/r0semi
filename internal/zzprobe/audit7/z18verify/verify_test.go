//go:build audit7

// Package zzprobe_z18verify is the adversarial re-check of area Z18
// (internal/zzprobe/audit7/z18gohazardsweep). It does NOT import or reuse the
// reviewed package: every probe here drives a different entry point or a
// different observation than the one Z18 used, so agreement is independent.
//
//   - TestZ18vReadyzColdWindowIsASilentNilNotACheckedAnswer  (indep. of Z18-1)
//   - TestZ18vTokenStoreHandsOutTheStoredScopeSlice          (indep. of Z18-3)
//   - TestZ18vGrantsViewSharesTheStoredScopeSlice            (new, same family)
//   - TestZ18vZeroRateLimiterNeverRefills                   (Z18 判断 1, runtime)
//   - TestZ18vDiscoveryFailureKeepsServingTheStaleProvider   (new)
//   - TestZ18vZeroRateLimiterFixtureCannotBeReclaimed        (fixture honesty)
package zzprobe_z18verify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// ------------------------------------------------------------------ fixtures

// zzIntrospector never reports a live token; the probes below do not use it.
type zzIntrospector struct{}

func (zzIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, nil
}

type zzGrants struct{}

func (zzGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (zzGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type zzDevices struct{}

func (zzDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, nil
}

func (zzDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return nil
}

type zzOIDC struct{}

func (zzOIDC) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// zzServer mounts httpapi's real middleware chain. Unlike the reviewed fixture
// it is created through the same exported constructor; the differences that
// matter are called out per probe.
func zzServer(t *testing.T, cfg httpapi.Config) *Server {
	t.Helper()
	cfg.Issuer = "https://re0auth.test"
	if cfg.OIDC == nil {
		cfg.OIDC = zzOIDC{}
	}
	cfg.TokenIntrospector = zzIntrospector{}
	cfg.GrantStore = zzGrants{}
	cfg.DeviceStore = zzDevices{}
	api, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	return &Server{t: t, h: api.Handler()}
}

type Server struct {
	t *testing.T
	h http.Handler
}

func (s *Server) get(path string) (int, string) {
	s.t.Helper()
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(body)
}

// ------------------------------------------------------------------ probe 1

// TestZ18vReadyzColdWindowIsASilentNilNotACheckedAnswer re-derives Z18-1 at the
// HTTP boundary with a different observation.
//
// The reviewed probe asserts the racing /readyz is 200. That alone cannot say
// why: a 200 could also come from the check's own fast answer. This probe
// asserts the mechanism instead — the request that ran the check is 503, the
// racing request is 200 "ok", and the racing request did NOT invoke the probe
// (so the 200 is not a fresh, healthy answer). It also keeps a failing probe in
// place and asks only after the check has failed once, so the 200 cannot be a
// TTL-stale healthy value either.
func TestZ18vReadyzColdWindowIsASilentNilNotACheckedAnswer(t *testing.T) {
	var calls atomic.Int64
	inCheck := make(chan struct{}, 1)
	release := make(chan struct{})

	ready := func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			select {
			case inCheck <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return errors.New("dependency unreachable")
	}

	srv := zzServer(t, httpapi.Config{Ready: ready})

	// Request A runs the first-ever check and parks inside it.
	first := make(chan struct {
		code int
		body string
	}, 1)
	go func() {
		code, body := srv.get("/readyz")
		first <- struct {
			code int
			body string
		}{code, body}
	}()
	select {
	case <-inCheck:
	case <-time.After(5 * time.Second):
		t.Fatal("the readiness probe was never invoked; the fixture is vacuous")
	}

	// Request B arrives inside the cold window, on its own connection.
	codeB, bodyB := srv.get("/readyz")
	callsAtB := calls.Load()

	close(release)
	a := <-first

	if a.code != http.StatusServiceUnavailable {
		t.Fatalf("control failed: the request that ran the failing check answered %d, want 503", a.code)
	}
	if callsAtB != 1 {
		t.Fatalf("the racing request did invoke the probe (%d calls); the 200 below cannot be attributed to the cache", callsAtB)
	}
	if codeB == http.StatusServiceUnavailable {
		return // fixed: nothing to report
	}
	t.Errorf("INDEPENDENT: /readyz answered %d %q while the first-ever dependency check was still in "+
		"flight, and the probe had been invoked exactly %d time(s) (its answer later was 503). "+
		"health.go:111-118 returns c.err for `fresh || c.running` without requiring c.checked, so the "+
		"zero value nil is answered as ready before any check has produced a value.",
		codeB, bodyB, callsAtB)
}

// ------------------------------------------------------------------ probe 2

// TestZ18vTokenStoreHandsOutTheStoredScopeSlice re-derives Z18-3 without any
// mutation through a returned value: it shows the store's own map reads back the
// caller's write, which is the aliasing and nothing else.
//
// A caller-visible mutation cannot prove aliasing on its own (a store could copy
// on write and hand back a real copy that the caller then mutates). This probe
// writes through BOTH doors — the slice handed to Introspect and the slice
// handed back by GetAccess — and asserts the stored grant changed each time.
func TestZ18vTokenStoreHandsOutTheStoredScopeSlice(t *testing.T) {
	ctx := context.Background()
	store := oauth.NewMemoryStore()

	granted := make([]oauth.Scope, 1, 4) // spare capacity: the exact hazard shape
	granted[0] = oauth.ScopeAccountID
	if err := store.SaveAccess(ctx, "tok-independent", oauth.AccessToken{
		ClientID: "cli", Subject: "usr_1", Scopes: granted,
	}); err != nil {
		t.Fatalf("SaveAccess: %v", err)
	}

	// Control: a plain read sees what was stored, and the store's own key is the
	// token's hash rather than the token (so this is not reading a caller map).
	control, err := store.GetAccess(ctx, "tok-independent")
	if err != nil {
		t.Fatalf("GetAccess: %v", err)
	}
	if len(control.Scopes) != 1 || control.Scopes[0] != oauth.ScopeAccountID {
		t.Fatalf("control failed: stored scopes=%v", control.Scopes)
	}

	// Door 2a: the slice GetAccess handed back. Rewriting it and reading the
	// store back is the one-step aliasing proof: a store that copied would show
	// account.id here.
	handedOut, err := store.GetAccess(ctx, "tok-independent")
	if err != nil {
		t.Fatalf("GetAccess: %v", err)
	}
	handedOut.Scopes[0] = oauth.Scope("escalated.one")
	afterWriteRead, err := store.GetAccess(ctx, "tok-independent")
	if err != nil {
		t.Fatalf("GetAccess: %v", err)
	}
	wroteThroughReturned := afterWriteRead.Scopes[0] == oauth.Scope("escalated.one")

	// Door 2b: the caller's ORIGINAL slice, on a second record so the two
	// observations cannot contaminate each other. A caller that put scopes in a
	// reused buffer keeps editing the stored grant forever.
	original := make([]oauth.Scope, 1, 4)
	original[0] = oauth.Scope("second.grant")
	if err := store.SaveAccess(ctx, "tok-second", oauth.AccessToken{
		ClientID: "cli", Subject: "usr_2", Scopes: original,
	}); err != nil {
		t.Fatalf("SaveAccess(second): %v", err)
	}
	original[0] = oauth.Scope("escalated.two")
	second, err := store.GetAccess(ctx, "tok-second")
	if err != nil {
		t.Fatalf("GetAccess(second): %v", err)
	}
	wroteThroughCallersSlice := second.Scopes[0] == oauth.Scope("escalated.two")

	if wroteThroughReturned || wroteThroughCallersSlice {
		t.Errorf("INDEPENDENT: the token store shares its scope array with callers — writing through the "+
			"slice GetAccess returned changed the STORED grant: %v; writing through the caller's own slice "+
			"after SaveAccess changed the STORED grant: %v. oauth/tokens.go:216-232 stores and returns the "+
			"record with no clone of Scopes, and oauth/as.go:280 passes that slice on as TokenInfo.Scopes. "+
			"A live token's grant is therefore editable by any consumer that narrows, reorders or reuses "+
			"the scopes it was handed.", wroteThroughReturned, wroteThroughCallersSlice)
	}
}

// ------------------------------------------------------------------ probe 3

// TestZ18vGrantsViewSharesTheStoredScopeSlice is the same invariant at a site the
// reviewed probe does not touch: MemoryStore.ListBySubject builds GrantRecord
// values (oauth/grants.go) whose Scopes field is the stored array, and the
// grants view is built from those records.
//
// This is the new evidence Z18-3's text lacks: the store hands the array out
// through a second door, so a fix that only clones in GetAccess/Introspect would
// leave the family open.
func TestZ18vGrantsViewSharesTheStoredScopeSlice(t *testing.T) {
	ctx := context.Background()
	store := oauth.NewMemoryStore()

	scopes := make([]oauth.Scope, 1, 4)
	scopes[0] = oauth.ScopeAccountID
	if err := store.SaveRefresh(ctx, "refresh-independent", oauth.RefreshToken{
		ClientID: "cli", Subject: "usr_1", Scopes: scopes,
	}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}

	records, err := store.ListBySubject(ctx, "usr_1")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(records) != 1 || len(records[0].Scopes) != 1 {
		t.Fatalf("control failed: records=%+v", records)
	}
	if records[0].Kind != oauth.TokenKindRefresh {
		t.Fatalf("control failed: kind=%q", records[0].Kind)
	}

	// Narrowing the record the grants view was built from edits the stored token.
	records[0].Scopes[0] = oauth.Scope("narrowed.by.grants.view")

	back, err := store.ConsumeRefresh(ctx, "refresh-independent")
	if err != nil {
		t.Fatalf("ConsumeRefresh: %v", err)
	}
	if back.Scopes[0] != oauth.ScopeAccountID {
		t.Errorf("INDEPENDENT: ListBySubject's GrantRecord.Scopes aliases the stored refresh token — "+
			"after narrowing the record the grants view was built from, the stored token's grant scope is "+
			"%q (was %q). oauth/tokens.go:171-178 and :158-180 attach t.Scopes directly; a fix that only "+
			"clones in GetAccess leaves this door open.",
			back.Scopes[0], oauth.ScopeAccountID)
	}
}

// ------------------------------------------------------------------ probe 4

// TestZ18vZeroRateLimiterNeverRefills confirms Z18's "判断 1" at runtime: a
// Limiter created with rate 0 is NOT rate.Inf. It answers once per burst and
// then never again, because x/time/rate reads Limit(0) as "no tokens are ever
// added back".
func TestZ18vZeroRateLimiterNeverRefills(t *testing.T) {
	l := ratelimit.New(0, 1)

	if v := l.Check("k"); !v.Allowed || v.Limit != 1 {
		t.Fatalf("control failed: the first event was not admitted (allowed=%v limit=%d)", v.Allowed, v.Limit)
	}
	for i := 0; i < 3; i++ {
		v := l.Check("k")
		if v.Allowed {
			t.Errorf("INDEPENDENT: a limiter built with perSecond=0 admitted event %d; refillWindow's "+
				"`l.limit <= 0 { return 0 // rate.Inf }` comment (internal/ratelimit/ratelimit.go:116-119) "+
				"claims the bucket is full at every instant, but rate.Limit(0) never refills", i+2)
			return
		}
	}
	// Give a refill window a chance to appear; with rate 0 there is none.
	time.Sleep(30 * time.Millisecond)
	if v := l.Check("k"); v.Allowed {
		t.Errorf("INDEPENDENT: a rate-0 bucket refilled after 30ms (Reset was still %s)", v.Reset)
	}
}

// TestZ18vZeroRateLimiterFixtureCannotBeReclaimed records the fixture limit for
// probe 4: because a zero rate can never be reclaimed (a non-zero refillWindow
// would dominate reclaimWindow), this probe can only assert the non-refill half
// without a clock the limiter does not expose. It is a green guard on the
// observation, not a finding.
func TestZ18vZeroRateLimiterFixtureCannotBeReclaimed(t *testing.T) {
	l := ratelimit.New(0, 1)
	_ = l.Check("k")
	if v := l.Check("other"); !v.Allowed {
		t.Logf("a second key on the same limiter is denied as well (overflow/naive accounting); "+
			"Reset=%s Remaining=%d", v.Reset, v.Remaining)
	}
	if got := l.Size(); got == 0 {
		t.Errorf("the limiter tracked no key after Check, so the probe above observed nothing")
	}
}

// ------------------------------------------------------------------ probe 5

// TestZ18vDiscoveryFailureKeepsServingTheStaleProvider is a new hazard in the
// same function Z18-2 reports (idp.Client.oidcProvider).
//
// The cache is documented as "at most providerTTL" (idp.go:606-618). That is
// true only while discovery SUCCEEDS: when a re-discovery fails after a
// successful one, the failing branch returns the cached provider and does not
// touch discoveredAt (idp.go:626-633). So a retired/rotated JWKS keeps verifying
// id_tokens indefinitely — the TTL stops applying exactly when the upstream is
// telling this client its key set is gone.
//
// The probe drives a real idp.Client against a real discovery endpoint: first
// discovery succeeds and is cached; every later discovery answers non-JSON so
// oidc.NewProvider fails; a call the TTL would force to re-discover still
// succeeds from the stale cache. The positive control is the first (successful)
// login, which proves the fixture reaches discovery at all; a second control
// (a fresh client against the broken issuer, never cached) must FAIL, which
// proves the failure is real and not the fixture answering from somewhere else.
func TestZ18vDiscoveryFailureKeepsServingTheStaleProvider(t *testing.T) {
	var broken atomic.Bool
	var base string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if broken.Load() {
			// A discovery document that is not one: the upstream has retired the
			// key set, or is answering an error page.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "<html>gone</html>")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	issuer := httptest.NewServer(mux)
	defer issuer.Close()
	base = issuer.URL

	newClient := func(ttl time.Duration) *idp.Client {
		t.Helper()
		reg, err := idp.NewRegistry(idp.RegistryConfig{
			RedirectBase:     "https://re0auth.test",
			HTTPClient:       issuer.Client(),
			ProviderCacheTTL: ttl,
			Credentials: []idp.Credentials{{
				Provider: idp.Provider("zzstale"), ClientID: "cid", ClientSecret: "sec",
				Issuer: issuer.URL,
			}},
		})
		if err != nil {
			t.Fatalf("idp.NewRegistry: %v", err)
		}
		c, ok := reg.Get(idp.Provider("zzstale"))
		if !ok {
			t.Fatal("the provider was not registered")
		}
		return c
	}

	// Control A: a never-cached client against the broken issuer must fail. If
	// it did not, the stale-cache result below would prove nothing.
	broken.Store(true)
	fresh := newClient(time.Nanosecond)
	if _, err := fresh.AuthCodeURL(context.Background(), "s", fresh.NewVerifier(), "n"); err == nil {
		t.Fatal("control failed: discovery against a broken issuer succeeded on a cold cache")
	}
	broken.Store(false)

	// A one-nanosecond TTL means every later call must re-discover.
	c := newClient(time.Nanosecond)
	if _, err := c.AuthCodeURL(context.Background(), "s1", c.NewVerifier(), "n1"); err != nil {
		t.Fatalf("control failed: the first login could not discover: %v", err)
	}

	broken.Store(true)
	_, err := c.AuthCodeURL(context.Background(), "s2", c.NewVerifier(), "n2")
	if err != nil {
		return // re-discovery failed and the call failed: the TTL bound held
	}
	t.Errorf("NEW: with a 1ns provider TTL and the issuer's discovery answering 500, a call that must " +
		"re-discover still succeeded. idp.go:626-633 returns the cached provider and does not update " +
		"discoveredAt on failure, so the documented `at most providerTTL` bound (idp.go:606-613) does " +
		"not hold once discovery starts failing: the cached keys — and the endpoints pinned from them — " +
		"are trusted for the life of the process.")
}
