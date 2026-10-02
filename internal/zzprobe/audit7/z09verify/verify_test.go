//go:build audit7

// Package zzprobe_z09verify — adversarial verification of the area Z09 report.
//
// Everything here is an INDEPENDENT probe written by the reviewing agent. Three
// things are being checked:
//
//  1. Z09-4's family: the upstream resource budget is joint, and the reviewer
//     found a second, cheaper instance of the same shape on the same shared
//     outbound client — the per-HOST circuit breaker. One account's dead
//     credential is classified as host-unhealthy, so five of that account's reads
//     shed every OTHER account's read of the same source for the cooldown.
//  2. A fail-dangerous branch in refreshRejected: a store read that FAILS is
//     treated as "the version did not move", which is the branch that shreds the
//     secret and deletes the binding.
//  3. A positive control for the reviewed report's CRLF guard, whose green it
//     never proved was not "the request never left".
package zzprobe_z09verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	zzGame   = "phigros"
	zzScope  = "phigros.profile.read"
	zzSource = "src"
)

func newVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("verify", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func secretPayload(t *testing.T, access, refresh string) []byte {
	t.Helper()
	p, err := json.Marshal(map[string]string{"access_token": access, "refresh_token": refresh})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// enroll mirrors CompleteBind: metadata in the store, the token pair in the vault.
func enroll(t *testing.T, store federation.BindingStore, v vault.Service, user account.UserID, access string) federation.Binding {
	t.Helper()
	b := federation.Binding{User: user, Game: zzGame, Source: zzSource, Version: 1}
	if err := store.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(b), secretPayload(t, access, ""), nil); err != nil {
		t.Fatal(err)
	}
	return b
}

func fetch(t *testing.T, svc federation.Service, user account.UserID) (federation.FetchResult, error) {
	t.Helper()
	return svc.Fetch(context.Background(), federation.FetchRequest{
		User: user, Game: zzGame, Resource: "profile",
	})
}

// ---------------------------------------------------------------------------
// New finding V1: the shared per-host breaker turns one account's credential
// failure into a source-wide outage.
// ---------------------------------------------------------------------------

// deadCredentialUpstream answers 401 for the attacker's upstream token and 200 for
// anyone else's. The source itself is healthy: the victim's read works before and
// after the attacker exists.
func deadCredentialUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer dead-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"served_by":"src"}`)
	}))
	t.Cleanup(up.Close)
	return up, &calls
}

// breakerService wires the composition root's shape: ONE shared outbound client
// (and therefore one breaker per host) for every account
// (cmd/re0auth/main.go:492-508).
func breakerService(t *testing.T, opts httpclient.BreakerOptions, up *httptest.Server) federation.Service {
	t.Helper()
	return breakerServiceTuned(t, opts, up, nil)
}

// breakerServiceTuned is breakerService with a last look at the federation
// Config, so a probe can shorten the per-binding cooldown (Z09V-1) the way it
// already shortens the breaker's.
func breakerServiceTuned(t *testing.T, opts httpclient.BreakerOptions, up *httptest.Server, tune func(*federation.Config)) federation.Service {
	t.Helper()
	reg, err := federation.NewRegistry(federation.Source{
		Game: zzGame, Name: zzSource, DisplayName: "Src", Issuer: up.URL,
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzScope},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := federation.NewMemoryBindingStore()
	v := newVault(t)
	enroll(t, store, v, "usr_atk", "dead-token")
	enroll(t, store, v, "usr_vic", "live-token")
	hc := httpclient.NewOutboundClient(httpclient.OutboundConfig{Breaker: &opts})
	cfg := federation.Config{
		Registry: reg, Bindings: store, Vault: v,
		Doer: hc, HTTPClient: hc, BaseURL: "https://re0auth.test",
	}
	if tune != nil {
		tune(&cfg)
	}
	svc, err := federation.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// fetchErr is fetch when only the error matters.
func fetchErr(t *testing.T, svc federation.Service, user account.UserID) error {
	t.Helper()
	_, err := fetch(t, svc, user)
	return err
}

// INVERTED, and the regression guard for the fix (Z09V-1,
// docs/issues/P2-medium.md). At shipped defaults (5 failures / 30s cooldown):
// after five reads by ONE account whose upstream credential is dead, an unrelated
// account's read of the same source must SUCCEED and cost exactly its own upstream
// call. The name is the defect this guards against; before the fix this test was
// the RED probe, and it asserted the victim was refused with ErrCircuitOpen and no
// upstream call.
//
// The attacker's own binding still has to pay for its dead credential somewhere:
// the per-binding cooldown (internal/federation) sheds the SIXTH read without
// dialing, which is asserted here so the inversion did not simply move the cost to
// the source.
func TestZ09VerifyOneAccountsDeadCredentialShedsAnothersRead(t *testing.T) {
	up, calls := deadCredentialUpstream(t)
	svc := breakerService(t, httpclient.BreakerOptions{}, up)

	// Control 1 (the source is healthy for the victim): baseline read.
	if _, err := fetch(t, svc, "usr_vic"); err != nil {
		t.Fatalf("baseline victim read = %v; the probe cannot attribute anything later to the breaker", err)
	}
	baselineCalls := calls.Load()

	// Control 2 (the attacker's failures are the attacker's OWN credential, not a
	// dead host): each of the five reads is answered 401 by a live source.
	var atk []error
	for i := 0; i < 5; i++ {
		_, err := fetch(t, svc, "usr_atk")
		atk = append(atk, err)
	}
	afterAttacker := calls.Load()
	t.Logf("baseline victim read ok (%d upstream calls); 5 attacker reads produced %d upstream calls; attacker errors = %v",
		baselineCalls, afterAttacker-baselineCalls, atk)

	// The property under guard: the victim's read, whose own credential the source
	// accepts, is served — a 401 is one caller's credential state, not the host's
	// health, so it must not shed the source for anybody else.
	res, err := fetch(t, svc, "usr_vic")
	shedCalls := calls.Load()
	t.Logf("after the attacker's reads: victim read = %+v err=%v, upstream calls added = %d",
		res, err, shedCalls-afterAttacker)

	if err != nil {
		t.Fatalf("the victim's read was refused (%v) after five 401s by a DIFFERENT account: a per-host "+
			"breaker is still reading one caller's dead credential as the source being down", err)
	}
	if shedCalls != afterAttacker+1 {
		t.Fatalf("the victim's read produced %d upstream calls, want exactly 1 (it was not shed, and it did "+
			"not fan out)", shedCalls-afterAttacker)
	}
	if string(res.Data) != `{"served_by":"src"}` {
		t.Fatalf("the victim's read returned %q, want the source's payload", res.Data)
	}

	// The cost of the attacker's own dead credential is now its OWN binding's
	// cooldown: the sixth read is refused without asking the source.
	beforeCooldown := calls.Load()
	if _, err := fetch(t, svc, "usr_atk"); !errors.Is(err, federation.ErrBindingCooldown) {
		t.Fatalf("the attacker's sixth read = %v, want ErrBindingCooldown: the per-binding cooldown did not "+
			"take over from the breaker's 401 rule", err)
	}
	if added := calls.Load() - beforeCooldown; added != 0 {
		t.Fatalf("a cooling binding was still dialed (%d upstream calls added)", added)
	}
	t.Logf("the attacker's sixth read was shed by the per-binding cooldown with no upstream call")
}

// The recovery control, re-derived for the fix (Z09V-1, docs/issues/P2-medium.md).
//
// It used to assert the victim got ErrCircuitOpen after the attacker's five reads
// and recovered when the HOST breaker half-opened. The victim is never inside the
// attacker's breaker now, so the assertion is the opposite: the victim is served
// throughout, and what sheds and recovers is the ATTACKER'S OWN binding, on the
// per-binding cooldown. The cooldown is shortened (Config.BindingCooldown) so the
// test does not sleep the shipped 30s; the failure threshold is still the shipped 5.
func TestZ09VerifyTheVictimRecoversWhenTheBreakerHalfOpens(t *testing.T) {
	up, calls := deadCredentialUpstream(t)
	svc := breakerServiceTuned(t, httpclient.BreakerOptions{
		Cooldown: 250 * time.Millisecond, HalfOpenSuccesses: 1,
	}, up, func(cfg *federation.Config) {
		cfg.BindingCooldown = 250 * time.Millisecond
	})

	if _, err := fetch(t, svc, "usr_vic"); err != nil {
		t.Fatalf("baseline victim read = %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := fetch(t, svc, "usr_atk"); err == nil {
			t.Fatalf("attacker read %d accepted the dead credential", i+1)
		}
	}
	// The victim is not punished for another binding's credential.
	if _, err := fetch(t, svc, "usr_vic"); err != nil {
		t.Fatalf("victim read after the attacker = %v, want success: a 401 is not host health", err)
	}
	// The attacker's own binding is cooling: refused without an upstream call.
	before := calls.Load()
	if _, err := fetch(t, svc, "usr_atk"); !errors.Is(err, federation.ErrBindingCooldown) {
		t.Fatalf("attacker read after the threshold = %v, want ErrBindingCooldown", err)
	}
	if added := calls.Load() - before; added != 0 {
		t.Fatalf("the cooling binding was still dialed (%d upstream calls added)", added)
	}

	time.Sleep(400 * time.Millisecond)
	// The cooldown has lapsed, so the source is asked again (and answers 401).
	before = calls.Load()
	err := fetchErr(t, svc, "usr_atk")
	if errors.Is(err, federation.ErrBindingCooldown) {
		t.Fatalf("attacker read after the cooldown = %v; the cooldown did not lapse", err)
	}
	if err == nil {
		t.Fatalf("attacker read after the cooldown succeeded; the dead credential should still be rejected")
	}
	if added := calls.Load() - before; added != 1 {
		t.Fatalf("after the cooldown the upstream call count moved by %d, want 1", added)
	}
	// The victim's read never depended on any of this.
	if _, err := fetch(t, svc, "usr_vic"); err != nil {
		t.Fatalf("victim read after everything = %v; the per-binding cooldown leaked", err)
	}
}

// The bound on V1 as it was measured: failsafe's countingStats is a rolling
// window of the last failureThresholdingCapacity (5) executions and the circuit
// opened only when ALL of them were failures, so an interleaved success by anybody
// kept it closed — which is why V1 was a burst attack rather than a guaranteed
// one. After Z09V-1 the shared breaker does not see a 401 at all, so this test is
// now two controls at once: the interleaved victim read stays green (nothing about
// the host opened), and the attacker's own binding is what eventually stops being
// dialed (its per-binding cooldown, counted separately from the victim's reads).
func TestZ09VerifyAnInterleavedSuccessKeepsTheSharedBreakerClosed(t *testing.T) {
	up, calls := deadCredentialUpstream(t)
	svc := breakerService(t, httpclient.BreakerOptions{}, up)

	for i := 0; i < 10; i++ {
		if _, err := fetch(t, svc, "usr_atk"); err == nil {
			t.Fatalf("iteration %d: the attacker's dead credential was accepted", i)
		}
		if _, err := fetch(t, svc, "usr_vic"); err != nil {
			t.Fatalf("iteration %d: an interleaved victim success did not stay accepted: %v", i, err)
		}
	}
	t.Logf("10 interleaved (dead, live) pairs produced %d upstream calls and no opened breaker", calls.Load())
}

// ---------------------------------------------------------------------------
// New finding V2: refreshRejected destroys a binding when its confirmatory
// re-read fails.
// ---------------------------------------------------------------------------

// fsStore fails Get while fail is set, delegating otherwise.
type fsStore struct {
	*federation.MemoryBindingStore
	fail atomic.Bool
}

func (s *fsStore) Get(ctx context.Context, user account.UserID, game, source string) (federation.Binding, error) {
	if s.fail.Load() {
		return federation.Binding{}, errors.New("verify: injected store read failure")
	}
	return s.MemoryBindingStore.Get(ctx, user, game, source)
}

// Subtest A (the finding): the upstream rejects the refresh, and the re-read that
// is supposed to prove "nobody else rotated this" fails. The store failure is not
// distinguished from "the version did not move", so the binding row is deleted and
// the vault secret shredded.
//
// Subtest B (the control): the identical rejection, but the re-read WORKS and
// shows a version that moved (another writer rotated the grant while this call was
// at the source). The binding survives and the read is retried. The two subtests
// differ only in the re-read's outcome — exactly the branch under review.
func TestZ09VerifyAStoreReadFailureIsDestroyedAsIfTheGrantWereDead(t *testing.T) {
	const user = account.UserID("usr_1")

	type rig struct {
		store federation.BindingStore
		v     vault.Service
		svc   federation.Service
	}
	setup := func(t *testing.T, otherWriterRotated bool) rig {
		t.Helper()
		store := &fsStore{MemoryBindingStore: federation.NewMemoryBindingStore()}
		v := newVault(t)
		// Expired + a refresh token: refreshBinding proceeds to the source.
		b := federation.Binding{
			User: user, Game: zzGame, Source: zzSource,
			HasRefresh: true, Expiry: time.Now().Add(-time.Hour), Version: 1,
		}
		if err := store.Put(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		if err := v.Enroll(context.Background(), federation.BindingIdentity(b),
			secretPayload(t, "old-token", "rt-1"), nil); err != nil {
			t.Fatal(err)
		}

		// The resource server: 401 for the old token, 200 for the replacement.
		res := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "Bearer new-token" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"served_by":"src"}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(res.Close)

		v2 := b
		v2.Version = 7
		v2.Expiry = time.Now().Add(time.Hour)

		// The token endpoint answers 400 invalid_grant, the one condition that
		// reaches refreshRejected.
		tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if otherWriterRotated {
				// Another writer commits a rotation while this call is at the source.
				if err := store.MemoryBindingStore.Put(context.Background(), v2); err != nil {
					t.Errorf("commit rotation: %v", err)
				}
				if err := v.Enroll(context.Background(), federation.BindingIdentity(v2),
					secretPayload(t, "new-token", "rt-2"), nil); err != nil {
					t.Errorf("enroll rotation: %v", err)
				}
			} else {
				store.fail.Store(true) // the confirmatory re-read will fail
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		}))
		t.Cleanup(tok.Close)

		reg, err := federation.NewRegistry(federation.Source{
			Game: zzGame, Name: zzSource, DisplayName: "Src", Issuer: res.URL,
			ClientID: "cid", ClientSecret: "sec", TokenEndpoint: tok.URL + "/oauth/token",
			Resources: []federation.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzScope},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		svc, err := federation.NewService(federation.Config{
			Registry: reg, Bindings: store, Vault: v,
			Doer: res.Client(), HTTPClient: tok.Client(), BaseURL: "https://re0auth.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return rig{store: store, v: v, svc: svc}
	}

	t.Run("A_the_re_read_fails_and_the_binding_is_destroyed", func(t *testing.T) {
		r := setup(t, false)
		ctx := context.Background()
		_, err := fetch(t, r.svc, user)
		r.store.(*fsStore).fail.Store(false)
		_, getErr := r.store.Get(ctx, user, zzGame, zzSource)
		secretErr := r.v.Use(ctx, federation.BindingIdentity(federation.Binding{
			User: user, Game: zzGame, Source: zzSource,
		}), func([]byte) error { return nil })
		t.Logf("fetch err=%v; binding row after the failed re-read: err=%v; vault secret: err=%v", err, getErr, secretErr)

		if !errors.Is(err, federation.ErrNotBound) {
			t.Fatalf("fetch = %v, want ErrNotBound on this path", err)
		}
		if getErr == nil {
			t.Fatalf("the binding row SURVIVED; this probe does not reproduce the destructive branch")
		}
		if secretErr == nil {
			t.Fatalf("the vault secret survived; the branch under test shreds it")
		}
		t.Errorf("an INJECTED STORE READ FAILURE was treated as 'the version did not move': the binding row is gone "+
			"(Get: %v) and its vault secret was shredded (Use: %v). refresh.go:143 spares the binding only when "+
			"err==nil && the version moved; every other outcome — including 'I could not read' — falls through to "+
			"vault.Revoke+Delete. An unreadable version is not evidence that the version did not move, and the branch it "+
			"falls into is the destructive one.", getErr, secretErr)
	})

	t.Run("B_control_a_successful_re_read_showing_a_rotation_preserves_it", func(t *testing.T) {
		r := setup(t, true)
		ctx := context.Background()
		res, err := fetch(t, r.svc, user)
		_, getErr := r.store.Get(ctx, user, zzGame, zzSource)
		t.Logf("control: fetch result=%+v err=%v; binding row: %v", res, err, getErr)
		if err != nil {
			t.Fatalf("the control expected the rotated binding to be used, got %v", err)
		}
		if getErr != nil {
			t.Fatalf("the control expected the binding to survive, got %v", getErr)
		}
	})
}

// ---------------------------------------------------------------------------
// Positive control for the reviewed report's CRLF guard.
// ---------------------------------------------------------------------------

// TestZ09VerifyACleanTokenDoesReachTheUpstream is the positive control the
// reviewed held_test.go::TestZ09AnUpstreamTokenCannotInjectAHeader lacks: that
// guard reports "upstream requests: []" and passes if the request never leaves, so
// on its own it cannot tell "the client refused the header" from "the data plane
// never sent anything". This probe shows the same fixture does reach the upstream
// with a clean token.
func TestZ09VerifyACleanTokenDoesReachTheUpstream(t *testing.T) {
	var calls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)

	svc := breakerService(t, httpclient.BreakerOptions{}, up)
	if _, err := fetch(t, svc, "usr_vic"); err != nil {
		t.Fatalf("a clean upstream token did not produce a successful read: %v", err)
	}
	if calls.Load() == 0 {
		t.Fatalf("the upstream was never reached even with a clean token: the fixture is not sending requests")
	}
	t.Logf("control: a clean token reached the upstream %d time(s)", calls.Load())
}

// ---------------------------------------------------------------------------
// Evidence for the reviewed report's own note 1 under "对既有编号的复核附注".
// The report DISCLOSED this and chose not to number it; the review agrees it is a
// separate consequence from round 6's token-exfiltration finding, and puts the
// measured shape here so the decision can be made on evidence.
// ---------------------------------------------------------------------------

// S05-6 GUARD (was the finding). `federation.Source.Issuer` used to be accepted
// with no absolute-URL requirement (federation.go checked only non-empty), so
// `//evil.example` produced a SCHEME-RELATIVE authorize URL, and the browser entry
// point at federation_routes.go handed that value to http.Redirect verbatim — a
// browser resolved it to another host. The registry now refuses any issuer (and
// any endpoint override) that is not an absolute http(s) URL. The name is kept for
// the audit coverage matrix.
func TestZ09VerifyASchemeRelativeIssuerWouldRedirectTheBindOffOrigin(t *testing.T) {
	for _, issuer := range []string{"//evil.example", "evil.example", "/oauth", "ftp://evil.example", "https://"} {
		_, err := federation.NewRegistry(federation.Source{
			Game: zzGame, Name: zzSource, DisplayName: "Src",
			Issuer:   issuer,
			ClientID: "cid", ClientSecret: "sec",
			Resources: []federation.Resource{
				{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzScope},
			},
		})
		if err == nil {
			t.Errorf("NewRegistry accepted Issuer %q. A scheme-relative or relative issuer reaches /bind's "+
				"http.Redirect and is resolved by the browser against another host (S05-6 regressed).", issuer)
		} else if !strings.Contains(err.Error(), "issuer") {
			t.Errorf("the refusal of Issuer %q does not name the field, so it is not fixable at startup: %v", issuer, err)
		}
	}

	// Positive control: an absolute https issuer is still accepted and its
	// authorize URL really names that origin, so the loop above is about the shape
	// and not "the registry rejects everything".
	reg, err := federation.NewRegistry(federation.Source{
		Game: zzGame, Name: zzSource, DisplayName: "Src",
		Issuer:   "https://src.example",
		ClientID: "cid", ClientSecret: "sec",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzScope},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry refused an absolute https issuer: %v", err)
	}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: federation.NewMemoryBindingStore(), Vault: newVault(t),
		Doer: http.DefaultClient, BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.BeginBind(context.Background(), "usr_1", zzGame, zzSource, "/app/sources")
	if err != nil {
		t.Fatalf("BeginBind = %v", err)
	}
	u, err := url.Parse(ch.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "src.example" {
		t.Errorf("the authorize URL names host %q, want src.example; from %q", u.Host, ch.AuthorizeURL)
	}
}
