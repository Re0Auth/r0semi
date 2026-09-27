//go:build audit5

package zzprobe_verifyfederation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/vault"
)

// ---------------------------------------------------------------------------
// FO-02, part 1: the reported probe does not measure what it claims.
// ---------------------------------------------------------------------------

// preDeleteStore deletes the row BEFORE the underlying CAS runs -- the
// interleaving the audit's frozenStore builds. The CAS therefore loses, which
// takes the "do not touch the vault" branch.
type preDeleteStore struct {
	federation.BindingStore
	once  sync.Once
	store *federation.MemoryBindingStore
	won   bool
}

func (s *preDeleteStore) PutIfVersion(ctx context.Context, b federation.Binding, v uint64) (bool, error) {
	s.once.Do(func() { _ = s.store.Delete(ctx, b.User, b.Game, b.Source) })
	w, err := s.BindingStore.PutIfVersion(ctx, b, v)
	s.won = w
	return w, err
}

func TestVerifyReportedFO02ProbeIsNonDiscriminating(t *testing.T) {
	ctx := context.Background()
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: "https://source.example", TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	b := federation.Binding{
		User: "usr_1", Game: "phigros", Source: "src",
		HasRefresh: true, Expiry: time.Now().Add(-time.Minute), Version: 7,
	}
	if err := store.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(ctx, federation.BindingIdentity(b), mustPair(t, "old-access", "old-refresh"), nil); err != nil {
		t.Fatal(err)
	}

	probe := &preDeleteStore{BindingStore: store, store: store}
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: probe, Vault: v, Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.Fetch(ctx, federation.FetchRequest{User: "usr_1", Game: "phigros", Resource: "profile"})

	_, gerr := store.Get(ctx, "usr_1", "phigros", "src")
	exists, _ := v.Exists(ctx, federation.BindingIdentity(b))
	secret, _ := secretOf(t, ctx, v, federation.BindingIdentity(b))
	t.Logf("CAS won=%v (false means the refresh never reached its vault write)", probe.won)
	t.Logf("row present=%v vault secret present=%v content=%v", gerr == nil, exists, secret)

	if probe.won {
		t.Fatalf("fixture: the CAS should have lost in this interleaving")
	}
	if secret["access_token"] != "old-access" {
		t.Errorf("the vault changed under a lost CAS: %v", secret)
	}

	// The audit's assertion is "no row AND a vault secret exists". Build that
	// state with NO refresh at all: enroll, delete the row behind the service's
	// back, and the predicate is already true. That is what makes the reported
	// FAIL non-discriminating -- a correct implementation fails it too.
	store2 := federation.NewMemoryBindingStore()
	v2 := newTestVault(t)
	if err := store2.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := v2.Enroll(ctx, federation.BindingIdentity(b), mustPair(t, "old-access", "old-refresh"), nil); err != nil {
		t.Fatal(err)
	}
	if err := store2.Delete(ctx, "usr_1", "phigros", "src"); err != nil {
		t.Fatal(err)
	}
	_, gerr2 := store2.Get(ctx, "usr_1", "phigros", "src")
	exists2, _ := v2.Exists(ctx, federation.BindingIdentity(b))
	if gerr2 != nil && exists2 {
		t.Logf("the audit's predicate `gerr != nil && exists` is TRUE with no service call at all: " +
			"its FAIL is produced by the fixture, not by the refresh")
	} else {
		t.Errorf("expected the vacuity demonstration to hold: gerr=%v exists=%v", gerr2, exists2)
	}
}

// ---------------------------------------------------------------------------
// FO-02, part 2: the residue is real, but only in the cross-process window.
// ---------------------------------------------------------------------------

// postDeleteStore runs its hook AFTER the CAS has been won, which is the window
// the ordering trade actually leaves open.
type postDeleteStore struct {
	federation.BindingStore
	hook func()
	done bool
	won  bool
}

func (s *postDeleteStore) PutIfVersion(ctx context.Context, b federation.Binding, v uint64) (bool, error) {
	w, err := s.BindingStore.PutIfVersion(ctx, b, v)
	s.won = w
	if w && !s.done {
		s.done = true
		s.hook()
	}
	return w, err
}

func TestVerifyOrphanSecretIsReachableOnlyByErasure(t *testing.T) {
	ctx := context.Background()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "rotated-access", "refresh_token": "rotated-refresh",
				"token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"served_by":"src"}`)
	}))
	defer srv.Close()

	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: srv.URL, TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := federation.NewMemoryBindingStore()
	repo := vault.NewMemoryRepo()
	v := newTestVaultFromRepo(t, repo)
	b := federation.Binding{
		User: "usr_1", Game: "phigros", Source: "src",
		HasRefresh: true, Expiry: time.Now().Add(-time.Minute), Version: 7,
	}
	if err := store.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(ctx, federation.BindingIdentity(b), mustPair(t, "old-access", "old-refresh"), nil); err != nil {
		t.Fatal(err)
	}

	// A cross-process Unbind: shred the secret, then delete the row (unbind.go:91
	// then :94). It lands inside the refresh's CAS->vault-write window.
	probe := &postDeleteStore{BindingStore: store}
	probe.hook = func() {
		if err := v.Revoke(ctx, federation.BindingIdentity(b)); err != nil {
			t.Errorf("hook revoke: %v", err)
		}
		if err := store.Delete(ctx, "usr_1", "phigros", "src"); err != nil {
			t.Errorf("hook delete: %v", err)
		}
	}

	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: probe, Vault: v, Doer: srv.Client(), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, ferr := svc.Fetch(ctx, federation.FetchRequest{User: "usr_1", Game: "phigros", Resource: "profile"})
	_, gerr := store.Get(ctx, "usr_1", "phigros", "src")
	secret, exists := secretOf(t, ctx, v, federation.BindingIdentity(b))
	t.Logf("CAS won=%v fetch err=%v row present=%v vault present=%v content=%v",
		probe.won, ferr, gerr == nil, exists, secret)

	if !probe.won {
		t.Fatal("fixture: the CAS should have been won")
	}
	if gerr == nil {
		t.Fatal("fixture: the row should be gone")
	}
	if exists {
		t.Logf("REPRODUCED: the refresh wrote a secret after its row was deleted, and the secret is the "+
			"ROTATED one (%v) -- the audit's mechanism holds in this window, which its own probe does not reach",
			secret["access_token"])
	}

	// (a) Unbind cannot reach it: it looks the row up and stops.
	if res, err := svc.Unbind(ctx, "usr_1", "phigros", "src"); err != nil {
		t.Errorf("unbind: %v", err)
	} else {
		t.Logf("Unbind on the orphan: %+v", res)
	}
	if still, _ := v.Exists(ctx, federation.BindingIdentity(b)); still {
		t.Logf("after Unbind the orphan secret is STILL in the vault: no endpoint reaches it")
	} else {
		t.Errorf("Unbind reached the orphan; the audit's reachability analysis is wrong in the safe direction")
	}

	// (b) The Kill Switch sweep enumerates the store, so it cannot see it.
	summary, err := svc.RevokeAllBindings(ctx)
	if err != nil {
		t.Errorf("kill switch: %v", err)
	}
	t.Logf("Kill Switch summary on an orphan-only deployment: %+v", summary)
	if summary.Total != 0 {
		t.Errorf("the sweep reported %d bindings; the orphan should be invisible to it", summary.Total)
	}

	// (c) Account erasure goes by subject, so it does reach it.
	n, err := repo.DeleteSubject(ctx, "usr_1")
	if err != nil {
		t.Fatalf("DeleteSubject: %v", err)
	}
	gone, _ := v.Exists(ctx, federation.BindingIdentity(b))
	t.Logf("vault.DeleteSubject removed %d record(s); orphan still present: %v", n, gone)
	if gone {
		t.Errorf("erasure did not reach the orphan")
	}
	_ = asked
}

// ---------------------------------------------------------------------------
// FO-02, part 3: the comment at refresh.go:121-127 describes a different case,
// and its claim is true for that one.
// ---------------------------------------------------------------------------

type failOnceVault struct {
	vault.Service
	mu     sync.Mutex
	failed bool
}

func (f *failOnceVault) Enroll(ctx context.Context, id vault.Identity, secret []byte, meta map[string]string) error {
	f.mu.Lock()
	first := !f.failed
	f.failed = true
	f.mu.Unlock()
	if first {
		return errors.New("verify: simulated vault write failure")
	}
	return f.Service.Enroll(ctx, id, secret, meta)
}

func TestVerifyCommentCaseSelfHeals(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	refreshes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			refreshes++
			n := refreshes
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if n == 1 {
				// The first refresh succeeds, so the CAS is won and the vault
				// write is the only thing that fails.
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "rotated-access", "refresh_token": "rotated-refresh",
					"token_type": "Bearer", "expires_in": 3600,
				})
				return
			}
			// Afterwards the rotated one-time refresh token is gone.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"expired"}`)
	}))
	defer srv.Close()

	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", Issuer: srv.URL, TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := federation.NewMemoryBindingStore()
	base := newTestVault(t)
	v := &failOnceVault{Service: base}
	b := federation.Binding{
		User: "usr_1", Game: "phigros", Source: "src",
		HasRefresh: true, Expiry: time.Now().Add(-time.Minute), Version: 11,
	}
	if err := store.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := base.Enroll(ctx, federation.BindingIdentity(b), mustPair(t, "old-access", "old-refresh"), nil); err != nil {
		t.Fatal(err)
	}

	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: store, Vault: v, Doer: srv.Client(), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// First call: the refresh succeeds upstream, the CAS is won, the vault write
	// fails. refresh.go:122-127 is about exactly this.
	_, err1 := svc.Fetch(ctx, federation.FetchRequest{User: "usr_1", Game: "phigros", Resource: "profile"})
	row, rerr := store.Get(ctx, "usr_1", "phigros", "src")
	rowSurvived := rerr == nil
	t.Logf("after the failed vault write: err=%v row present=%v version=%d", err1, rowSurvived, row.Version)

	// Second call: it presents the stale token, is rejected, and the rejection
	// path cleans up -- unless the row is gone, which is NOT this case.
	_, err2 := svc.Fetch(ctx, federation.FetchRequest{User: "usr_1", Game: "phigros", Resource: "profile"})
	_, rerr2 := store.Get(ctx, "usr_1", "phigros", "src")
	exists, _ := base.Exists(ctx, federation.BindingIdentity(b))
	t.Logf("after the next call: err=%v row present=%v vault present=%v refreshes=%d", err2, rerr2 == nil, exists, refreshes)

	if !rowSurvived {
		t.Errorf("fixture: the row should have survived the failed vault write")
	}
	if rerr2 == nil || exists {
		t.Errorf("the rejection path did NOT clean up (row present=%v vault present=%v), "+
			"so refresh.go:122-127's claim would be false", rerr2 == nil, exists)
	} else {
		t.Logf("the comment's claim holds for its own case: the row is present, so the next call does " +
			"reach refreshRejected, which shreds the secret and deletes the row")
	}
}

// newTestVaultFromRepo lives in helpers_test.go.
