package federation

// The deployment-wide sweep is paged and its upstream calls run in a bounded pool.
// Neither changes what the sweep does — every binding is still cut and counted —
// so what these tests pin is the load shape: pages that neither skip nor repeat,
// and fan-out that stays bounded.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// pagedSweepService builds a service whose sweep page is small, so the paging loop
// is exercised without needing hundreds of bindings.
func pagedSweepService(t *testing.T, pageSize int, srcs ...Source) (Service, *MemoryBindingStore, vault.Service) {
	t.Helper()
	reg, err := NewRegistry(srcs...)
	if err != nil {
		t.Fatal(err)
	}
	bindings := NewMemoryBindingStore()
	v := newVault(t)
	svc, err := NewService(Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: &countingDoer{}, HTTPClient: http.DefaultClient,
		BaseURL:            "https://re0auth.test",
		KillSwitchPageSize: pageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, bindings, v
}

// countingDoer answers every upstream revocation with 200 and records how many
// requests were in flight at once, which is what "bounded fan-out" means.
type countingDoer struct {
	mu       sync.Mutex
	inFlight int
	peak     int
	calls    int
}

func (d *countingDoer) Do(*http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.inFlight++
	d.calls++
	if d.inFlight > d.peak {
		d.peak = d.inFlight
	}
	d.mu.Unlock()

	// Long enough that overlapping calls are visible rather than theoretical.
	time.Sleep(2 * time.Millisecond)

	d.mu.Lock()
	d.inFlight--
	d.mu.Unlock()

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
		Request:    &http.Request{},
	}, nil
}

func (d *countingDoer) stats() (calls, peak int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, d.peak
}

// seedBinding writes a binding row and its vault secret directly. The sweep only
// needs the two, and going through the bind flow would mean standing up a token
// endpoint to exchange a code, which is not what these tests are about.
func seedBinding(t *testing.T, bindings *MemoryBindingStore, v vault.Service, user string, index int) Binding {
	t.Helper()
	b := Binding{User: account.UserID(user), Game: game, Source: sourceName, Version: 1}
	if err := v.Enroll(context.Background(), BindingIdentity(b),
		[]byte(`{"access_token":"up-token-`+strconv.Itoa(index)+`"}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := bindings.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	return b
}

// The sweep walks pages until the store has no more, and every binding is cut
// exactly once.
func TestRevokeAllBindingsSweepsEveryPage(t *testing.T) {
	svc, bindings, v := pagedSweepService(t, 5, unbindSource("https://source.test", "revocable"))
	ctx := context.Background()
	const total = 12
	for i := 0; i < total; i++ {
		seedBinding(t, bindings, v, fmt.Sprintf("usr_%02d", i), i)
	}

	summary, err := svc.RevokeAllBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != total || summary.Revoked != total {
		t.Fatalf("summary = %+v, want %d total and %d revoked across pages", summary, total, total)
	}
	if left, _ := bindings.ListAll(ctx); len(left) != 0 {
		t.Fatalf("%d bindings survived the sweep", len(left))
	}
}

// A sweep over a large deployment must not ask every source at once. The pool is
// bounded (killSwitchWorkers), and it is wider than one — otherwise the sweep is
// back to being serial.
func TestRevokeAllBindingsBoundsUpstreamFanOut(t *testing.T) {
	svc, bindings, v := pagedSweepService(t, 100, unbindSource("https://source.test", "revocable"))
	ctx := context.Background()
	const total = killSwitchWorkers * 3
	for i := 0; i < total; i++ {
		seedBinding(t, bindings, v, fmt.Sprintf("usr_%02d", i), i)
	}

	summary, err := svc.RevokeAllBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != total || summary.Revoked != total {
		t.Fatalf("summary = %+v, want %d revoked", summary, total)
	}

	doer := svc.(*service).doer.(*countingDoer)
	calls, peak := doer.stats()
	if calls != total {
		t.Fatalf("upstream revocation calls = %d, want one per binding (%d)", calls, total)
	}
	if peak <= 1 {
		t.Fatal("the sweep was serial: nothing overlapped")
	}
	if peak > killSwitchWorkers {
		t.Fatalf("upstream fan-out peaked at %d, above the %d bound", peak, killSwitchWorkers)
	}
}

// Pages must cover the deployment exactly once: a cursor bug that skipped or
// repeated a binding would leave a live upstream token behind, or cut one twice.
func TestMemoryBindingStorePagesCoverEverythingOnce(t *testing.T) {
	store := NewMemoryBindingStore()
	ctx := context.Background()
	const total = 10
	for i := 0; i < total; i++ {
		// Users and sources vary independently, so the cursor has to compare all
		// three fields rather than happening to distinguish rows on the first.
		b := Binding{
			User:    account.UserID(fmt.Sprintf("usr_%02d", i%4)),
			Game:    game,
			Source:  fmt.Sprintf("src_%d", i%3),
			Version: 1,
		}
		if err := store.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	all, err := store.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != total {
		t.Fatalf("fixture has %d bindings, want %d", len(all), total)
	}

	var (
		seen  []Binding
		after Binding
		first = true
		pages int
	)
	for {
		var cursorUser, cursorGame, cursorSource string
		if !first {
			cursorUser, cursorGame, cursorSource = string(after.User), after.Game, after.Source
		}
		page, err := store.ListAllPage(ctx, cursorUser, cursorGame, cursorSource, 3)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(page) == 0 {
			break
		}
		if len(page) > 3 {
			t.Fatalf("page of %d, want at most 3", len(page))
		}
		seen = append(seen, page...)
		after = page[len(page)-1]
		first = false
		if pages > total+2 {
			t.Fatal("paging did not terminate")
		}
	}

	if len(seen) != len(all) {
		t.Fatalf("pages yielded %d bindings, want %d", len(seen), len(all))
	}
	for i := range seen {
		if seen[i] != all[i] {
			t.Fatalf("page order differs from ListAll at %d: %+v vs %+v", i, seen[i], all[i])
		}
	}
}
