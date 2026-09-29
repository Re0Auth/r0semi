//go:build audit || audit6

package federation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
)

// zz_audit_race_test.go —audit probe, run under -race.
//
// The federation layer's shared state is the per-binding lock, the vault's
// plaintext window, the joint buffer budget and the breaker/host map. This probe
// drives every one of them at once from many goroutines and lets the detector say
// whether any of it is actually synchronized:
//
//	Fetch / Raw          —read a body through the budget
//	Unbind / CascadeRevoke —shred the secret and delete the row
//	BeginBind/CompleteBind —replace the binding and its secret
//	RevokeAllBindings    —the paged sweep, 2 bindings/page
func TestZZAuditRaceProbeAllPathsAtOnce(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"rt"}`)
		case "/oauth/revoke", "/oauth/cascade_revocation":
			w.WriteHeader(http.StatusOK)
		case "/resources/profile":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			// The raw base lives under the same host.
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "raw-body")
		}
	}))
	defer up.Close()

	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL,
		RawBase: up.URL + "/native", ClientID: "cid", ClientSecret: "sec",
		TokenClass:                tokenClassRevocable,
		CascadeRevocationEndpoint: up.URL + "/oauth/cascade_revocation",
		Resources:                 []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	svc := mustService(t, Config{
		Registry: reg, Doer: up.Client(), HTTPClient: up.Client(),
		BaseURL: "https://re0auth.test", KillSwitchPageSize: 2,
		TotalTimeout: 10 * time.Second,
	}, b)

	ctx := context.Background()
	for i := 0; i < 8; i++ {
		b.bind(t, userFor(i), sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))
	}

	var wg sync.WaitGroup
	work := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}
	for i := 0; i < 8; i++ {
		u := userFor(i)
		work(func() {
			for n := 0; n < 20; n++ {
				_, _ = svc.Fetch(ctx, FetchRequest{User: u, Game: game, Resource: "profile"})
			}
		})
		work(func() {
			for n := 0; n < 20; n++ {
				_, _ = svc.Raw(ctx, RawRequest{User: u, Game: game, Source: sourceName, Path: "native/scores"})
			}
		})
		work(func() {
			time.Sleep(time.Millisecond)
			_, _ = svc.Unbind(ctx, u, game, sourceName)
			_, _ = svc.CascadeRevoke(ctx, u, game, sourceName)
		})
		work(func() {
			ch, err := svc.BeginBind(ctx, u, game, sourceName, "/app")
			if err != nil {
				return
			}
			_, _, _ = svc.CompleteBind(ctx, u, ch.ID, "code")
		})
	}
	work(func() { _, _ = svc.RevokeAllBindings(ctx) })
	work(func() { _, _ = svc.MissingBindings(ctx, "usr_race_00", []string{profileScope}) })
	work(func() { _ = svc.AllSources() })
	wg.Wait()
}

func userFor(i int) account.UserID { return account.UserID(fmt.Sprintf("usr_race_%02d", i)) }
