// Guards for the findings of the second adversarial audit (docs/security-audit-2.md).
//
// Each of these failed before its fix and passes now. They live together so the
// audit and its guards stay in one place, and each test names the finding it pins.
package federation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/vault"
)

// frozenStore pins what Get reports and refuses the compare-and-swap, so a test can
// put the winner's commit INSIDE the loser's source call: the loser's own re-read
// still sees the version it started from, which is the only interleaving where the
// ordering of store-secret-then-CAS can be observed. A store that merely fails the
// CAS is not enough — the version re-read at the top of refreshBinding returns
// early.
type frozenStore struct {
	BindingStore
	frozen Binding
}

func (f frozenStore) Get(context.Context, account.UserID, string, string) (Binding, error) {
	return f.frozen, nil
}

func (frozenStore) PutIfVersion(context.Context, Binding, uint64) (bool, error) {
	return false, nil
}

// brokenVault opens nothing, while still holding the records. It stands in for any
// reason a credential cannot be read that is NOT "there is no credential": a KEK
// the deployment rotated away from, or an audit write the sink refused.
type brokenVault struct {
	vault.Service
	err error
}

func (b brokenVault) Use(context.Context, vault.Identity, func([]byte) error) error {
	return b.err
}

func adversaryRegistry(t *testing.T, issuer string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: issuer,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// Finding A6-2: a refresh that LOSES the compare-and-swap has already overwritten
// the winner's secret in the vault.
//
// `refreshBinding` stores the new token pair FIRST and only then attempts the CAS
// (`storeBindingSecret` precedes `PutIfVersion`). On `!won` it returns the winner's
// binding row without restoring the winner's secret, so the vault and the row
// disagree about which upstream token is live — and in the worst interleaving the
// vault keeps a token the source has already rotated away from, which the next
// call reads as a dead grant and answers by deleting a healthy binding.
func TestAdversarialLosingRefreshDoesNotOverwriteTheWinnersSecret(t *testing.T) {
	ctx := context.Background()
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}

	// The binding as the loser read it: expired, and holding a refresh token, or
	// refreshBinding returns before it ever calls the source.
	stale := Binding{
		User: "usr_1", Game: game, Source: sourceName, Version: 1,
		HasRefresh: true, Expiry: time.Now().Add(-time.Hour),
	}
	b.bind(t, "usr_1", sourceName, "stale-token", "rt-1", time.Now().Add(-time.Hour))

	// The upstream commits the winner's rotation WHILE the loser is waiting on it,
	// which is the interleaving the ordering bug needs.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		winner := stale
		winner.Version = 2
		winner.HasRefresh = true
		winner.Expiry = time.Now().Add(time.Hour)
		if err := b.store.Put(ctx, winner); err != nil {
			t.Errorf("winner commit: %v", err)
		}
		if err := b.vault.Enroll(ctx, BindingIdentity(winner), mustSecretPair(t, "winner-token", "rt-w"), nil); err != nil {
			t.Errorf("winner secret: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "loser-token", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-2",
		})
	}))
	defer up.Close()

	// The loser's store still reports version 1 and refuses the CAS, so the loser
	// does its work and then discovers it lost.
	loserSvc := mustService(t, Config{
		Registry: adversaryRegistry(t, up.URL),
		Doer:     http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	}, backend{store: frozenStore{BindingStore: b.store, frozen: stale}, vault: b.vault})

	src := loserSvc.Sources(game)[0]
	if _, err := loserSvc.(*service).refreshBinding(ctx, src, stale, false); err != nil {
		t.Logf("refreshBinding (loser) returned: %v", err)
	}

	got := b.secret(t, "usr_1", sourceName)
	if got.AccessToken != "winner-token" {
		t.Errorf("the vault now holds the LOSER's token %q while the winner's row "+
			"describes %q: the two stores disagree about which upstream token is live",
			got.AccessToken, "winner-token")
	}
}

// Finding A6-1: `Unbind` reports "nothing to revoke" when the vault cannot be
// OPENED, which is a different thing from "there was no secret".
//
// `useBindingSecret` returns an error for every reason other than absence — an
// unconfigured KEK, a refused audit write, a failed decrypt — and unbind collapses
// all of them into `RevocationNothingToDo`, which is not an error. The kill switch
// then counts the binding as revoked while no revocation request was ever sent, so
// an incident responder reads "every source was told" when none was.
func TestAdversarialUnbindReportsAnUnopenableSecret(t *testing.T) {
	ctx := context.Background()

	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	b.bind(t, "usr_1", sourceName, "tok", "rt-1", time.Now().Add(time.Hour))

	svc := mustService(t, Config{
		Registry: adversaryRegistry(t, "https://unused.example"),
		Doer:     http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
	}, backend{
		store: b.store,
		vault: brokenVault{
			Service: b.vault,
			err:     errors.New(`vault: record was wrapped by key "kek-0", which is not configured`),
		},
	})

	result, err := svc.Unbind(ctx, "usr_1", game, sourceName)
	if err != nil {
		t.Fatalf("Unbind returned an error (acceptable, but it currently does not): %v", err)
	}
	if result.Upstream == RevocationNothingToDo {
		t.Errorf("an unopenable credential was reported as %q: the caller — and the "+
			"kill switch's counters — is told nothing needed doing, while the upstream "+
			"token was never asked to be revoked", result.Upstream)
	}
}
