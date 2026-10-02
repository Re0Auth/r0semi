package memory

// Z15-3: DeleteAuthRequest used to find a request's codes by walking every code
// in the store under the global lock (Postgres reaches the same rows through the
// `oidc_codes(request_id)` index). The fix adds codeByRequest, so these probes
// assert the index is what serves the delete — a delete that forgets the index
// leaves a stale entry that checkIndexes catches.

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/oauth"
)

func newPendingRequest(t *testing.T, store *OIDCStore) string {
	t.Helper()
	ar, err := store.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     "cli",
		RedirectURI:  "https://app.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray{"account.id"},
	}, "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	return ar.GetID()
}

// TestCodeIndexServesDeleteAuthRequest is the focused probe: deleting one request
// removes exactly its own codes, leaves another request's code alone, and clears
// the request's index entry with them.
func TestCodeIndexServesDeleteAuthRequest(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	mine := newPendingRequest(t, store)
	other := newPendingRequest(t, store)
	for _, code := range []string{"code-a", "code-a2"} {
		if err := store.SaveAuthCode(ctx, mine, code); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveAuthCode(ctx, other, "code-b"); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	if err := store.DeleteAuthRequest(ctx, mine); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	_, mineAlive := store.codes[oauth.TokenHash("code-a")]
	_, otherAlive := store.codes[oauth.TokenHash("code-b")]
	_, stillIndexed := store.codeByRequest[mine]
	remaining := len(store.codes)
	store.mu.Unlock()

	if mineAlive {
		t.Error("a code of the deleted request survived DeleteAuthRequest")
	}
	if !otherAlive {
		t.Error("DeleteAuthRequest removed another request's code")
	}
	if stillIndexed {
		t.Error("the deleted request still owns a code index entry")
	}
	if remaining != 1 {
		t.Errorf("codes left = %d, want 1 (the other request's)", remaining)
	}
	checkIndexes(t, store)
}

// TestCodeIndexServesTheSweepAndThePurges drives the other paths that remove
// codes and re-asserts the index after each: expiry, an account purge and a
// grant revocation.
func TestCodeIndexServesTheSweepAndThePurges(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	// Expiry: a code past its deadline is removed by the sweep, and its index
	// entry goes with it.
	swept := newPendingRequest(t, store)
	if err := store.SaveAuthCode(ctx, swept, "code-swept"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(31 * time.Minute)
	store.SweepExpired()
	checkIndexes(t, store)

	// Purge: an account erasure drops the request and its code.
	purged := newPendingRequest(t, store)
	if err := store.SaveAuthCode(ctx, purged, "code-purged"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PurgeSubject(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	// Revocation: RevokeGrant clears the pending request, its code and the index.
	revoked := newPendingRequest(t, store)
	if err := store.SaveAuthCode(ctx, revoked, "code-revoked"); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeGrant(ctx, "usr_1", "cli"); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	store.mu.Lock()
	left := len(store.codes) + len(store.codeByRequest)
	store.mu.Unlock()
	if left != 0 {
		t.Errorf("codes and code-index entries left = %d, want 0", left)
	}
}
