//go:build audit5

package concurrency

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// --- Finding CM-3: copy-on-return aliasing in the in-memory OP store ---
//
// The store is explicit about copying on the read path (AuthRequestByID returns
// cloneAuthRequest, DeviceByUserCode returns deviceRecord.state(), SetIntrospection
// FromToken copies the scope slice) and equally explicit about copying what it
// stores (CreateAuthRequest copies req.Scopes). Three places break that rule, and
// each hands a caller a reference into the store's own record — so a caller can
// change store state without ever taking the lock.
//
// Each test below asserts the SAFE property first on a path known to copy (the
// control), so a pass on the unsafe path cannot be "the probe never ran".

// CreateAuthRequest returns the store's own *oidcstore.AuthRequest. It is the
// object the store keeps in authRequests; nothing copies it, while AuthRequestByID
// returns a clone of the same object.
func TestCreateAuthRequestDoesNotHandItsRecordToTheCaller(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()

	created, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
	}, "usr_owner")
	if err != nil {
		t.Fatal(err)
	}
	live, ok := created.(*oidcstore.AuthRequest)
	if !ok {
		t.Fatalf("CreateAuthRequest returned %T, want *oidcstore.AuthRequest", created)
	}
	id := live.GetID()

	// Control: the read path hands out a clone, so mutating what it returned does
	// not reach the store. This is what makes the two assertions below meaningful.
	clone, err := st.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	clone.(*oidcstore.AuthRequest).Subject = "usr_clone_mutation"
	afterClone, err := st.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if afterClone.GetSubject() != "usr_owner" {
		t.Fatalf("control failed: AuthRequestByID handed out the stored record (%q)", afterClone.GetSubject())
	}

	// Finding: the create path does.
	live.Subject = "usr_attacker"
	live.Scopes[0] = "phigros.score.read"
	back, err := st.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if back.GetSubject() == "usr_attacker" {
		t.Errorf("a caller's write to the value CreateAuthRequest returned changed the store's record: subject=%q",
			back.GetSubject())
	}
	if got := back.GetScopes(); len(got) > 0 && got[0] == "phigros.score.read" {
		t.Errorf("a caller's write to the returned record's scope slice changed the stored scopes: %v", got)
	}
}

// TokenRequestByRefreshToken copies Scopes but hands out the stored AMR and
// Audience slices, and the stored *time.Time for auth_time. auth_time is the
// claim that says how recently the human authenticated; a caller holding the
// returned request can rewrite it in the store.
func TestTokenRequestByRefreshTokenDoesNotHandOutItsSlices(t *testing.T) {
	st := newProbeStore(t, nil)
	ctx := context.Background()

	authTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	req := &oidcstore.RefreshRequest{
		IDHash: "idh", ClientID: probeClientID, Subject: "usr_1",
		Scopes: []string{"account.id"}, AMR: []string{"pwd"},
		Audience: []string{probeClientID}, AuthTime: &authTime,
	}
	_, refresh, _, err := st.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}

	first, err := st.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}

	// Control: Scopes IS copied, so writing to it does not reach the store.
	first.SetCurrentScopes([]string{"phigros.score.read"})
	second, err := st.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.GetScopes(); len(got) > 0 && got[0] == "phigros.score.read" {
		t.Fatalf("control failed: the returned scopes aliased the stored ones (%v)", got)
	}

	second.SetCurrentScopes([]string{"account.id"}) // restore for clarity

	// Finding: AMR and Audience are not copied.
	if amr := first.GetAMR(); len(amr) > 0 {
		amr[0] = "amr_rewritten"
		again, err := st.TokenRequestByRefreshToken(ctx, refresh)
		if err != nil {
			t.Fatal(err)
		}
		if got := again.GetAMR(); len(got) > 0 && got[0] == "amr_rewritten" {
			t.Errorf("the returned AMR slice aliases the stored record: %v", got)
		}
	} else {
		t.Fatal("the probe never saw an AMR slice; nothing was measured")
	}
	if aud := first.GetAudience(); len(aud) > 0 {
		aud[0] = "aud_rewritten"
		again, err := st.TokenRequestByRefreshToken(ctx, refresh)
		if err != nil {
			t.Fatal(err)
		}
		if got := again.GetAudience(); len(got) > 0 && got[0] == "aud_rewritten" {
			t.Errorf("the returned Audience slice aliases the stored record: %v", got)
		}
	} else {
		t.Fatal("the probe never saw an Audience slice; nothing was measured")
	}
	// auth_time is shared by pointer.
	if pointed := first.(*oidcstore.RefreshRequest); pointed != nil {
		*pointed.AuthTime = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		again, err := st.TokenRequestByRefreshToken(ctx, refresh)
		if err != nil {
			t.Fatal(err)
		}
		if got := again.GetAuthTime(); got.Year() == 2030 {
			t.Errorf("the returned auth_time aliases the stored record: %v", got)
		}
	}
}
