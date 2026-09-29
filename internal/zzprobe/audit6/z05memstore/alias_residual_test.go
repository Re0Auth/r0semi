//go:build audit6

// Finding 05-4: the f6af208 copy-on-return fix is incomplete. cloneAuthRequest
// (internal/store/memory/oidc.go) copies the struct and the Scopes slice but
// still shares two POINTER fields between the returned clone and the stored
// record: CodeChallenge (*oidc.CodeChallenge) and AuthTime (*time.Time).
//
// A caller that writes *through* those pointers changes the store's record
// without ever taking the store's lock. Round 5 proved this class of mechanism
// for the fields it probed (Subject/Scopes on CreateAuthRequest's return,
// AMR/Audience/AuthTime on TokenRequestByRefreshToken's) and f6af208 fixed
// exactly those; these two fields were not part of that fix.
//
// Reachability today: nothing in production writes through them — the
// library consumes op.AuthRequest through a getter-only interface and
// internal/oidchttp only reads the values it gets. The probe pins the
// mechanism so the shape is on record; the impact is latent, not live.
package z05memstore

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

func newPendingRequest(t *testing.T, e *env) *oidcstore.AuthRequest {
	t.Helper()
	created, err := e.store.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID: probeClientID, RedirectURI: probeRedirect,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
		CodeChallenge: "challenge-1234567890123456789012345678901234567890",
		State:         "st", Nonce: "nn",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	return created.(*oidcstore.AuthRequest)
}

// The mechanism, through the read path a consent screen actually uses
// (AuthRequestByID → DescribeAuthorization/ApproveAuthorization all read the
// clone it returns): a write through the shared *time.Time lands in the stored
// record. Red until the clone is deep.
func TestAuthRequestCloneSharesItsAuthTimePointerWithTheStore(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	created := newPendingRequest(t, e)
	id := created.GetID()

	signedIn := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := e.store.SetAuthTime(ctx, id, signedIn); err != nil {
		t.Fatal(err)
	}

	clone, err := e.store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// Control: a FIELD write on the clone must not reach the store (the
	// struct itself is copied). If this fails, the probe below measures
	// nothing.
	clone.(*oidcstore.AuthRequest).Subject = "usr_field_write"
	after, err := e.store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.GetSubject() == "usr_field_write" {
		t.Fatal("control failed: the clone IS the stored record")
	}

	// The finding: a write THROUGH the shared pointer reaches the store.
	if pointed := clone.(*oidcstore.AuthRequest).AuthTime; pointed != nil {
		*pointed = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	} else {
		t.Fatal("the clone carries no AuthTime pointer; the probe measured nothing")
	}
	after, err = e.store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.GetAuthTime(); got.Year() == 2035 {
		t.Errorf("a write through the AuthRequestByID clone's AuthTime pointer changed the stored "+
			"record's auth_time to %v: the clone aliases store state", got)
	}
}

// The same mechanism through the CodeChallenge pointer — the field the code
// exchange's PKCE check is judged on (pkg/op/token_code.go AuthorizeCodeChallenge
// reads request.GetCodeChallenge() from this very clone).
func TestAuthRequestCloneSharesItsCodeChallengePointerWithTheStore(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	created := newPendingRequest(t, e)
	id := created.GetID()

	clone, err := e.store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	challenge := clone.GetCodeChallenge()
	if challenge == nil {
		t.Fatal("the clone carries no CodeChallenge pointer; the probe measured nothing")
	}
	// A write through the pointer the clone handed out:
	challenge.Challenge = "rewritten-by-the-caller"
	challenge.Method = oidc.CodeChallengeMethodPlain

	after, err := e.store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.GetCodeChallenge(); got != nil && got.Challenge == "rewritten-by-the-caller" {
		t.Errorf("a write through the AuthRequestByID clone's CodeChallenge pointer changed the stored "+
			"record's PKCE challenge to %q (method %v): the clone aliases store state",
			got.Challenge, got.Method)
	}
}

// Regression controls for the parts f6af208 DID fix: these must stay green.
// If one fails, the round-5 fix regressed.
func TestF6af208AliasFixesHold(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()

	// 1. CreateAuthRequest no longer hands out the stored record itself.
	created := newPendingRequest(t, e)
	live := created
	live.Subject = "usr_attacker"
	live.Scopes[0] = "phigros.score.read"
	back, err := e.store.AuthRequestByID(ctx, live.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if back.GetSubject() == "usr_attacker" {
		t.Errorf("regression: a write to CreateAuthRequest's return value changed the stored subject")
	}
	if got := back.GetScopes(); len(got) > 0 && got[0] == "phigros.score.read" {
		t.Errorf("regression: a write to CreateAuthRequest's return value changed the stored scopes: %v", got)
	}

	// 2. TokenRequestByRefreshToken copies every slice and the AuthTime value.
	authTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	req := &oidcstore.RefreshRequest{
		IDHash: "idh", ClientID: probeClientID, Subject: "usr_1",
		Scopes: []string{"account.id"}, AMR: []string{"pwd"},
		Audience: []string{probeClientID}, AuthTime: &authTime,
	}
	_, refresh, _, err := e.store.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.store.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}
	first.(*oidcstore.RefreshRequest).SetCurrentScopes([]string{"phigros.score.read"})
	if amr := first.GetAMR(); len(amr) > 0 {
		amr[0] = "amr_rewritten"
	}
	if aud := first.GetAudience(); len(aud) > 0 {
		aud[0] = "aud_rewritten"
	}
	if pointed := first.(*oidcstore.RefreshRequest).AuthTime; pointed != nil {
		*pointed = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	again, err := e.store.TokenRequestByRefreshToken(ctx, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.GetScopes(); len(got) > 0 && got[0] == "phigros.score.read" {
		t.Errorf("regression: the returned scopes alias the stored ones")
	}
	if got := again.GetAMR(); len(got) > 0 && got[0] == "amr_rewritten" {
		t.Errorf("regression: the returned AMR aliases the stored record")
	}
	if got := again.GetAudience(); len(got) > 0 && got[0] == "aud_rewritten" {
		t.Errorf("regression: the returned Audience aliases the stored record")
	}
	if got := again.GetAuthTime(); got.Year() == 2030 {
		t.Errorf("regression: the returned auth_time aliases the stored record")
	}
}
