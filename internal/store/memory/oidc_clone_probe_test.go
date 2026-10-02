package memory

// G-16: cloneAuthRequest used to share CodeChallenge and AuthTime with the stored
// record. The copy-on-return exists so a caller's write cannot reach the store's
// state; these probes write through both pointers on the returned handle and then
// re-read, which is exactly the escape the sharing allowed.

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

func TestClonedAuthRequestDoesNotSharePointerFields(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	const challenge = "challenge-1234567890"
	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            "cli",
		RedirectURI:         "https://app.example/cb",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"account.id"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	signedIn := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if err := store.SetAuthTime(ctx, ar.GetID(), signedIn); err != nil {
		t.Fatal(err)
	}

	// Write through the handle CreateAuthRequest returned. AuthTime is still nil
	// on this one: SetAuthTime ran afterwards, and with the fix the handle keeps
	// its own copy rather than seeing the store's later write.
	created := ar.(*oidcstore.AuthRequest)
	if created.CodeChallenge == nil {
		t.Fatalf("fixture: challenge=%v, want it set", created.CodeChallenge)
	}
	created.CodeChallenge.Challenge = "written-through-create"

	// Write through the handle AuthRequestByID returned.
	got, err := store.AuthRequestByID(ctx, ar.GetID())
	if err != nil {
		t.Fatal(err)
	}
	read := got.(*oidcstore.AuthRequest)
	if read.CodeChallenge == nil || read.AuthTime == nil {
		t.Fatalf("fixture: challenge=%v authTime=%v, want both set", read.CodeChallenge, read.AuthTime)
	}
	read.CodeChallenge.Challenge = "written-through-read"
	*read.AuthTime = signedIn.Add(48 * time.Hour)

	again, err := store.AuthRequestByID(ctx, ar.GetID())
	if err != nil {
		t.Fatal(err)
	}
	final := again.(*oidcstore.AuthRequest)
	if final.CodeChallenge == nil || final.CodeChallenge.Challenge != challenge {
		t.Errorf("the stored code challenge = %+v, want %q: a returned handle wrote through to the store (G-16)", final.CodeChallenge, challenge)
	}
	if final.AuthTime == nil || !final.AuthTime.Equal(signedIn) {
		t.Errorf("the stored auth_time = %v, want %s: a returned handle wrote through to the store (G-16)", final.AuthTime, signedIn)
	}
	// The two returned handles must not share with each other either.
	if read.CodeChallenge == created.CodeChallenge || read.AuthTime == created.AuthTime {
		t.Error("two handles from the store share the same pointer fields")
	}
}
