package memory

// introspection_fault_probe_test.go is the store half of S02-8=A, requested by
// w1-oidchttp.
//
// The introspection handler must answer Active:false for a token this issuer never
// handed out (or one that expired) and 500 for a store fault. That decision is only
// possible if the store classifies: SetIntrospectionFromToken used to return an
// untyped errors.New("memory: token not found") for both, so a revoked/expired
// token was indistinguishable from a fault and the handler could not tell them
// apart.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/oauth"
)

func TestIntrospectionClassifiesUnknownAndExpiredAsTokenNotFound(t *testing.T) {
	clock := newTestClock()
	store := clockedStore(t, clock)
	ctx := context.Background()

	// Unknown: never issued.
	if err := store.SetIntrospectionFromToken(ctx, new(oidc.IntrospectionResponse), "never-issued", "usr_1", ""); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("an unknown token introspected as %v, want oauth.ErrTokenNotFound; the handler cannot "+
			"distinguish it from a store fault (S02-8)", err)
	}

	// Expired: issued, past its deadline.
	accessID, _, err := store.CreateAccessToken(ctx, tokenRequest())
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Hour)
	if err := store.SetIntrospectionFromToken(ctx, new(oidc.IntrospectionResponse), accessID, "usr_1", ""); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("an expired token introspected as %v, want oauth.ErrTokenNotFound", err)
	}
}
