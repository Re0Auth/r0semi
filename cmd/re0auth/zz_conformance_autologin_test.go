//go:build conformance

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

func conformanceTestStore(t *testing.T) *memory.OIDCStore {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  oauth.NewMemoryClientRegistry(),
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("conformance-kid", key),
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func conformanceTestRequest(t *testing.T, store *memory.OIDCStore) string {
	t.Helper()
	zero := uint(0) // prompt=login normalizes to max_age=0
	ar, err := store.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "conformance",
		RedirectURI:         "http://localhost:9443/test/a/conformance/callback",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{"openid", "account.id"},
		CodeChallenge:       "challenge-1234567890",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		Prompt:              []string{oidc.PromptLogin},
		MaxAge:              &zero,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	return ar.GetID()
}

// The tagged, opted-in build completes a freshness-bound request with no user: the
// callback URL is returned, the request is done, and auth_time is a real time
// stamped moments ago — which is what lets CompleteLogin accept it even though
// prompt=login is present (S02-1's boundary is not skipped, it is satisfied).
func TestConformanceAutoLoginCompletesAFreshnessBoundRequest(t *testing.T) {
	t.Setenv(conformanceAutoLoginEnv, "1")
	ctx := context.Background()
	store := conformanceTestStore(t)
	id := conformanceTestRequest(t, store)

	before := time.Now()
	target, handled, err := conformanceAutoLogin(ctx, store, id)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("the opted-in conformance build did not handle the request")
	}
	if want := "/oauth/authorize/callback?id=" + url.QueryEscape(id); target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
	done, err := store.AuthRequestByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !done.Done() {
		t.Fatal("the request was not completed")
	}
	if got := done.GetSubject(); got != conformanceSubject {
		t.Fatalf("subject = %q, want %q", got, conformanceSubject)
	}
	at := done.GetAuthTime()
	if at.IsZero() || at.Before(before.Add(-time.Minute)) || at.After(time.Now().Add(time.Minute)) {
		t.Fatalf("auth_time = %s, want a real authentication stamped now", at)
	}
}

// Without the opt-in the tagged build behaves like production: nothing is handled.
func TestConformanceAutoLoginIsOffWithoutTheOptIn(t *testing.T) {
	t.Setenv(conformanceAutoLoginEnv, "")
	store := conformanceTestStore(t)
	id := conformanceTestRequest(t, store)

	if target, handled, err := conformanceAutoLogin(context.Background(), store, id); err != nil || handled || target != "" {
		t.Fatalf("auto-login ran without the opt-in: target=%q handled=%v err=%v", target, handled, err)
	}
	ar, err := store.AuthRequestByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if ar.Done() {
		t.Fatal("the request was completed without the opt-in")
	}
}
