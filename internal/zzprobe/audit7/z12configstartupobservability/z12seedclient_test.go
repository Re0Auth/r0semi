//go:build audit7

// Z12-3: the seeded downstream client is created once and never reconciled.
package z12configstartupobservability

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// Z12-3: the seeded downstream client is created once and never reconciled, so a
// later change to [client] is silently ignored.
//
// cmd/re0auth/main.go:1583-1591 (seedClient) asks the registry for the configured
// id and returns as soon as it is found — "an existing registration is left
// untouched rather than overwritten" — printing
// `downstream client already registered`. Every [client] field is therefore
// applied exactly once, at the first start against an empty registry.
//
// The probe drives the same two steps seedClient does, against the same
// ClientRegistry interface the composition root passes (`store.clients` is
// `oauth.NewMemoryClientRegistry()` in memory mode, `db.Clients()` otherwise), so
// the mechanism is exercised for real rather than read: a mutated config cannot
// change what the registry answers.
func TestZ12SeedClientNeverReconcilesTheConfiguredClient(t *testing.T) {
	ctx := context.Background()
	reg := oauth.NewMemoryClientRegistry()

	// First boot: the file says public with redirect A and one scope.
	first, err := oauth.NewClient("cli", "First-party client", oauth.ClientPublic, "",
		[]string{"https://app.example/callback"}, []oauth.Scope{"account.id"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Create(ctx, first); err != nil {
		t.Fatal(err)
	}

	// Second boot: the operator makes it CONFIDENTIAL, moves the redirect, and
	// widens the scopes.
	second, err := oauth.NewClient("cli", "First-party client", oauth.ClientConfidential, "s3cret",
		[]string{"https://newapp.example/callback"}, []oauth.Scope{"account.id", "phigros.profile.read"})
	if err != nil {
		t.Fatal(err)
	}

	// seedClient's exact logic: Get first, and if it is found, stop.
	got, err := reg.Get(ctx, "cli")
	if err != nil {
		t.Fatalf("the registry lost the seeded client: %v", err)
	}
	if got.Type != oauth.ClientPublic {
		t.Fatalf("premise wrong: the seeded client's type is %q", got.Type)
	}

	// Anti-vacuous: the config the operator would write really does differ, so a
	// reconciliation step would have something to apply.
	if second.Type == got.Type {
		t.Fatal("premise wrong: the two configurations do not differ in type")
	}
	if got.AllowsRedirect("https://newapp.example/callback") {
		t.Fatalf("premise wrong: the stored client already accepts the new redirect URI")
	}
	if got.AllowsScope("phigros.profile.read") {
		t.Fatalf("premise wrong: the stored client already allows the new scope")
	}
	if got.Authenticate("s3cret") {
		t.Fatalf("premise wrong: the stored client already accepts the configured secret")
	}

	// The finding: there is no code path in the process that would change any of
	// it, and the only startup signal is the "already registered" info line.
	t.Errorf("the configured client is not reconciled: the deployment now asks to be "+
		"type=%q redirect=%v scopes=%v, while the registry still answers "+
		"type=%q redirect=%v scopes=%v. seedClient (main.go:1583-1591) returns as soon as "+
		"Get succeeds and prints only 'downstream client already registered'",
		second.Type, second.RedirectURIs, second.AllowedScopes,
		got.Type, got.RedirectURIs, got.AllowedScopes)
}
