package wiring

import (
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/core"
	"github.com/Re0Auth/r0semi/oauth"
)

func TestComponentProvidesAS(t *testing.T) {
	app := core.New()
	if _, err := KeyClients.Provide(app.Root(), oauth.NewMemoryClientRegistry()); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyTokens.Provide(app.Root(), oauth.NewMemoryStore()); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyLog.Provide(app.Root(), audit.NewMemoryLogger()); err != nil {
		t.Fatal(err)
	}

	f, err := app.Use(OAuthComponent(oauth.Config{Issuer: "https://auth.test", Scopes: oauth.DefaultRegistry()}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.State(); got != core.StateActive {
		t.Fatalf("state = %s, want active", got)
	}
	if _, err := KeyAS.Get(app.Root()); err != nil {
		t.Fatal(err)
	}
}

// I5: without the token store the AS never activates.
func TestComponentInactiveWithoutTokens(t *testing.T) {
	app := core.New()
	if _, err := KeyClients.Provide(app.Root(), oauth.NewMemoryClientRegistry()); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyLog.Provide(app.Root(), audit.NewMemoryLogger()); err != nil {
		t.Fatal(err)
	}
	f, err := app.Use(OAuthComponent(oauth.Config{Issuer: "https://auth.test", Scopes: oauth.DefaultRegistry()}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.State(); got != core.StateInactive {
		t.Fatalf("state = %s, want inactive", got)
	}
}

// A misconfigured AS fails closed instead of publishing a broken service.
func TestComponentFailsWithoutIssuer(t *testing.T) {
	app := core.New()
	if _, err := KeyClients.Provide(app.Root(), oauth.NewMemoryClientRegistry()); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyTokens.Provide(app.Root(), oauth.NewMemoryStore()); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyLog.Provide(app.Root(), audit.NewMemoryLogger()); err != nil {
		t.Fatal(err)
	}
	f, err := app.Use(OAuthComponent(oauth.Config{Scopes: oauth.DefaultRegistry()}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.State(); got != core.StateFailed {
		t.Fatalf("state = %s, want failed", got)
	}
	if _, err := KeyAS.Get(app.Root()); !errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("oauth/as resolvable after a failed load: %v", err)
	}
}
