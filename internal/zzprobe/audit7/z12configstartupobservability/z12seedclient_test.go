//go:build audit7

// Z12-3: the seeding path must refuse a registration that drifts from [client].
package z12configstartupobservability

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// overlaySeedClientTest is compiled INTO package main through `go test -overlay`.
// The seeding path is unexported package-main code, so a probe living in
// internal/zzprobe cannot call it (and importing package main is impossible); the
// overlay adds a throwaway _test.go to cmd/re0auth at build time without writing a
// single file into the checkout. The test drives the production seeding path
// (seedClients, the entry point the composition root uses) against the same
// in-memory ClientRegistry the composition root passes.
const overlaySeedClientTest = `package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

func TestOverlayZ12SeedClientDrift(t *testing.T) {
	ctx := context.Background()

	// Control A: an empty registry receives the configured client.
	fresh := oauth.NewMemoryClientRegistry()
	cfg := settings{
		clientID:        "cli",
		clientName:      "First-party client",
		clientRedirects: []string{"https://app.example/callback"},
		clientScopes:    []string{"account.id"},
	}
	if err := seedClients(ctx, fresh, cfg); err != nil {
		t.Fatalf("control: seeding an empty registry failed: %v", err)
	}
	if _, err := fresh.Get(ctx, "cli"); err != nil {
		t.Fatalf("control: the configured client was not registered: %v", err)
	}

	// Control B: the SAME configuration, already registered, still boots.
	if err := seedClients(ctx, fresh, cfg); err != nil {
		t.Fatalf("control: an unchanged configuration was refused: %v", err)
	}

	// The guard: the registered client differs in every field the drift check
	// compares (type via the secret, redirect_uris, scopes, secret digest).
	drifted := settings{
		clientID:        "cli",
		clientName:      "First-party client",
		clientSecret:    "s3cret",
		clientRedirects: []string{"https://newapp.example/callback"},
		clientScopes:    []string{"account.id", "phigros.profile.read"},
	}
	err := seedClients(ctx, fresh, drifted)
	if err == nil {
		t.Fatalf("seedClients accepted a registration that differs from [client] in type, redirect_uris, scopes and secret")
	}
	for _, field := range []string{"type", "redirect_uris", "scopes", "secret"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("the refusal does not name the differing field %q: %v", field, err)
		}
	}

	// The registry stays authoritative: the refusal does not rewrite the client.
	got, gerr := fresh.Get(ctx, "cli")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got.Type != oauth.ClientPublic || !got.AllowsRedirect("https://app.example/callback") {
		t.Errorf("the drift refusal rewrote the registered client: type=%q redirects=%v",
			got.Type, got.RedirectURIs)
	}
}
`

// TestZ12SeedClientRefusesADriftedRegistration is the re-derived Z12-3 guard. The
// old probe of this name never called the seeding path and ended in an unconditional
// t.Errorf, so it could never pass once the finding was fixed. This one passes on
// the fixed code and fails if the drift refusal is removed.
//
// Two layers:
//   - a real-process control: an unchanged [client] boots through the seeding path and
//     reaches the listen stage;
//   - a behavioural guard of the production seeding path itself (seedClients), compiled into
//     package main with `go test -overlay` (no checkout file is added or changed),
//     because the in-memory registry cannot carry a client across process boots
//     (each memory boot starts empty, so no second boot can present a drifted
//     registration) and the seeding path is unexported.
func TestZ12SeedClientRefusesADriftedRegistration(t *testing.T) {
	z12SeedClientGuard(t)
}

// TestZ12SeedClientNeverReconcilesTheConfiguredClient keeps the round-7 finding's
// name runnable: `go test -run ^TestZ12SeedClientNeverReconcilesTheConfiguredClient$`
// still reaches the regression guard instead of matching nothing.
func TestZ12SeedClientNeverReconcilesTheConfiguredClient(t *testing.T) {
	z12SeedClientGuard(t)
}

func z12SeedClientGuard(t *testing.T) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	// Control, real process: the unchanged [client] section seeds cleanly and the
	// run moves on to the listener (which fails by design, because
	// RE0AUTH_ADDR is unbindable). The prefix is the production seeding path.
	clientTOML := serverOnly +
		"\n[client]\nid = \"cli\"\nname = \"First-party client\"\n" +
		"redirect_uris = [\"https://app.example/callback\"]\nscopes = [\"account.id\"]\n"
	path := writeConfig(t, "client.toml", clientTOML)
	boot := runBinary(t, serveEnv(), "-config", path)
	if !strings.Contains(boot.out, "registered downstream client") {
		t.Fatalf("the real binary never reached the seeding path:\n%s", boot.out)
	}
	if !strings.Contains(boot.out, "stage=listen") {
		t.Fatalf("the unchanged [client] did not reach the listen stage:\n%s", boot.out)
	}

	work := t.TempDir()
	backing := filepath.Join(work, "zzprobe_overlay_seedclient_test.go")
	if err := os.WriteFile(backing, []byte(overlaySeedClientTest), 0o644); err != nil {
		t.Fatal(err)
	}
	// The overlay maps a path that does not exist in the checkout to the backing
	// file above, so the package main build sees one extra test file and nothing
	// on disk changes.
	target := filepath.Join(root, "cmd", "re0auth", "zzprobe_overlay_seedclient_test.go")
	blob, err := json.Marshal(map[string]any{
		"Replace": map[string]string{filepath.ToSlash(target): backing},
	})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(work, "overlay.json")
	if err := os.WriteFile(overlayPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-overlay", overlayPath, "-count=1", "-v",
		"-run", "^TestOverlayZ12SeedClientDrift$", "./cmd/re0auth/")
	cmd.Dir = root
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("the production seeding path does not refuse a registration that drifts from [client]: %v\n%s",
			err, out)
		return
	}
	// A `-run` that matches nothing exits 0, so require the PASS marker: without
	// it this guard would be green because it never ran.
	if !strings.Contains(string(out), "--- PASS: TestOverlayZ12SeedClientDrift") {
		t.Errorf("the overlay test did not run, so the drift guard is vacuous:\n%s", out)
	}
}
