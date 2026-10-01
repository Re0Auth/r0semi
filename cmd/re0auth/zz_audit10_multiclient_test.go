package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// The [[clients]] array is the multi-client form of the [client] section. These
// tests pin the four places a mistake would hide: the file schema, the client list
// it builds, the refusals for a malformed or duplicated entry, and the fact that
// every client goes through the same registration and drift check.

func writeConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const multiClientBase = "[server]\nissuer = \"https://auth.example\"\ncookie_secure = true\n"

func TestLoadConfigReadsExtraClients(t *testing.T) {
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SECOND_CLIENT_SECRET", "second-secret")

	body := multiClientBase +
		"[client]\nid = \"cli\"\nredirect_uris = [\"https://app.example/cb\"]\n\n" +
		"[[clients]]\nid = \"second\"\nsecret_env = \"SECOND_CLIENT_SECRET\"\n" +
		"redirect_uris = [\"https://second.example/cb\"]\nscopes = [\"account.id\"]\n\n" +
		"[[clients]]\nid = \"third\"\nredirect_uris = [\"https://third.example/cb\"]\n"

	cfg, err := loadConfig(writeConfig(t, "re0auth.toml", body))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.noPrimaryClient {
		t.Fatal("the primary [client] section was skipped even though it is present")
	}
	if len(cfg.extraClients) != 2 {
		t.Fatalf("extraClients = %d, want 2: %+v", len(cfg.extraClients), cfg.extraClients)
	}
	second := cfg.extraClients[0]
	if second.ID != "second" || second.Name != "second" || second.Secret != "second-secret" ||
		len(second.RedirectURIs) != 1 || second.RedirectURIs[0] != "https://second.example/cb" ||
		len(second.Scopes) != 1 || second.Scopes[0] != "account.id" {
		t.Fatalf("the first extra client was mis-resolved: %+v", second)
	}
	// Name defaults to the id and scopes to account.id, exactly as for [client].
	third := cfg.extraClients[1]
	if third.Name != "third" || third.Secret != "" || len(third.Scopes) != 1 || third.Scopes[0] != "account.id" {
		t.Fatalf("the second extra client did not get the documented defaults: %+v", third)
	}

	clients, err := configuredClients(cfg)
	if err != nil {
		t.Fatalf("configuredClients: %v", err)
	}
	if len(clients) != 3 {
		t.Fatalf("configuredClients = %d clients, want 3 (primary then file order)", len(clients))
	}
	if clients[0].ID != "cli" || clients[1].ID != "second" || clients[2].ID != "third" {
		t.Fatalf("client order = %q, %q, %q", clients[0].ID, clients[1].ID, clients[2].ID)
	}
	if clients[1].Type != oauth.ClientConfidential || !clients[1].Authenticate("second-secret") {
		t.Fatalf("the secret_env client is not confidential or cannot authenticate: %+v", clients[1])
	}
	if clients[2].Type != oauth.ClientPublic {
		t.Fatalf("a secretless extra client is not public: %+v", clients[2])
	}
	if !clients[2].AllowsRedirect("https://third.example/cb") {
		t.Fatalf("the extra client lost its redirect: %v", clients[2].RedirectURIs)
	}
}

func TestLoadConfigRefusesDuplicateClientIDs(t *testing.T) {
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	// An entry that repeats the primary's id.
	body := multiClientBase + "[client]\nid = \"cli\"\n\n[[clients]]\nid = \"cli\"\n" +
		"redirect_uris = [\"https://other.example/cb\"]\n"
	if _, err := loadConfig(writeConfig(t, "dup-primary.toml", body)); err == nil {
		t.Fatal("a [[clients]] entry repeating the [client] id was accepted")
	} else if !strings.Contains(err.Error(), "cli") {
		t.Fatalf("the refusal does not name the duplicated id: %v", err)
	}

	// Two entries repeating each other.
	body = multiClientBase + "[[clients]]\nid = \"same\"\nredirect_uris = [\"https://a.example/cb\"]\n\n" +
		"[[clients]]\nid = \"same\"\nredirect_uris = [\"https://b.example/cb\"]\n"
	if _, err := loadConfig(writeConfig(t, "dup-extra.toml", body)); err == nil {
		t.Fatal("two [[clients]] entries with the same id were accepted")
	} else if !strings.Contains(err.Error(), "same") {
		t.Fatalf("the refusal does not name the duplicated id: %v", err)
	}
}

func TestLoadConfigRefusesIncompleteExtraClient(t *testing.T) {
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	cases := map[string]string{
		"missing id": multiClientBase +
			"[[clients]]\nredirect_uris = [\"https://a.example/cb\"]\n",
		"missing redirect_uris": multiClientBase +
			"[[clients]]\nid = \"second\"\n",
		"unknown key": multiClientBase +
			"[[clients]]\nid = \"second\"\nredirect_uris = [\"https://a.example/cb\"]\nredirect_uri = \"typo\"\n",
	}
	for name, body := range cases {
		if _, err := loadConfig(writeConfig(t, "bad.toml", body)); err == nil {
			t.Errorf("%s: loadConfig accepted it", name)
		} else if !strings.Contains(err.Error(), "clients[0]") && !strings.Contains(err.Error(), "typo") {
			t.Errorf("%s: the refusal does not name the entry: %v", name, err)
		}
	}
}

func TestLoadConfigClientArrayWithoutClientSection(t *testing.T) {
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	body := multiClientBase + "[[clients]]\nid = \"only\"\nredirect_uris = [\"https://only.example/cb\"]\n"

	cfg, err := loadConfig(writeConfig(t, "array-only.toml", body))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.noPrimaryClient {
		t.Fatal("with no [client] section and [[clients]] present, the default `cli` client must not be seeded")
	}
	clients, err := configuredClients(cfg)
	if err != nil {
		t.Fatalf("configuredClients: %v", err)
	}
	if len(clients) != 1 || clients[0].ID != "only" {
		t.Fatalf("configuredClients = %+v, want exactly the [[clients]] entry", clients)
	}

	// Without [[clients]], an absent [client] keeps today's default primary.
	cfg, err = loadConfig(writeConfig(t, "no-clients.toml", multiClientBase))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.noPrimaryClient || cfg.clientID != "cli" {
		t.Fatalf("the default primary client changed: noPrimary=%t id=%q", cfg.noPrimaryClient, cfg.clientID)
	}
}

// RE0AUTH_CLIENT_ID is an explicit statement that there IS a primary client, even
// when the file leaves [client] out and names [[clients]] entries instead. Kept
// apart from the test above because t.Setenv lasts for the whole test.
func TestLoadConfigClientIDEnvForcesThePrimaryClient(t *testing.T) {
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("RE0AUTH_CLIENT_ID", "from-env")
	body := multiClientBase + "[[clients]]\nid = \"only\"\nredirect_uris = [\"https://only.example/cb\"]\n"

	cfg, err := loadConfig(writeConfig(t, "array-only.toml", body))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.noPrimaryClient || cfg.clientID != "from-env" {
		t.Fatalf("RE0AUTH_CLIENT_ID did not force the primary client: noPrimary=%t id=%q",
			cfg.noPrimaryClient, cfg.clientID)
	}
	clients, err := configuredClients(cfg)
	if err != nil {
		t.Fatalf("configuredClients: %v", err)
	}
	if len(clients) != 2 || clients[0].ID != "from-env" {
		t.Fatalf("configuredClients = %+v, want the env primary then the entry", clients)
	}
}

func TestConfiguredClientsRefusesExemptPublicExtraClient(t *testing.T) {
	cfg := settings{
		noPrimaryClient: true,
		extraClients: []clientSpec{{
			ID:               "legacy",
			Name:             "legacy",
			RedirectURIs:     []string{"https://legacy.example/cb"},
			Scopes:           []string{"account.id"},
			AllowMissingPKCE: true,
		}},
	}
	_, err := configuredClients(cfg)
	if err == nil {
		t.Fatal("an extra public client without PKCE was accepted")
	}
	if !strings.Contains(err.Error(), "allow_missing_pkce") || !strings.Contains(err.Error(), "clients[0]") {
		t.Fatalf("the refusal does not name the entry and the field: %v", err)
	}
}

func TestSeedClientsRegistersAndChecksEveryClient(t *testing.T) {
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SECOND_CLIENT_SECRET", "second-secret")
	body := multiClientBase +
		"[client]\nid = \"cli\"\nredirect_uris = [\"https://app.example/cb\"]\n\n" +
		"[[clients]]\nid = \"second\"\nsecret_env = \"SECOND_CLIENT_SECRET\"\n" +
		"redirect_uris = [\"https://second.example/cb\"]\nscopes = [\"account.id\"]\n"
	cfg, err := loadConfig(writeConfig(t, "re0auth.toml", body))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	ctx := context.Background()
	registry := oauth.NewMemoryClientRegistry()
	if err := seedClients(ctx, registry, cfg); err != nil {
		t.Fatalf("seedClients: %v", err)
	}
	for _, id := range []string{"cli", "second"} {
		if _, err := registry.Get(ctx, id); err != nil {
			t.Fatalf("client %q was not registered: %v", id, err)
		}
	}
	// Idempotent: the second boot finds both and matches.
	if err := seedClients(ctx, registry, cfg); err != nil {
		t.Fatalf("seeding an unchanged configuration was refused: %v", err)
	}

	// A changed [[clients]] entry is refused by the same drift rule as [client], and
	// the refusal names the entry, not just the field.
	drifted := cfg
	drifted.extraClients = append([]clientSpec(nil), cfg.extraClients...)
	drifted.extraClients[0].RedirectURIs = []string{"https://new.example/cb"}
	err = seedClients(ctx, registry, drifted)
	if err == nil {
		t.Fatal("a drifted [[clients]] entry was accepted")
	}
	for _, want := range []string{"[[clients]]", "second", "redirect_uris"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	// The registry stays authoritative: the refusal did not rewrite the client.
	got, err := registry.Get(ctx, "second")
	if err != nil {
		t.Fatal(err)
	}
	if !got.AllowsRedirect("https://second.example/cb") {
		t.Fatalf("the drift refusal rewrote the extra client: %v", got.RedirectURIs)
	}
}

func TestConfiguredClientsRefusesAnEmptyList(t *testing.T) {
	// Belt and braces: a settings value with neither a primary nor an entry (only
	// reachable by bypassing loadConfig) must not silently seed nothing.
	if _, err := configuredClients(settings{noPrimaryClient: true}); err == nil {
		t.Fatal("configuredClients accepted a deployment with no client at all")
	}
}
