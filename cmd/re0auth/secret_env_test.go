package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestConfigSecretEnvNamesListsEveryDeclaredSecret pins the flag the backup script
// reads. The rule it encodes is "names, never values": the output is parsed by
// scripts/backup-keys.sh, and a value on that stream would be a credential in a
// log line.
//
// The fixture is deliberately awkward — a renamed KEK, a retired KEK, two providers
// and a source — because those are exactly the declarations the script cannot guess
// from the environment.
func TestConfigSecretEnvNamesListsEveryDeclaredSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "re0auth.toml")
	const fixture = `
[server]
issuer = "https://auth.example"

[vault]
kek_env = "MY_KEK"
kek_id  = "kek-2"

[[vault.retired]]
kek_id  = "kek-1"
kek_env = "MY_OLD_KEK"

[idp.github]
client_id         = "ov23li"
client_secret_env = "GH_SECRET"

[idp.authentik]
client_id         = "authentik"
client_secret_env = "AUTHENTIK_SECRET"

[[sources]]
game        = "phigros"
source      = "next-phi"
issuer      = "https://api.next-phi.example"
token_class = "revocable"
status      = "active"
raw_base    = "https://api.next-phi.example/v1"

client_id         = "re0auth"
client_secret_env = "NEXT_PHI_SECRET"
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	// The values are set in this process, and must not appear anywhere in the
	// output: the flag reports names only.
	t.Setenv("MY_KEK", "kek-material-do-not-print")
	t.Setenv("NEXT_PHI_SECRET", "client-secret-do-not-print")

	lines, err := configSecretEnvNames(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"idp.authentik.client_secret_env=AUTHENTIK_SECRET",
		"idp.github.client_secret_env=GH_SECRET",
		"sources[0].client_secret_env=NEXT_PHI_SECRET",
		"vault.kek_env=MY_KEK",
		"vault.retired[0].kek_env=MY_OLD_KEK",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("names = %q, want %q", lines, want)
	}
	for _, line := range lines {
		if strings.Contains(line, "do-not-print") || strings.Contains(line, "=") && strings.Count(line, "=") != 1 {
			t.Fatalf("line %q carries more than a name", line)
		}
	}
}

// A config that declares no secret variables is an empty answer, not an error: a
// deployment with no idp and no sources still has its four fixed keys, which the
// script knows by name.
func TestConfigSecretEnvNamesIsEmptyForAConfigWithoutDeclarations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "re0auth.toml")
	if err := os.WriteFile(path, []byte("[server]\nissuer = \"https://auth.example\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := configSecretEnvNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Fatalf("names = %q, want none", lines)
	}
}

// A missing file is an error rather than silence: an empty list would tell the
// backup script there is nothing to enumerate, which is the wrong answer when the
// path itself is wrong.
func TestConfigSecretEnvNamesRefusesAMissingFile(t *testing.T) {
	if _, err := configSecretEnvNames(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("a missing config file was reported as an empty list")
	}
}
