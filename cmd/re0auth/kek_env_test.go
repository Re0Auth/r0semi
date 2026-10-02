package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// S08-1: `vault.kek_env` NAMES the variable holding the KEK, and the name in the
// file wins over the hardcoded RE0AUTH_KEK.
//
// Reading the hardcoded name first made a rename a silent no-op: the process came
// up on whatever RE0AUTH_KEK still held, logged nothing, and every unwrap after the
// first write failed with "authentication failed" — survivable-looking, and
// discovered only when records stopped being readable. docs/operations.md is
// explicit that the variable may be renamed; -print-secret-env and
// scripts/backup-keys.sh both read the file's name.
func TestVaultKEKEnvNameIsAuthoritative(t *testing.T) {
	keyA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA1}, 32))
	keyB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xB2}, 32))
	const body = "[server]\nissuer = \"https://auth.example\"\ncookie_secure = true\n" +
		"[vault]\nkek_env = \"MY_KEK\"\n"

	t.Run("the renamed variable is the one that is read", func(t *testing.T) {
		t.Setenv("RE0AUTH_KEK", "")
		t.Setenv("MY_KEK", keyA)

		cfg, err := loadConfig(writeConfig(t, "kek.toml", body))
		if err != nil {
			t.Fatal(err)
		}
		if want := bytes.Repeat([]byte{0xA1}, 32); !bytes.Equal(cfg.KEK, want) {
			t.Error("the KEK was read from somewhere other than the variable vault.kek_env names")
		}
	})

	t.Run("a stale RE0AUTH_KEK holding another key refuses startup", func(t *testing.T) {
		t.Setenv("MY_KEK", keyA)
		t.Setenv("RE0AUTH_KEK", keyB)

		_, err := loadConfig(writeConfig(t, "kek.toml", body))
		if err == nil {
			t.Fatal("startup accepted two different KEKs; the file's name must be the one that is read")
		}
		if !strings.Contains(err.Error(), "MY_KEK") || !strings.Contains(err.Error(), "RE0AUTH_KEK") {
			t.Errorf("the refusal does not name both variables, so it cannot be acted on: %v", err)
		}
	})

	t.Run("the same key under both names is not an accident", func(t *testing.T) {
		t.Setenv("MY_KEK", keyA)
		t.Setenv("RE0AUTH_KEK", keyA)

		if _, err := loadConfig(writeConfig(t, "kek.toml", body)); err != nil {
			t.Fatalf("the same key under both names was refused: %v", err)
		}
	})

	t.Run("nothing set is an error that names the position", func(t *testing.T) {
		t.Setenv("MY_KEK", "")
		t.Setenv("RE0AUTH_KEK", "")

		_, err := loadConfig(writeConfig(t, "kek.toml", body))
		if err == nil {
			t.Fatal("startup succeeded with no KEK at all")
		}
		if !strings.Contains(err.Error(), "vault.kek_env") {
			t.Errorf("the refusal does not name vault.kek_env: %v", err)
		}
	})
}

// The default name is still the default: a file that names nothing keeps working
// with RE0AUTH_KEK alone, which is what every deployment and test fixture in this
// repo does.
func TestVaultKEKDefaultsToTheHardcodedName(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xC3}, 32))
	t.Setenv("RE0AUTH_KEK", key)

	cfg, err := loadConfig(writeConfig(t, "re0auth.toml", multiClientBase))
	if err != nil {
		t.Fatalf("a config with no vault.kek_env was refused: %v", err)
	}
	if want := bytes.Repeat([]byte{0xC3}, 32); !bytes.Equal(cfg.KEK, want) {
		t.Error("the default RE0AUTH_KEK was not read")
	}

	// And with nothing set, the message names both spellings rather than only the
	// position: that is the pair an operator has to choose between.
	t.Setenv("RE0AUTH_KEK", "")
	if _, err := loadConfig(writeConfig(t, "re0auth.toml", multiClientBase)); err == nil {
		t.Fatal("startup succeeded with no KEK")
	} else if !strings.Contains(err.Error(), "RE0AUTH_KEK") || !strings.Contains(err.Error(), "vault.kek_env") {
		t.Errorf("the refusal names only one spelling: %v", err)
	}
}
