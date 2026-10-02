//go:build audit || audit6

package main

// Round-6 audit probe (crypto/key-management area): which variable actually holds
// the KEK, and which one scripts/backup-keys.sh archives.
//
// TEST-ONLY. Write-up: C:\git\r0semi\_audit\crypto-vault.md

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func auditB64Key(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// TestAuditDeclaredKekEnvWinsAndAStaleFixedNameRefuses pins the S08-1 fix.
//
// Before the fix, cmd/re0auth/config.go read RE0AUTH_KEK FIRST and consulted
// vault.kek_env only when it was empty, so a deployment whose config renamed the
// variable (kek_env = "MY_KEK") but whose environment still carried the fixed
// name — a leftover from before the rename, a shared secret store, a CI job — was
// silently served by RE0AUTH_KEK, while scripts/backup-keys.sh archived the
// declared one and exited 0. The two keys could differ, and that was discovered
// only when records stopped decrypting.
//
// Now the file's declared name wins, and a stale fixed name holding DIFFERENT
// material is a startup refusal that names both spellings rather than a quiet
// choice between two keys.
func TestAuditDeclaredKekEnvWinsAndAStaleFixedNameRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "re0auth.toml")
	body := "[server]\nissuer = \"https://re0auth.test\"\n\n" +
		"[storage]\ndriver = \"memory\"\n\n" +
		"[vault]\nkek_id = \"kek-1\"\nkek_env = \"MY_KEK\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", auditB64Key(0x11))
	t.Setenv("MY_KEK", auditB64Key(0xBB))

	// 1. The declared name alone decides.
	t.Setenv("RE0AUTH_KEK", "")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cfg.KEK, bytes.Repeat([]byte{0xBB}, 32)) {
		t.Fatalf("the service did not resolve the KEK from the declared kek_env: %x", cfg.KEK[:4])
	}

	// 2. A stale fixed name with DIFFERENT material is refused, not quietly picked.
	t.Setenv("RE0AUTH_KEK", auditB64Key(0xAA))
	_, err = loadConfig(path)
	if err == nil {
		t.Fatal("a stale RE0AUTH_KEK holding a different key was accepted")
	}
	if !strings.Contains(err.Error(), "vault.kek_env") || !strings.Contains(err.Error(), "RE0AUTH_KEK") {
		t.Fatalf("the refusal does not name both spellings: %v", err)
	}

	// 3. The same material under both names is not the accident being refused.
	t.Setenv("RE0AUTH_KEK", auditB64Key(0xBB))
	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cfg.KEK, bytes.Repeat([]byte{0xBB}, 32)) {
		t.Fatalf("matching material under both names failed to load: %x", cfg.KEK[:4])
	}

	// 4. What backup-keys.sh consumes: the declared role -> variable name.
	names, err := configSecretEnvNames(path)
	if err != nil {
		t.Fatal(err)
	}
	var declared string
	for _, line := range names {
		if line == "vault.kek_env=MY_KEK" {
			declared = "MY_KEK"
		}
	}
	if declared != "MY_KEK" {
		t.Fatalf("configSecretEnvNames = %v, want vault.kek_env=MY_KEK", names)
	}
	t.Logf("declared kek_env %s wins, and a stale fixed name with different material refuses startup; "+
		"backup-keys.sh follows the same declared name", declared)
}
