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
	"testing"
)

func auditB64Key(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// TestAuditRenamedKekEnvLosesToTheFixedName pins the precedence that makes
// scripts/backup-keys.sh archive the wrong KEK.
//
// cmd/re0auth/config.go:721-731 reads RE0AUTH_KEK FIRST and consults
// vault.kek_env only when it is empty, so a deployment whose config renames the
// variable but whose environment also still carries RE0AUTH_KEK (a leftover from
// before the rename, a shared secret store, a CI job) is served by
// RE0AUTH_KEK.
//
// scripts/backup-keys.sh:53-61 does the opposite: it reads
// `-print-secret-env` (which reports vault.kek_env, i.e. the RENAMED name) and
// REPLACES its default kek_name with it, and line 83 lists only the three OIDC
// keys as fixed names —RE0AUTH_KEK is never added. So the backup archives the
// renamed variable's value, exits 0, and prints "key backup written"; the key the
// service actually encrypts with is not in the file.
func TestAuditRenamedKekEnvLosesToTheFixedName(t *testing.T) {
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
	// The two candidates: the fixed name the service prefers, and the renamed one
	// the config declares and the backup script follows.
	t.Setenv("RE0AUTH_KEK", auditB64Key(0xAA))
	t.Setenv("MY_KEK", auditB64Key(0xBB))

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cfg.KEK, bytes.Repeat([]byte{0xAA}, 32)) {
		t.Fatalf("the service resolved the KEK from somewhere other than RE0AUTH_KEK: %x", cfg.KEK[:4])
	}
	if bytes.Equal(cfg.KEK, bytes.Repeat([]byte{0xBB}, 32)) {
		t.Fatal("MY_KEK won; the finding does not reproduce")
	}

	// What backup-keys.sh consumes: the declared role -> variable name.
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
	t.Logf("CONFIRMED: the service encrypts with RE0AUTH_KEK (0xaa—, while backup-keys.sh "+
		"(scripts/backup-keys.sh:53-61,83) archives %s (0xbb— and exits 0; a restore from that "+
		"key backup cannot decrypt the database dump", declared)
}
