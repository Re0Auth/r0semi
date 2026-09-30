package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AUDIT9 / S08-2 (fixed) — storage.dsn_env is resolved whenever the driver
// resolves to postgres, whether the driver was inferred or stated.
//
// Before the fix, cfg.DatabaseURL was pre-loaded only from the literal
// DATABASE_URL. With storage.driver absent and storage.dsn_env naming some OTHER
// variable, the loader concluded "postgres" from the mere presence of dsn_env but
// never called config.Secret on that name, so DatabaseURL stayed empty: openStorage
// took the memory branch while StorageDriver said postgres, the durable-audit-key
// gate was skipped, and persistence plus the tamper-evident chain were lost.
func TestAudit9DSNEnvIsResolvedWhenDriverIsInferred(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", valid)
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", valid)
	t.Setenv("RE0AUTH_STORAGE_DRIVER", "")
	// The declared variable IS set; DATABASE_URL is not.
	t.Setenv("RE0AUTH_DSN", "postgres://user:secret@db.example/r0semi")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("RE0AUTH_AUDIT_KEY", valid)

	path := filepath.Join(t.TempDir(), "re0auth.toml")
	body := "[server]\nissuer = \"https://re0auth.test\"\n\n[storage]\ndsn_env = \"RE0AUTH_DSN\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.StorageDriver != "postgres" {
		t.Fatalf("StorageDriver = %q, want postgres (dsn_env alone selects postgres)", cfg.StorageDriver)
	}
	if cfg.DatabaseURL != "postgres://user:secret@db.example/r0semi" {
		t.Fatalf("DatabaseURL = %q, want the RE0AUTH_DSN value resolved from storage.dsn_env", cfg.DatabaseURL)
	}
	// The durable-audit gate reads DatabaseURL, so it must have been enforced:
	// the key above is valid, and removing it has to be refused.
	if cfg.AuditKey == nil {
		t.Error("AuditKey is nil although the driver is durable")
	}
}

// A dsn_env that names an unset variable is an operator error, not a silent
// downgrade to memory.
func TestAudit9DeclaredButUnsetDSNEnvIsRefused(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", valid)
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", valid)
	t.Setenv("RE0AUTH_STORAGE_DRIVER", "")
	t.Setenv("RE0AUTH_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("RE0AUTH_AUDIT_KEY", valid)

	path := filepath.Join(t.TempDir(), "re0auth.toml")
	body := "[server]\nissuer = \"https://re0auth.test\"\n\n[storage]\ndsn_env = \"RE0AUTH_DSN\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig accepted a storage.dsn_env whose variable is unset: that is the " +
			"silent-downgrade path S08-2 is about")
	} else if !strings.Contains(err.Error(), "storage.dsn_env") {
		t.Fatalf("err = %v, want it to name storage.dsn_env", err)
	}
}

// The file's dsn_env is authoritative for the variable NAME: a stale DATABASE_URL
// in the environment must not shadow it.
func TestAudit9FileDSNEnvShadowsAStaleDatabaseURL(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", valid)
	t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", valid)
	t.Setenv("RE0AUTH_STORAGE_DRIVER", "")
	t.Setenv("RE0AUTH_DSN", "postgres://declared.example/r0semi")
	t.Setenv("DATABASE_URL", "postgres://stale.example/wrongdb")
	t.Setenv("RE0AUTH_AUDIT_KEY", valid)

	path := filepath.Join(t.TempDir(), "re0auth.toml")
	// driver stated, so only the NAME precedence is under test here.
	body := "[server]\nissuer = \"https://re0auth.test\"\n\n[storage]\ndriver = \"postgres\"\ndsn_env = \"RE0AUTH_DSN\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.DatabaseURL != "postgres://declared.example/r0semi" {
		t.Fatalf("DatabaseURL = %q, want the file's dsn_env to win over a stale DATABASE_URL", cfg.DatabaseURL)
	}
}
