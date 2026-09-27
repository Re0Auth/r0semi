package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A boolean that is present but unparseable must be an error, like Float and Int:
// otherwise "RE0AUTH_COOKIE_SECURE=yes" silently uses the fallback and looks
// applied.
func TestBoolRejectsUnparseableValues(t *testing.T) {
	t.Setenv("TEST_BOOL", "")
	if v, err := Bool("TEST_BOOL", true); err != nil || v != true {
		t.Fatalf("unset = %v, %v; want the fallback", v, err)
	}
	for raw, want := range map[string]bool{"true": true, "1": true, "false": false, "0": false} {
		t.Setenv("TEST_BOOL", raw)
		got, err := Bool("TEST_BOOL", !want)
		if err != nil || got != want {
			t.Fatalf("Bool(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	t.Setenv("TEST_BOOL", "yes")
	if _, err := Bool("TEST_BOOL", false); err == nil {
		t.Fatal("an unparseable boolean was accepted")
	}
}

func TestNumberParsersRejectUnparseableValues(t *testing.T) {
	t.Setenv("TEST_FLOAT", "50/s")
	if _, err := Float("TEST_FLOAT", 1); err == nil {
		t.Fatal("an unparseable float was accepted")
	}
	t.Setenv("TEST_INT", "many")
	if _, err := Int("TEST_INT", 1); err == nil {
		t.Fatal("an unparseable int was accepted")
	}
}

type readSchema struct {
	Storage struct {
		Driver string `toml:"driver"`
		DSNEnv string `toml:"dsn_env"`
	} `toml:"storage"`
	Server struct {
		Addr string `toml:"addr"`
	} `toml:"server"`
}

func writeTOML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A key the schema does not know must be an error, not a setting that silently
// never takes effect.
//
// The failure this prevents is not cosmetic: `dsn` for `dsn_env` leaves the driver
// empty, and the driver's default is memory, so a deployment meant to be durable
// comes up ephemeral. `trusted_proxies` and the admin allowlist fail the same way.
func TestReadRejectsUnknownKeys(t *testing.T) {
	// A typo in a key name, and a typo in a table name.
	for name, body := range map[string]string{
		"misspelled key":   "[storage]\ndsn = \"DATABASE_URL\"\n",
		"misspelled table": "[storrage]\ndriver = \"postgres\"\n",
	} {
		var out readSchema
		if err := Read(writeTOML(t, body), &out); err == nil {
			t.Fatalf("%s was silently ignored: %+v", name, out)
		}
	}

	// The same file with the right keys parses, so the guard cannot be satisfied by
	// refusing everything.
	var out readSchema
	path := writeTOML(t, "[storage]\ndriver = \"postgres\"\ndsn_env = \"DATABASE_URL\"\n[server]\naddr = \"127.0.0.1:8080\"\n")
	if err := Read(path, &out); err != nil {
		t.Fatalf("a valid file was rejected: %v", err)
	}
	if out.Storage.Driver != "postgres" || out.Storage.DSNEnv != "DATABASE_URL" {
		t.Fatalf("decoded = %+v", out)
	}

	// An empty path still means "environment only", not an error.
	if err := Read("", &out); err != nil {
		t.Fatalf("the empty path was rejected: %v", err)
	}
}
