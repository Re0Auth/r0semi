package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// The concurrency cap exists to bound work in progress. In a durable deployment
// that work is mostly requests waiting on a pooled connection, so a cap far above
// the pool bounds nothing: it turns a fast 503 into a slow wait for a connection
// the process does not have. The default is therefore derived from the pool.
func TestMaxInFlightDefaultIsDerivedFromThePool(t *testing.T) {
	cases := []struct {
		name    string
		durable bool
		maxConn int32
		want    int
	}{
		{name: "in memory keeps the flat default", durable: false, maxConn: 16, want: defaultMaxInFlightMemory},
		{name: "durable scales with the pool", durable: true, maxConn: 16, want: 128},
		{name: "a large pool scales with it", durable: true, maxConn: 64, want: 512},
		{name: "a tiny pool keeps a usable floor", durable: true, maxConn: 2, want: minMaxInFlight},
		{name: "an unset pool still has the floor", durable: true, maxConn: 0, want: minMaxInFlight},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultMaxInFlightFor(tc.durable, tc.maxConn); got != tc.want {
				t.Fatalf("defaultMaxInFlightFor(%v, %d) = %d, want %d", tc.durable, tc.maxConn, got, tc.want)
			}
		})
	}
}

// The resolution end to end: a deployment that chooses a cap keeps it, one that
// does not gets the pool-derived number, and an explicit 0 still means "no cap".
func TestMaxInFlightResolution(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))

	// serverExtra and storageExtra are appended inside their own tables: a second
	// [storage] header would be a duplicate table and TOML would refuse the file.
	writeConfig := func(t *testing.T, driver, serverExtra, storageExtra string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "re0auth.toml")
		body := "[server]\nissuer = \"https://re0auth.test\"\n" + serverExtra +
			"\n[storage]\ndriver = \"" + driver + "\"\n" + storageExtra
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := func(t *testing.T, driver string) {
		t.Helper()
		t.Setenv("RE0AUTH_ISSUER", "https://re0auth.test")
		t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
		t.Setenv("RE0AUTH_KEK", valid)
		t.Setenv("RE0AUTH_OIDC_TOKEN_KEY", valid)
		t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "")
		if driver == "postgres" {
			t.Setenv("DATABASE_URL", "postgres://localhost/r0semi")
			t.Setenv("RE0AUTH_AUDIT_KEY", valid)
		} else {
			t.Setenv("DATABASE_URL", "")
			t.Setenv("RE0AUTH_AUDIT_KEY", "")
		}
	}

	t.Run("durable, unchosen", func(t *testing.T) {
		base(t, "postgres")
		cfg, err := loadConfig(writeConfig(t, "postgres", "", ""))
		if err != nil {
			t.Fatal(err)
		}
		if want := defaultMaxInFlightFor(true, cfg.Pool.MaxConns); cfg.MaxInFlight != want {
			t.Fatalf("MaxInFlight = %d, want the pool-derived %d", cfg.MaxInFlight, want)
		}
	})

	t.Run("durable, unchosen, small pool", func(t *testing.T) {
		base(t, "postgres")
		cfg, err := loadConfig(writeConfig(t, "postgres", "", "max_conns = 2\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxInFlight != minMaxInFlight {
			t.Fatalf("MaxInFlight = %d, want the floor %d", cfg.MaxInFlight, minMaxInFlight)
		}
	})

	t.Run("in memory, unchosen", func(t *testing.T) {
		base(t, "memory")
		cfg, err := loadConfig(writeConfig(t, "memory", "", ""))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxInFlight != defaultMaxInFlightMemory {
			t.Fatalf("MaxInFlight = %d, want %d", cfg.MaxInFlight, defaultMaxInFlightMemory)
		}
	})

	t.Run("a chosen cap is kept", func(t *testing.T) {
		base(t, "memory")
		cfg, err := loadConfig(writeConfig(t, "memory", "max_in_flight = 7\n", ""))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxInFlight != 7 {
			t.Fatalf("MaxInFlight = %d, want the configured 7", cfg.MaxInFlight)
		}
	})

	t.Run("an explicit 0 still disables the cap", func(t *testing.T) {
		base(t, "postgres")
		cfg, err := loadConfig(writeConfig(t, "postgres", "max_in_flight = 0\n", ""))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxInFlight != 0 {
			t.Fatalf("MaxInFlight = %d, want 0 (no cap)", cfg.MaxInFlight)
		}
	})

	t.Run("the environment beats the file", func(t *testing.T) {
		base(t, "memory")
		t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "9")
		cfg, err := loadConfig(writeConfig(t, "memory", "max_in_flight = 7\n", ""))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxInFlight != 9 {
			t.Fatalf("MaxInFlight = %d, want the environment's 9", cfg.MaxInFlight)
		}
	})

	t.Run("a negative cap is refused", func(t *testing.T) {
		base(t, "memory")
		t.Setenv("RE0AUTH_MAX_IN_FLIGHT", "-2")
		if _, err := loadConfig(writeConfig(t, "memory", "", "")); err == nil {
			t.Fatal("a negative max_in_flight was accepted")
		}
	})
}
