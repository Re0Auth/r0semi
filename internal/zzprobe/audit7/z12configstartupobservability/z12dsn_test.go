//go:build audit7

// Guard: the connection string is not echoed, even when the driver's own error
// names the host it failed to reach.
package z12configstartupobservability

import (
	"strings"
	"testing"
)

// Guard: the connection string is echoed by the driver's own error, so a password
// in DATABASE_URL reaches the startup log.
//
// The config schema is careful never to hold a secret ("the file names the
// environment variable that holds it"), and loadConfig itself never prints the
// DSN — but internal/store/postgres wraps the driver's parse/connect error with
// %w, and both pgx and net/url quote the string they were given. A parse failure
// would therefore report the DSN, password included — so this probe exists to fail
// the day that happens.
//
// No database is needed: the well-formed-but-unreachable case is a connection
// refusal and the malformed cases fail before any dial.
func TestZ12DSNPasswordIsNotEchoedIntoTheStartupLog(t *testing.T) {
	const password = "Z12-DSN-PASSWORD-SECRET-9931"

	common := map[string]string{
		"RE0AUTH_ISSUER":                  "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE":           "true",
		"RE0AUTH_KEK":                     key32("Z12-KEK-MATERIAL-32-BYTES-BBB!"),
		"RE0AUTH_AUDIT_KEY":               key32("Z12-AUDIT-KEY-MATERIAL-32B!!"),
		"RE0AUTH_ADDR":                    "not-an-address",
		"RE0AUTH_STORAGE_DRIVER":          "postgres",
		"RE0AUTH_STORAGE_CONNECT_TIMEOUT": "1s",
	}

	cases := []struct {
		name string
		dsn  string
	}{
		{"well-formed but unreachable", "postgres://z12user:" + password + "@127.0.0.1:1/z12db?sslmode=disable"},
		{"port that is not a number", "postgres://z12user:" + password + "@127.0.0.1:notaport/z12db"},
		{"scheme with no host", "postgres://z12user:" + password + "@/z12db"},
		{"unknown scheme", "mysql://z12user:" + password + "@127.0.0.1:1/z12db"},
		{"keyword/value with a bad key", "host=127.0.0.1 password=" + password + " z12badkey=1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range common {
				env[k] = v
			}
			env["DATABASE_URL"] = tc.dsn

			got := runBinary(t, env)
			if !strings.Contains(got.out, "stage=storage") {
				t.Fatalf("the run never reached the storage stage, so this probe observed nothing:\n%s", got.out)
			}
			if strings.Contains(got.out, password) {
				t.Errorf("the DSN password was printed into the startup log (exit=%d):\n%s", got.code, got.out)
			} else {
				t.Logf("no leak for %q", tc.name)
			}
		})
	}
}
