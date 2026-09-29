//go:build audit7

package z19verify

import (
	"strings"
	"testing"
)

// TestZ19VHostlessDsnPasswordReachesTheStartupLog is the black-box half of
// TestZ19VDsnParseErrorRedactionBattery: the real binary, the real composition
// root, the real stage=storage log line.
//
// cmd/re0auth resolves storage.dsn_env (or DATABASE_URL) and hands the string to
// postgres.Open, which calls pgxpool.ParseConfig
// (internal/store/postgres/postgres.go:225). pgx v5.11.0's ParseConfigError
// redacts a password only in the positions its own heuristics recognise; a
// userinfo password with no '@' has no recognised position, so redactPW copies
// the string through verbatim (pgconn/errors.go:236-246) and the error text
// becomes `cannot parse \`<dsn>\`: invalid port`.
//
// The control is the shape zone 12's green probe already covered: the same
// password with an '@' and a host is masked.
func TestZ19VHostlessDsnPasswordReachesTheStartupLog(t *testing.T) {
	const pw = "Z19V-HOSTLESS-DSN-PASSWORD-a71c"
	const user = "z19vuser"

	common := map[string]string{
		"RE0AUTH_ISSUER":           "https://re0auth.test",
		"RE0AUTH_COOKIE_SECURE":    "true",
		"RE0AUTH_KEK":              key32("Z19V-KEK-MATERIAL-32-BYTES-AA"),
		"RE0AUTH_AUDIT_KEY":        key32("Z19V-AUDIT-KEY-MATERIAL-32-BB"),
		"RE0AUTH_OIDC_TOKEN_KEY":   key32("Z19V-OP-TOKEN-KEY-MATERIAL-32C"),
		"RE0AUTH_OIDC_SIGNING_KEY": signingKey,
		"RE0AUTH_ADDR":             "not-an-address",
		"RE0AUTH_STORAGE_DRIVER":   "postgres",
	}

	run := func(t *testing.T, dsn string) runResult {
		t.Helper()
		env := map[string]string{"DATABASE_URL": dsn}
		for k, v := range common {
			env[k] = v
		}
		return runBinary(t, env)
	}

	// Control: the shape zone 12 covered. The run reaches the storage stage and
	// the password is masked.
	ctrl := run(t, "postgres://"+user+":"+pw+"@127.0.0.1:notaport/db")
	if !strings.Contains(ctrl.out, "stage=storage") {
		t.Fatalf("control never reached the storage stage, so the probe observes nothing:\n%s", ctrl.out)
	}
	if strings.Contains(ctrl.out, pw) {
		t.Fatalf("control is wrong: the @-host shape echoed the password:\n%s", ctrl.out)
	}
	t.Logf("control (user@host shape) masked the password: %s", lastLine(ctrl.out))

	// Subject: userinfo with no '@' and no host.
	got := run(t, "postgres://"+user+":"+pw)
	if !strings.Contains(got.out, "stage=storage") {
		t.Fatalf("the subject run never reached the storage stage:\n%s", got.out)
	}
	if strings.Contains(got.out, pw) {
		t.Errorf("DISCLOSURE: a DSN whose userinfo has no '@' is echoed verbatim into the "+
			"stage=storage startup log, password included (exit=%d):\n%s", got.code, got.out)
	} else {
		t.Logf("the hostless shape did not echo the password: %s", lastLine(got.out))
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}
