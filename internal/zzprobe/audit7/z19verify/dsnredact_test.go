//go:build audit7

package z19verify

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestZ19VDsnParseErrorRedactionBattery re-checks the positive claim zone 19
// wrote into its "probed, not broken" list:
//
//	"pgx v5.11 的 ParseConfigError.Error() 经 redactPW 脱敏，区 12 的 DSN 条目在
//	 本版本上实际泄漏面比想象的窄"
//
// Zone 12's green probe (z12dsn_test.go) drove the real binary with five DSN
// shapes. The library's own comment says redaction is "necessarily best effort"
// and "cannot guarantee redaction when malformed input makes component
// boundaries ambiguous" (pgx v5.11.0 pgconn/errors.go:233-235), so the five
// shapes are not the whole surface.
//
// This probe asks the same library the production path asks
// (internal/store/postgres/postgres.go:225 pgxpool.ParseConfig) a wider battery
// of malformed strings, and fails when the password survives into the error
// text that internal/store/postgres wraps with %w and cmd/re0auth logs at
// stage=storage (postgres.go:227, main.go:375).
//
// Each case also asserts the error really rendered the DSN (the recognisable
// host/user marker is present), so a vacuous "no password" cannot pass.
func TestZ19VDsnParseErrorRedactionBattery(t *testing.T) {
	const pw = "Z19V-DSN-PASSWORD-5f3a"
	const user = "z19vuser"

	cases := []struct {
		name string
		dsn  string
		// marker must appear in the error for the case to count as observed.
		marker string
	}{
		{"userinfo without an at-sign", "postgres://" + user + ":" + pw, user},
		{"userinfo, at-sign, no host", "postgres://" + user + ":" + pw + "@", user},
		{"userinfo, empty host and path", "postgres://" + user + ":" + pw + "@/", user},
		{"keyword/value, unquoted", "host=h " + user + "=x password=" + pw, pw},
		{"keyword/value, quoted", "host=h password='" + pw + "'", pw},
		{"keyword/value, password with a space", "host=h password=" + pw + " trailing", pw},
		{"keyword/value, password after a newline", "host=h\npassword=" + pw, pw},
		{"URI with a query password and a bad port", "postgres://" + user + "@127.0.0.1:notaport/db?password=" + pw, pw},
		{"URI with a stranded at-sign in the password", "postgres://" + user + ":" + pw + "@@127.0.0.1:1/db", pw},
		{"URI with a slash inside the password", "postgres://" + user + ":" + pw + "/x@127.0.0.1:1/db", pw},
		{"URI with a question mark inside the password", "postgres://" + user + ":" + pw + "?x=y@127.0.0.1:1/db", pw},
		{"URI with no scheme separator", "postgres:" + user + ":" + pw + "@127.0.0.1:1/db", pw},
		{"scheme repeated", "postgres://postgres://" + user + ":" + pw + "@h/db", pw},
		{"URI password with an encoded colon", "postgres://" + user + ":" + pw + "%3Amore@127.0.0.1:1/db", pw},
		{"URI password with a percent that cannot decode", "postgres://" + user + ":" + pw + "%zz@127.0.0.1:1/db", pw},
		{"trailing newline after a good URI", "postgres://" + user + ":" + pw + "@127.0.0.1:1/db\n", pw},
		{"leading space before the scheme", " postgres://" + user + ":" + pw + "@127.0.0.1:1/db", pw},
		{"no scheme at all", user + ":" + pw + "@127.0.0.1:1/db", pw},
		{"bare userinfo", user + ":" + pw, pw},
		{"keyword/value without the equals", "host=h password " + pw, pw},
		{"keyword/value with an empty host", "host= port= user=" + user + " password=" + pw, pw},
	}

	observed := 0
	leaked := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pgxpool.ParseConfig(tc.dsn)
			if err == nil {
				// Parsing succeeded: nothing is echoed, and no dial is made here.
				t.Logf("accepted (no error text to inspect): %q", tc.dsn)
				return
			}
			text := err.Error()
			if !strings.Contains(text, tc.marker) {
				t.Logf("the error did not render the DSN at all, so this case observes nothing: %v", err)
				return
			}
			observed++
			if strings.Contains(text, pw) {
				leaked++
				t.Errorf("DISCLOSURE: pgxpool.ParseConfig echoed the DSN password. "+
					"internal/store/postgres/postgres.go:225-227 wraps this error with %%w and "+
					"cmd/re0auth/main.go:375 logs it at stage=storage, so this reaches the startup log.\nDSN:   %s\nerror: %s", tc.dsn, text)
			} else {
				t.Logf("redacted: %v", err)
			}
		})
	}
	if observed == 0 {
		t.Fatal("no case produced an error that rendered the DSN: the battery observed nothing")
	}
	t.Logf("%d of %d cases rendered the DSN in the error; %d of those carried the password",
		observed, len(cases), leaked)
}
