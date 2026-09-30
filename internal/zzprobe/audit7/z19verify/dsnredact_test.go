//go:build audit7

package z19verify

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/internal/store/postgres"
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
// The probe originally asked pgxpool.ParseConfig directly. That is the wrong
// place to assert: the library's behaviour is not ours to fix, and the finding is
// about the STARTUP LOG. The assertion now sits at the boundary the process
// actually uses — postgres.Open (internal/store/postgres/postgres.go), which is
// what cmd/re0auth calls and whose error reaches stage=storage — so a shape pgx
// itself leaks must still not reach the log. Each case is run through
// pgxpool.ParseConfig as well, both to observe the library leak (anti-vacuity:
// if the library stops leaking, this probe has nothing left to test and says so)
// and to skip the shapes that parse.
func TestZ19VDsnParseErrorRedactionBattery(t *testing.T) {
	const pw = "Z19V-DSN-PASSWORD-5f3a"
	const user = "z19vuser"

	cases := []struct {
		name string
		dsn  string
	}{
		{"userinfo without an at-sign", "postgres://" + user + ":" + pw},
		{"userinfo, at-sign, no host", "postgres://" + user + ":" + pw + "@"},
		{"userinfo, empty host and path", "postgres://" + user + ":" + pw + "@/"},
		{"keyword/value, unquoted", "host=h " + user + "=x password=" + pw},
		{"keyword/value, quoted", "host=h password='" + pw + "'"},
		{"keyword/value, password with a space", "host=h password=" + pw + " trailing"},
		{"keyword/value, password after a newline", "host=h\npassword=" + pw},
		{"URI with a query password and a bad port", "postgres://" + user + "@127.0.0.1:notaport/db?password=" + pw},
		{"URI with a stranded at-sign in the password", "postgres://" + user + ":" + pw + "@@127.0.0.1:1/db"},
		{"URI with a slash inside the password", "postgres://" + user + ":" + pw + "/x@127.0.0.1:1/db"},
		{"URI with a question mark inside the password", "postgres://" + user + ":" + pw + "?x=y@127.0.0.1:1/db"},
		{"URI with no scheme separator", "postgres:" + user + ":" + pw + "@127.0.0.1:1/db"},
		{"scheme repeated", "postgres://postgres://" + user + ":" + pw + "@h/db"},
		{"URI password with an encoded colon", "postgres://" + user + ":" + pw + "%3Amore@127.0.0.1:1/db"},
		{"URI password with a percent that cannot decode", "postgres://" + user + ":" + pw + "%zz@127.0.0.1:1/db"},
		{"trailing newline after a good URI", "postgres://" + user + ":" + pw + "@127.0.0.1:1/db\n"},
		{"leading space before the scheme", " postgres://" + user + ":" + pw + "@127.0.0.1:1/db"},
		{"no scheme at all", user + ":" + pw + "@127.0.0.1:1/db"},
		{"bare userinfo", user + ":" + pw},
		{"keyword/value without the equals", "host=h password " + pw},
		{"keyword/value with an empty host", "host= port= user=" + user + " password=" + pw},
	}

	ctx := context.Background()
	observed, leaked, libraryLeaks := 0, 0, 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, perr := pgxpool.ParseConfig(tc.dsn); perr == nil {
				// Parsing succeeded: there is no error text to inspect, and Open
				// would go on to dial, so this case observes nothing.
				t.Logf("accepted (no error text to inspect): %q", tc.dsn)
				return
			} else if strings.Contains(perr.Error(), pw) {
				libraryLeaks++
			}

			// The boundary the process uses. An unparseable DSN is refused before
			// any connection is attempted, so this does no I/O.
			_, err := postgres.Open(ctx, tc.dsn, postgres.DefaultPoolOptions())
			if err == nil {
				t.Fatalf("the boundary accepted a DSN the driver refused: %q", tc.dsn)
			}
			text := err.Error()
			if !strings.Contains(text, "postgres: parse dsn") {
				// Some other refusal (pool/connect); not the path under test.
				t.Logf("boundary error was not the parse refusal: %v", err)
				return
			}
			observed++
			if strings.Contains(text, pw) {
				leaked++
				t.Errorf("DISCLOSURE: the DSN password survives into the error postgres.Open "+
					"returns, which cmd/re0auth logs at stage=storage.\nDSN:   %s\nerror: %s", tc.dsn, text)
			} else {
				t.Logf("redacted: %v", err)
			}
		})
	}
	if observed == 0 {
		t.Fatal("no case reached the boundary's parse refusal: the battery observed nothing")
	}
	if libraryLeaks == 0 {
		t.Fatal("pgxpool.ParseConfig leaked the password in no case: the battery no longer " +
			"exercises the ambiguous shapes it exists for, so re-read this probe")
	}
	t.Logf("%d of %d cases reached the parse refusal; %d of those leaked; pgx itself leaked in %d cases",
		observed, len(cases), leaked, libraryLeaks)
}
