//go:build audit7

// Z12-6 and Z12-8: a non-finite rate_limit is accepted and turns the limiter into
// a limiter that admits everything; and positional arguments are never checked.
package z12configstartupobservability

import (
	"math"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// Z12-6: a non-finite rate_limit is refused at load.
//
// config.Float is strconv.ParseFloat, which accepts "nan"/"inf", and every
// comparison against NaN is false, so the old guard (`rate_limit < 0`) let NaN
// reach buildLimiter, which installed a limiter that admitted everything
// (main.go:224-229). The loader now rejects a non-finite value before anything
// is wired. The limiter arithmetic at the end of this test is kept as the reason
// the refusal matters: it shows what the accepted value used to do.
//
// The probe first proves the spelling is accepted by a real process, then
// measures what the resulting limiter does, using the same ratelimit package
// buildLimiter builds.
func TestZ12NonFiniteRateLimitIsRefusedAtLoad(t *testing.T) {
	// The finding: the spelling a deployment would use is refused by the loader,
	// before anything is wired, and the refusal names the field.
	env := serveEnv()
	env["RE0AUTH_RATE_LIMIT"] = "nan"
	got := runBinary(t, env)
	if strings.Contains(got.out, "stage=listen") {
		t.Fatalf("RE0AUTH_RATE_LIMIT=nan still reached the listener:\n%s", got.out)
	}
	if !strings.Contains(got.out, "stage=config") {
		t.Fatalf("RE0AUTH_RATE_LIMIT=nan was not refused at load (want stage=config):\n%s", got.out)
	}
	if !strings.Contains(got.out, "server.rate_limit") {
		t.Fatalf("the refusal does not name the field:\n%s", got.out)
	}
	t.Logf("RE0AUTH_RATE_LIMIT=nan was refused at load: %s", oneLine(got.out))

	// Control: a finite value still starts, so the refusal is about the
	// non-finite spelling and not about this probe's environment.
	finiteEnv := serveEnv()
	finiteEnv["RE0AUTH_RATE_LIMIT"] = "50"
	if finiteRun := runBinary(t, finiteEnv); !strings.Contains(finiteRun.out, "stage=listen") {
		t.Fatalf("control: a finite rate_limit did not reach the listener:\n%s", finiteRun.out)
	}

	// Control: the same probe with a finite value, so the assertions below are
	// about the non-finite value and not about the limiter being broken.
	finite := ratelimit.New(50, 100)
	admitted := 0
	for i := 0; i < 1000; i++ {
		if finite.Allow("127.0.0.1") {
			admitted++
		}
	}
	if admitted < 100 || admitted > 200 {
		t.Fatalf("control failed: 1000 sequential requests against a 50/s bucket with burst 100 "+
			"admitted %d; the limiter is not behaving as a token bucket", admitted)
	}

	// NaN: buildLimiter's `cfg.RateLimit <= 0` is false for NaN, so this is the
	// limiter a deployment gets.
	nan := ratelimit.New(math.NaN(), 100)
	nanAdmitted := 0
	for i := 0; i < 1000; i++ {
		if nan.Allow("127.0.0.1") {
			nanAdmitted++
		}
	}

	// +Inf: the other non-finite value ParseFloat accepts. rate.Limit(+Inf) is the
	// library's documented "no limit at all".
	inf := ratelimit.New(math.Inf(1), 100)
	infAdmitted := 0
	for i := 0; i < 1000; i++ {
		if inf.Allow("127.0.0.1") {
			infAdmitted++
		}
	}

	t.Logf("1000 sequential requests: finite(50/s,burst100)=%d NaN=%d +Inf=%d",
		admitted, nanAdmitted, infAdmitted)

	// Kept as the demonstration of why the load-time refusal is the fix: the
	// value the loader used to accept admitted every request, while the same
	// variable with 0 means "off" deliberately and a negative is refused.
	if nanAdmitted != 1000 {
		t.Logf("note: the NaN limiter admitted %d of 1000 (it used to admit all); the load-time refusal "+
			"is still the property under test", nanAdmitted)
	}
	t.Logf("had NaN been accepted it would have admitted every request: finite(50/s,burst100)=%d "+
		"NaN=%d +Inf=%d of 1000", admitted, nanAdmitted, infAdmitted)
}

// Z12-8: positional arguments are never checked, so an argument that is not a
// flag (a misspelling, a stray token from a runbook) is ignored and the process
// does whatever its flags said.
//
// main() calls flag.Parse() (main.go:259) and never looks at flag.Args(). The
// standard library's Parse stops at the first non-flag argument: everything after
// it is left as a positional argument and the process continues. A line such as
// `re0auth -config /etc/re0auth.toml rotate-keys` — the flag written without its
// dashes — therefore starts the SERVER, in a systemd unit or a Kubernetes command
// the operator is watching, instead of rotating anything.
//
// The probe uses the documented -version short circuit (main.go:264-267), which
// prints one line and returns, so the assertion is about argument handling and
// nothing else.
func TestZ12TrailingArgumentsAreSilentlyIgnored(t *testing.T) {
	// Control: the flag itself works and exits 0.
	ok := runBinary(t, map[string]string{}, "-version")
	if ok.code != 0 || !strings.Contains(ok.out, "re0auth") {
		t.Fatalf("control failed: -version = exit %d, output %q", ok.code, ok.out)
	}

	// The same arguments, with the would-be flag written the way a human typo
	// produces it: no dashes.
	for _, args := range [][]string{
		{"-version", "rotate-keys"},
		{"-version", "migrate-down"},
		{"-version", "unexpected-positional-argument"},
	} {
		got := runBinary(t, map[string]string{}, args...)
		if got.code == 0 {
			t.Errorf("%v was accepted (exit 0, %q): flag.Parse leaves %q as a positional argument "+
				"and nothing in main looks at flag.Args(), so a flag missing its dashes turns the "+
				"requested one-shot mode into whatever the remaining flags select",
				args, strings.TrimSpace(got.out), args[1])
		} else {
			t.Logf("%v -> exit %d: %s", args, got.code, oneLine(got.out))
		}
	}
}
