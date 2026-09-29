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

// Z12-6: a non-finite rate_limit is accepted by the loader and turns the limiter
// into a limiter that admits everything.
//
// config.Float (internal/config/config.go:98-108) is strconv.ParseFloat, which
// accepts "NaN", "Inf" and "+Inf"; loadConfig's only guard is
// `cfg.RateLimit < 0` (cmd/re0auth/config.go:512-522), and every comparison
// against NaN is false, so NaN walks past the negative check, past the
// `== 0` (disable) branch and past `burst < 1`. buildLimiter (main.go:224-229)
// then sees `NaN <= 0` as false and installs a limiter instead of the documented
// "0 disables it".
//
// The probe first proves the spelling is accepted by a real process, then
// measures what the resulting limiter does, using the same ratelimit package
// buildLimiter builds.
func TestZ12NonFiniteRateLimitIsAcceptedAndDisablesTheLimiter(t *testing.T) {
	// First, that the loader really accepts the spelling a deployment would use:
	// the same run with the same environment reaches the listener, so the value
	// was consumed rather than refused.
	env := serveEnv()
	env["RE0AUTH_RATE_LIMIT"] = "nan"
	got := runBinary(t, env)
	if !strings.Contains(got.out, "stage=listen") {
		t.Fatalf("RE0AUTH_RATE_LIMIT=nan was not accepted by the loader, so the finding below "+
			"does not apply to a real process:\n%s", got.out)
	}
	t.Logf("RE0AUTH_RATE_LIMIT=nan was accepted: the run reached %s", stageOf(got.out))

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

	if nanAdmitted == 1000 {
		t.Errorf("rate_limit = NaN is accepted by the configuration layer and builds a limiter that " +
			"admits every request (1000 of 1000): per-address load shedding is silently OFF, while " +
			"the same variable with 0 means \"off\" deliberately and a negative is refused. " +
			"buildLimiter's `cfg.RateLimit <= 0` is false for NaN, so a limiter is installed; " +
			"inside it the NaN never reaches rate's `limit == Inf` shortcut, so every reservation " +
			"leaves tokens=NaN and x/time/rate's comparison is false — i.e. always allowed. " +
			"The deployment's documented default (50/s) is gone and nothing says so")
		return
	}
	if nanAdmitted == 0 {
		t.Errorf("rate_limit = NaN builds a limiter that refuses every request (0 of 1000 admitted)")
		return
	}
	t.Errorf("rate_limit = NaN builds a limiter with an unspecified verdict (%d of 1000 admitted)",
		nanAdmitted)
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
