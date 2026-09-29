//go:build audit7

// Z12-VERIFY: independent probes for zone 12. These re-derive the claimed
// mechanisms from their own fixtures rather than re-running the reporter's.
package z12verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// The three seams httpapi.New requires; none of them is reached by the paths
// under test.
type vIntrospector struct{}

func (vIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, nil
}

type vGrants struct{}

func (vGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (vGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type vDevices struct{}

func (vDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, nil
}

func (vDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return nil
}

// nan is math.NaN without importing math into the assertion path; kept local so
// the value under test is unmistakably the non-finite one.
func nan() float64 {
	z := 0.0
	return z / z
}

// TestZ12VerifyNaNInstallsAnAdmittingLimiterThroughTheRealChain takes Z12-6's
// claim — "rate_limit = NaN builds a limiter that admits everything" — and
// measures it at the layer that actually rejects: the composed handler, where a
// finite limit produces 429s. The reporter only called ratelimit.Allow in a loop;
// if the middleware refused every request for some other reason (an auth guard, a
// missing seam) the reporter's loop would still look red. This probe cannot pass
// vacuously: the finite control must produce at least one 429 through the SAME
// handler, with no limiter at all as the second control.
func TestZ12VerifyNaNInstallsAnAdmittingLimiterThroughTheRealChain(t *testing.T) {
	newServer := func(l *ratelimit.Limiter) http.Handler {
		t.Helper()
		cfg := httpapi.Config{
			Issuer:            "https://re0auth.test",
			OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }),
			TokenIntrospector: vIntrospector{},
			GrantStore:        vGrants{},
			DeviceStore:       vDevices{},
			Limiter:           l,
		}
		srv, err := httpapi.New(cfg)
		if err != nil {
			t.Fatalf("httpapi.New: %v", err)
		}
		return srv.Handler()
	}

	count := func(t *testing.T, h http.Handler, path string, n int) (ok, tooMany int) {
		t.Helper()
		ts := httptest.NewServer(h)
		defer ts.Close()
		client := &http.Client{}
		for i := 0; i < n; i++ {
			resp, err := client.Get(ts.URL + path) //nolint:gosec // loopback, test-only
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusTooManyRequests:
				tooMany++
			case http.StatusOK:
				ok++
			}
		}
		return ok, tooMany
	}

	const path = "/oauth/authorize"
	const n = 500

	// Controls: a finite bucket must shed, and no limiter must not.
	if shed := func() int { _, s := count(t, newServer(ratelimit.New(50, 100)), path, n); return s }(); shed == 0 {
		t.Fatalf("control failed: a 50/s burst-100 limiter produced no 429 in %d requests through the "+
			"composed handler, so this probe's path never reaches the limiter", n)
	} else {
		t.Logf("control: finite(50,100) shed %d of %d", shed, n)
	}
	if ok, shed := count(t, newServer(nil), path, n); shed != 0 || ok != n {
		t.Fatalf("control failed: with no limiter, %d of %d were shed (ok=%d)", shed, n, ok)
	} else {
		t.Logf("control: no limiter admitted %d of %d", ok, n)
	}

	// Subject: the limiter buildLimiter actually installs for NaN.
	ok, shed := count(t, newServer(ratelimit.New(nan(), 100)), path, n)
	t.Logf("subject: NaN(100) admitted=%d shed=%d of %d", ok, shed, n)
	if shed != 0 {
		t.Errorf("NaN did shed %d requests, so the reporter's claim does not hold at the HTTP layer", shed)
	}
	if ok != n {
		t.Errorf("NaN admitted only %d of %d requests: neither a working limiter nor a fully disabled one",
			ok, n)
	}
}
