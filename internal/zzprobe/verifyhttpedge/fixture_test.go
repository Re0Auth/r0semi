//go:build audit5

// Package verifyhttpedge holds the ADVERSARIAL VERIFIER's probes for the HTTP
// edge report (docs/audit-5/findings/http-edge.md).
//
// It contains no production code and modifies no existing file. The server here
// is built through httpapi's EXPORTED surface only (httpapi.New + Config), so it
// does not inherit a fixture bug from the report's own in-package probe file.
package verifyhttpedge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// zzNoRefill is "one token, never refilled" in practice: a second request on the
// same bucket key is refused unless that key was given a brand-new bucket.
const zzNoRefill = 0.001

type stubIntrospector struct{}

func (stubIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, errors.New("verifyhttpedge: no tokens exist here")
}

type stubGrants struct{}

func (stubGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (stubGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type stubDevices struct{}

func (stubDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, errors.New("verifyhttpedge: no device flow here")
}

func (stubDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return errors.New("verifyhttpedge: no device flow here")
}

// zzServer builds a real httpapi.Server with a limiter of one token and no
// refill, and the given trust list.
func zzServer(t *testing.T, trusted ...string) *httpapi.Server {
	t.Helper()
	return zzNew(t, true, false, trusted...)
}

// zzServerNoLimit is the same server with no limiter at all, so a walk sees the
// ROUTER's answer instead of the limiter's.
func zzServerNoLimit(t *testing.T, trusted ...string) *httpapi.Server {
	t.Helper()
	return zzNew(t, false, false, trusted...)
}

// zzServerNoLimitReal is served over a real TCP listener, so a dot-segment path is
// what an actual client can send.
func zzServerNoLimitReal(t *testing.T, trusted ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(zzNew(t, false, false, trusted...).Handler())
}

func zzNew(t *testing.T, limit, _ bool, trusted ...string) *httpapi.Server {
	t.Helper()
	var prefixes []netip.Prefix
	for _, c := range trusted {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		prefixes = append(prefixes, p)
	}
	cfg := httpapi.Config{
		Issuer:            "https://op.verify.test",
		OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		TokenIntrospector: stubIntrospector{},
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
		TrustedProxies:    prefixes,
	}
	if limit {
		cfg.Limiter = ratelimit.New(zzNoRefill, 1)
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	return srv
}

// zzPeer hands out a distinct peer per call, so one limiter can serve a walk
// without every later request inheriting an exhausted bucket.
func zzPeer() string {
	zzPeerSeq++
	return fmt.Sprintf("198.19.%d.%d:5555", zzPeerSeq/250, zzPeerSeq%250+1)
}

var zzPeerSeq int

// zzCall sends one request as the given peer, with the given X-Forwarded-For
// values, and returns the response. A non-429 answer means the limiter admitted
// the request.
func zzCall(t *testing.T, srv *httpapi.Server, peer, method, target string, xff ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = peer
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func zzAdmitted(code int) bool { return code != http.StatusTooManyRequests }
