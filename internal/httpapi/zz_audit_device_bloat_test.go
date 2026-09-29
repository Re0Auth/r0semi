//go:build audit || audit6

package httpapi

// Audit probe (round 6): how large can one session be made from the device
// verification page?
//
// The chain under test is entirely in production code:
//
//	GET /v1/device/verification?user_code=<anything that normalizes to a live code>
//	  -> oauth.device.DescribeDeviceAuthorization / memory.OIDCStore.DescribeDeviceAuthorization
//	     returns oauth.DeviceAuthorization{UserCode: userCode}   <-- the RAW request value
//	  -> httpapi.device_routes.go:69  sessions.Bind(ctx, deviceBindKind, auth.UserCode)
//	  -> auth.Manager.Bind writes handle_device_<raw>, owner_device_<raw> and one
//	     entry in the boundq_device queue.
//
// normalizeUserCode (memory/oidc.go:850) strips '-' and upper-cases, so one code
// has unboundedly many spellings; each distinct spelling is a distinct handle.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// sessionLens reports the byte length of every committed session blob.
func (s *recordingSessions) sessionLens() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, len(s.data))
	for _, b := range s.data {
		out = append(out, len(b))
	}
	return out
}

func (s *recordingSessions) totalBytes() int {
	total := 0
	for _, n := range s.sessionLens() {
		total += n
	}
	return total
}

// TestZZAuditDeviceVerificationStoresTheRawRequestString pins the entry point:
// the handle that is bound is byte-for-byte what the caller put in the query.
func TestZZAuditDeviceVerificationStoresTheRawRequestString(t *testing.T) {
	sessions := newRecordingSessions()
	base, _, _ := newFlowEnvWithOptions(t, flowEnvOptions{SessionStore: sessions})

	start := decodeResp(t, postForm(t, newBrowser(t), base+"/oauth/device_authorization",
		url.Values{"client_id": {"cli"}, "scope": {"account.id"}}))
	code, _ := start["user_code"].(string)
	if code == "" {
		t.Fatalf("no user_code: %v", start)
	}
	t.Logf("issued user_code = %q", code)

	// A different spelling of the SAME code: normalization strips '-' and
	// upper-cases, so this must be accepted and must be what gets bound.
	padded := strings.Join(strings.Split(code, ""), "-")
	victim := newBrowser(t)
	signInAs(t, victim, base, "v")
	view := decodeResp(t, getURL(t, victim, base+"/v1/device/verification?user_code="+url.QueryEscape(padded)))
	if view["state"] != "pending" {
		t.Fatalf("padded spelling was not accepted: %v", view)
	}
	echoed, _ := view["user_code"].(string)
	t.Logf("bound user_code  = %q", echoed)
	if echoed != padded {
		t.Fatalf("the response echoed %q, want the raw request value %q", echoed, padded)
	}
	if !sessions.holds("handle_device_" + padded) {
		t.Fatalf("the session does not carry the padded spelling")
	}
}

// TestZZAuditDeviceVerificationInflatesTheSession measures the amplification: a
// request of N bytes buys ~3N bytes of session, per spelling, and the session is
// re-committed whole on every later request (auth.Manager sets IdleTimeout>0).
func TestZZAuditDeviceVerificationInflatesTheSession(t *testing.T) {
	sessions := newRecordingSessions()
	base, _, _ := newFlowEnvWithOptions(t, flowEnvOptions{SessionStore: sessions})

	start := decodeResp(t, postForm(t, newBrowser(t), base+"/oauth/device_authorization",
		url.Values{"client_id": {"cli"}, "scope": {"account.id"}}))
	code, _ := start["user_code"].(string)
	if code == "" {
		t.Fatalf("no user_code: %v", start)
	}

	victim := newBrowser(t)
	signInAs(t, victim, base, "v")

	// cmd/re0auth/main.go:122 sets MaxHeaderBytes to 64 KiB, so each navigation
	// can carry a user_code of about 60 KiB. That is the per-handle budget.
	const pad = 60 << 10
	empty := sessions.totalBytes()

	visit := func(n int) {
		t.Helper()
		spelling := strings.Repeat("-", n) + code
		resp := getURL(t, victim, base+"/v1/device/verification?user_code="+url.QueryEscape(spelling))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("padded verification (%d dashes) = %d: %s", n, resp.StatusCode, readAllString(resp))
		}
		resp.Body.Close()
	}

	// One navigation of the maximum production size.
	visit(pad)
	one := sessions.totalBytes()
	t.Logf("one %d-byte navigation -> session blob %d bytes (was %d)", pad, one, empty)

	// The cap is 32 handles per kind, and every spelling is a distinct handle.
	for i := 2; i <= 32; i++ {
		visit(i * 1024) // distinct lengths => distinct spellings of the same code
	}
	sizes := sessions.sessionLens()
	total := sessions.totalBytes()
	t.Logf("after 32 navigations (all <= %d bytes): session blob(s) = %v (total %d bytes)", pad, sizes, total)

	if one < 3*pad/2 {
		t.Errorf("one navigation bought only %d bytes of session, expected ~3x its %d-byte code", one, pad)
	}
	if total < 3<<20 {
		t.Errorf("32 navigations produced only %d bytes of session", total)
	}
	if !sessions.holds("boundq_device") {
		t.Error("no handle queue was committed; the probe measured something else")
	}
}

func readAllString(resp *http.Response) string {
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return sb.String()
		}
	}
}
