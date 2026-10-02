//go:build audit || audit6

package httpapi

// Audit probes (round 6), rewritten as regression guards for Z07-3.
//
// The chain under test is entirely in production code:
//
//	GET /v1/device/verification?user_code=<anything that normalizes to a live code>
//	  -> httpapi/device_routes.go:59  oauth.NormalizeUserCode(query)      <-- Z07-3
//	  -> oauth.device.DescribeDeviceAuthorization / memory.OIDCStore.DescribeDeviceAuthorization
//	     returns oauth.DeviceAuthorization{UserCode: oauth.NormalizeUserCode(...)}
//	       (internal/store/memory/oidc.go:1799)                          <-- Z07-3
//	  -> httpapi/device_routes.go:72  sessions.Bind(ctx, deviceBindKind, auth.UserCode)
//
// Original round-6 findings:
//
//	Z07-3: the page bound and echoed the caller's own spelling, so one code had
//	       unboundedly many session handles: 32 navigations piled ~1.8 MiB into a
//	       single browser session (docs/issues/P2-medium.md:37).
//	Z07-5: the decision endpoint required the caller's exact spelling while the
//	       lookup normalised, so one device code had two answers
//	       (docs/issues/_fragments/round7.md:68).
//
// Both are fixed: the canonical (uppercase, separator-stripped) spelling is the
// only handle, and device_routes.go:113 normalises the decision body too.
// docs/issues/fixed.md:47 pins the policy — "句柄只绑定规范化后的码（两 store
// 返回、页面回显、决策路径规范化），auth.Manager.Bind 加 128 字节上限".
//
// These two tests keep their original names but now guard the fixed behaviour.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
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

// TestZZAuditDeviceVerificationStoresTheRawRequestString — 原为发现演示，现为
// Z07-3 回归守卫。
//
// The old demonstration proved the page stored byte-for-byte what the caller put
// in the query. The fix made the canonical spelling the only handle, so the guard
// is the opposite: every accepted spelling resolves to that one canonical handle,
// and the raw request bytes are neither echoed nor bound.
func TestZZAuditDeviceVerificationStoresTheRawRequestString(t *testing.T) {
	sessions := newRecordingSessions()
	base, _, _ := newFlowEnvWithOptions(t, flowEnvOptions{SessionStore: sessions})

	start := decodeResp(t, postForm(t, newBrowser(t), base+"/oauth/device_authorization",
		url.Values{"client_id": {"cli"}, "scope": {"account.id"}}))
	code, _ := start["user_code"].(string)
	if code == "" {
		t.Fatalf("no user_code: %v", start)
	}
	canonical := oauth.NormalizeUserCode(code)
	t.Logf("issued user_code = %q (canonical %q)", code, canonical)

	// A different spelling of the SAME code: normalization strips '-' and
	// upper-cases, so this must be accepted — and it must resolve to the
	// canonical handle rather than become one of its own.
	padded := strings.Join(strings.Split(code, ""), "-")
	if padded == canonical {
		t.Fatalf("probe is broken: padded spelling %q equals the canonical spelling", padded)
	}
	victim := newBrowser(t)
	signInAs(t, victim, base, "v")
	view := decodeResp(t, getURL(t, victim, base+"/v1/device/verification?user_code="+url.QueryEscape(padded)))
	if view["state"] != "pending" {
		t.Fatalf("padded spelling was not accepted: %v", view)
	}
	echoed, _ := view["user_code"].(string)
	t.Logf("bound user_code  = %q", echoed)
	if echoed != canonical {
		t.Errorf("the response echoed %q, want the canonical value %q", echoed, canonical)
	}
	if echoed == padded {
		t.Errorf("the response echoed the raw request spelling %q", padded)
	}
	if !sessions.holds("handle_device_" + canonical) {
		t.Errorf("the session does not carry the canonical handle %q", canonical)
	}
	if sessions.holds("handle_device_" + padded) {
		t.Errorf("the session carries a handle for the raw request spelling %q", padded)
	}
}

// TestZZAuditDeviceVerificationInflatesTheSession — 原为发现演示，现为 Z07-3
// 回归守卫。
//
// The old demonstration measured the amplification: a request of N bytes bought
// ~3N bytes of session, once per spelling. The fix normalises before binding and
// caps the bound id, so the guard measures the absence of amplification: the
// session grows by a small constant that does not depend on the request line, and
// 32 spellings of one code leave exactly one handle.
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
	// can carry a user_code of about 60 KiB. That was the per-handle budget; the
	// guard drives that same size through the page.
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

	// The bound handle is the canonical code, not the 60 KiB spelling.
	if !sessions.holds("handle_device_" + oauth.NormalizeUserCode(code)) {
		t.Errorf("the canonical handle was not bound")
	}
	if sessions.holds("handle_device_" + strings.Repeat("-", pad) + code) {
		t.Errorf("a padded spelling became its own session handle")
	}
	// A 60 KiB request may not buy anything close to 60 KiB of session. The
	// session carries a few short keys plus the canonical handle; 4 KiB is a
	// generous ceiling that the amplification could never satisfy.
	if grew := one - empty; grew > 4<<10 {
		t.Errorf("one %d-byte navigation grew the session by %d bytes", pad, grew)
	}

	// 32 distinct-length spellings of the SAME code: all normalize to one handle,
	// so the session must not accumulate anything.
	for i := 2; i <= 32; i++ {
		visit(i * 1024)
	}
	sizes := sessions.sessionLens()
	total := sessions.totalBytes()
	t.Logf("after 32 navigations (all <= %d bytes): session blob(s) = %v (total %d bytes)", pad, sizes, total)

	if len(sizes) != 1 {
		t.Errorf("%d session blobs were committed; one browser must hold one", len(sizes))
	}
	if total != one {
		t.Errorf("32 navigations grew the session from %d to %d bytes", one, total)
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
