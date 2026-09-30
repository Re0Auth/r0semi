//go:build audit7

// Z11-3: the caller's X-Request-Id is adopted only when it is a short opaque
// token (<= 128 bytes, [A-Za-z0-9._-]); anything else is replaced with a
// generated id.
//
// Before the fix `withRequestContext` (middleware.go) adopted the header
// verbatim, so its size was priced by the request: one unauthenticated 60 000
// byte header was echoed in the response header, written into the problem body
// and formatted into a ~60 000 byte access log line. The server's own
// MaxHeaderBytes = 64 KiB (cmd/re0auth/main.go) is what bounded the input, and
// the shipped rate limit bounds the resulting log only per address.
package zzprobe_z11resiliencedos

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// TestZ11ACallerChosenRequestIDIsEchoedAndLoggedInFull guards that the id is
// replaced rather than echoed. The earlier version of this probe asserted the
// vulnerable echo (`len(echoed) != idLen`) and called `t.Errorf` in both
// branches of its final check, so it could never go green; this rewrite is the
// regression guard for the fixed behaviour. The name is kept because the
// acceptance command selects the probe by it.
func TestZ11ACallerChosenRequestIDIsEchoedAndLoggedInFull(t *testing.T) {
	srv := miniAPI(t, miniConfig{})

	cap := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(cap))
	defer slog.SetDefault(prev)

	// 60000 bytes fits inside the server's 64 KiB MaxHeaderBytes with room for
	// the request line and the other headers, so it is a request the process
	// accepts rather than one it refuses.
	const idLen = 60000
	id := strings.Repeat("A", idLen)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/nowhere", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Request-Id", id)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with a %d-byte X-Request-Id: %v", idLen, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	echoed := resp.Header.Get("X-Request-Id")
	logged := cap.String()
	t.Logf("status=%d echoed=%d bytes logged=%d bytes (a normal request's line is ~150 bytes)",
		resp.StatusCode, len(echoed), len(logged))

	if len(logged) == 0 {
		t.Fatal("nothing was logged, so the log assertions below would be vacuous")
	}
	if echoed == "" {
		t.Fatal("no request id was echoed, so the header assertions below would be vacuous")
	}
	if echoed == id {
		t.Errorf("the response echoed the caller's %d-byte request id verbatim", idLen)
	}
	if !strings.HasPrefix(echoed, "req_") {
		t.Errorf("the echoed request id %q does not look generated (want the req_ prefix)", echoed)
	}
	if len(echoed) > 128 {
		t.Errorf("the echoed request id is %d bytes, want at most 128", len(echoed))
	}
	for i := 0; i < len(echoed); i++ {
		c := echoed[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			t.Fatalf("the echoed request id %q is outside the accepted charset", echoed)
		}
	}
	if strings.Contains(logged, id) {
		t.Errorf("the access log carried the caller's request id in full; %d bytes of log were written", len(logged))
	}
	if len(logged) >= idLen/10 {
		t.Errorf("one unauthenticated request produced a %d-byte access log line by setting X-Request-Id to %d "+
			"bytes: the log is proportional to a caller-controlled header, so the per-address rate limit is the only "+
			"bound and an IPv6 /64 removes even that", len(logged), idLen)
	}
}
