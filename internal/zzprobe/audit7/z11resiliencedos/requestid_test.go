//go:build audit7

// Z11-3: the caller's X-Request-Id is unbounded and is copied verbatim into both
// the response header and the access log line.
//
// withRequestContext adopts `X-Request-Id` as-is (middleware.go:138-142), with no
// charset and no length cap, and withAccessLog writes it into every line
// (middleware.go:262). The HTTP server's own cap is MaxHeaderBytes = 64 KiB
// (cmd/re0auth/main.go:122), so one unauthenticated request can make the process
// read 64 KiB, echo 64 KiB, and format a ~64 KiB log line — roughly 650x the
// bytes of an ordinary request against the access log's steady state. The
// shipped rate limit (50/s, burst 100) bounds one address at ~3 MiB/s of log;
// an IPv6 /64 or a handful of addresses removes even that.
package zzprobe_z11resiliencedos

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// TestZ11ACallerChosenRequestIDIsEchoedAndLoggedInFull is red while the id is
// echoed and logged without a bound.
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

	if len(echoed) != idLen {
		t.Errorf("the response echoed %d of %d bytes of the caller's request id", len(echoed), idLen)
	}
	if !strings.Contains(logged, id) {
		t.Errorf("the access log did not carry the caller's request id in full; %d bytes of log were written",
			len(logged))
	}
	if len(logged) < idLen {
		t.Errorf("the access log line for one unauthenticated request was %d bytes (the id alone is %d): "+
			"the log grows with a caller-chosen header, with no cap between the client and the disk",
			len(logged), idLen)
	} else {
		t.Errorf("one unauthenticated request produced a %d-byte access log line by setting X-Request-Id to %d "+
			"bytes: the log is proportional to a caller-controlled header (no charset and no length cap at "+
			"middleware.go:138-142), so 50 requests/s per address is ~3 MiB/s of log and an IPv6 /64 removes "+
			"even that bound", len(logged), idLen)
	}
}
