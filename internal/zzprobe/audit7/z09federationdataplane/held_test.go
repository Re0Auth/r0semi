//go:build audit7

// Guards for area Z09: attacks that were tried against the real HTTP surface and
// did NOT get through. Each one keeps a "the boundary holds" claim from being an
// assumption, and two of them re-check a previous round's verdict.
package zzprobe_z09federationdataplane

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

// probeUpstream is a real upstream that records what it was asked and answers a
// fixed body.
type probeUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	uris []string
	hdrs []http.Header
	n    atomic.Int64
}

func newProbeUpstream(t *testing.T, status int, ct, body string, extra http.Header) *probeUpstream {
	t.Helper()
	p := &probeUpstream{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.uris = append(p.uris, r.URL.RequestURI())
		p.hdrs = append(p.hdrs, r.Header.Clone())
		p.mu.Unlock()
		p.n.Add(1)
		for k, v := range extra {
			for _, one := range v {
				w.Header().Add(k, one)
			}
		}
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *probeUpstream) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.uris...)
}

func (p *probeUpstream) headers() []http.Header {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]http.Header(nil), p.hdrs...)
}

func zzRegistryFor(t *testing.T, up string, raw bool) *federation.Registry {
	t.Helper()
	src := federation.Source{
		Game: zzGame, Name: "src", DisplayName: "Src", Issuer: up,
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzProfileScope},
		},
	}
	if raw {
		src.RawBase = up + "/native"
	}
	reg, err := federation.NewRegistry(src)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// An upstream-issued access token is attacker-influenced content: it is whatever
// the source put in its token response. If it reaches `Header.Set("Authorization",
// "Bearer "+token)` with a CRLF in it, the next header would be the source's.
func TestZ09AnUpstreamTokenCannotInjectAHeader(t *testing.T) {
	up := newProbeUpstream(t, http.StatusOK, "application/json", `{"ok":true}`, nil)
	reg := zzRegistryFor(t, up.URL, false)
	srv, mint := zzHarness(t, reg, []zzBind{
		{User: "usr_v", Game: zzGame, Source: "src", Access: "tok\r\nX-Injected: 1"},
	}, nil)
	at := mint("usr_v", zzProfileScope)

	code, _, _ := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/profile", at)
	t.Logf("fetch with a CRLF-bearing upstream token => %d, upstream requests: %v", code, up.requests())
	for _, h := range up.headers() {
		if h.Get("X-Injected") != "" {
			t.Errorf("the token injected a header into the outbound request: X-Injected=%q", h.Get("X-Injected"))
		}
		if strings.ContainsAny(h.Get("Authorization"), "\r\n") {
			t.Errorf("a newline reached the outbound Authorization header: %q", h.Get("Authorization"))
		}
	}
	if len(up.requests()) > 0 && code != http.StatusOK {
		t.Errorf("the upstream was reached (%v) but the caller got %d: unexpected shape", up.requests(), code)
	}
}

// The raw proxy attaches the upstream's media type to THIS origin. What else of
// the upstream's response may travel with it?
func TestZ09RawResponseDoesNotLeakTheSourcesHeaders(t *testing.T) {
	extra := http.Header{
		"Set-Cookie":                  {"sid=upstream-secret"},
		"Location":                    {"https://evil.example/next"},
		"Access-Control-Allow-Origin": {"*"},
		"X-Upstream-Internal":         {"10.0.0.5"},
		"Content-Encoding":            {"identity"},
	}
	up := newProbeUpstream(t, http.StatusOK, "text/plain", "hello", extra)
	reg := zzRegistryFor(t, up.URL, true)
	srv, mint := zzHarness(t, reg, []zzBind{
		{User: "usr_v", Game: zzGame, Source: "src", Access: "tok"},
	}, nil)
	at := mint("usr_v", oauth.RawScope(zzGame))

	code, hdr, body := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/sources/src/raw/data", at)
	t.Logf("raw => %d content-type=%q cache-control=%q body=%q",
		code, hdr.Get("Content-Type"), hdr.Get("Cache-Control"), body)
	if code != http.StatusOK {
		t.Fatalf("raw = %d, want 200 (the probe needs the success path)", code)
	}
	for _, h := range []string{"Set-Cookie", "Location", "Access-Control-Allow-Origin", "X-Upstream-Internal"} {
		if got := hdr.Values(h); len(got) > 0 {
			t.Errorf("the upstream's %s reached the downstream response: %v", h, got)
		}
	}
	if hdr.Get("Content-Type") != "text/plain" {
		t.Errorf("the upstream's media type should be passed through verbatim; got %q", hdr.Get("Content-Type"))
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", hdr.Get("Cache-Control"))
	}
}

// The raw path is joined to an operator-configured base. Every payload here was
// expected to be refused outright or to stay inside the base prefix.
//
// The last three are a CORRECTION to the round-5 federation report, which recorded
// "`?` / `#` cannot be injected" on the strength of `url.PathEscape`. rawFetch does
// NOT escape the cleaned path (service.go: `endpoint += "/" + cleaned`), so a
// percent-encoded `?` in the wildcard segment becomes a real query delimiter in the
// outbound request. The host and the base prefix are unchanged, which is why it is
// recorded as held rather than as a finding: the caller already controls the query
// string (`RawRequest.Query` is the raw r.URL.Query()).
func TestZ09RawPathCannotEscapeTheSourcesBase(t *testing.T) {
	up := newProbeUpstream(t, http.StatusOK, "text/plain", "raw", nil)
	reg := zzRegistryFor(t, up.URL, true)
	srv, mint := zzHarness(t, reg, []zzBind{
		{User: "usr_v", Game: zzGame, Source: "src", Access: "tok"},
	}, nil)
	at := mint("usr_v", oauth.RawScope(zzGame))

	cases := []struct {
		payload string
		refused bool
	}{
		{"..%2f..%2fadmin", true},
		{"%252e%252e%252fadmin", true},
		{"..%5c..%5cadmin", true},
		{"..;/admin", true},
		{"x%3Fy=1", false},
		{"%2F%2Fevil.example%2Fx", false},
		{"http:%2F%2Fevil.example%2Fx", false},
		{"@evil.example%2Fx", false},
	}
	for _, tc := range cases {
		before := len(up.requests())
		code, _, _ := zzGet(t, srv.Client(),
			srv.URL+"/v1/games/"+zzGame+"/sources/src/raw/"+tc.payload, at)
		after := up.requests()
		t.Logf("raw/%s => %d, upstream saw %v", tc.payload, code, after[before:])
		if tc.refused {
			if code != http.StatusBadRequest {
				t.Errorf("raw/%s => %d, want 400 (the path guard refuses it)", tc.payload, code)
			}
			if len(after) != before {
				t.Errorf("raw/%s reached the upstream (%v) although it must be refused", tc.payload, after[before:])
			}
			continue
		}
		if len(after) == before {
			t.Fatalf("raw/%s never reached the upstream, so this case proves nothing", tc.payload)
		}
		for _, uri := range after[before:] {
			if !strings.HasPrefix(uri, "/native/") {
				t.Errorf("raw/%s landed outside the configured base: upstream saw %q", tc.payload, uri)
			}
		}
	}
}

// TestZ09ASourceNameCannotInjectAResponseHeader is the flipped form of FO-04; the
// name is kept so the coverage matrix still maps here.
//
// The finding was: federation.NewRegistry accepted a source name carrying CRLF,
// and that name reached `Re0Auth-Source` verbatim, so the CRLF could become a
// header of its own. The registry now validates game, source and resource names
// (internal/federation/federation.go validateSourceName, which cites FO-04), so
// the shape is refused at construction. The guard pins that, and keeps the
// end-to-end header check as the second line of defence for names that do pass.
func TestZ09ASourceNameCannotInjectAResponseHeader(t *testing.T) {
	up := newProbeUpstream(t, http.StatusOK, "application/json", `{"ok":true}`, nil)

	// The finding's shape must now be refused at construction.
	if _, err := federation.NewRegistry(federation.Source{
		Game: zzGame, Name: "src\r\nX-Injected: 1", DisplayName: "Src", Issuer: up.URL,
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzProfileScope},
		},
	}); err == nil {
		t.Errorf("NewRegistry accepted a source name carrying CRLF; it reaches the Re0Auth-Source " +
			"response header and could become a header of its own (FO-04)")
	} else {
		t.Logf("CRLF source name refused: %v", err)
	}

	// Anti-vacuity + end-to-end: a clean name is accepted and no injected header
	// appears on the response.
	reg := zzRegistryFor(t, up.URL, false)
	srv, mint := zzHarness(t, reg, []zzBind{
		{User: "usr_v", Game: zzGame, Source: "src", Access: "tok"},
	}, nil)
	at := mint("usr_v", zzProfileScope)

	code, hdr, _ := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/profile", at)
	t.Logf("clean source name => %d Re0Auth-Source=%q X-Injected=%q",
		code, hdr.Get("Re0Auth-Source"), hdr.Get("X-Injected"))
	if hdr.Get("X-Injected") != "" {
		t.Errorf("the source name injected a response header: X-Injected=%q", hdr.Get("X-Injected"))
	}
	if strings.ContainsAny(hdr.Get("Re0Auth-Source"), "\r\n") {
		t.Errorf("a newline survived into the response header: %q", hdr.Get("Re0Auth-Source"))
	}
}

// RETARGETED by Z09V-1 (docs/issues/P2-medium.md). This was the P1-3 regression
// guard: 401 used to be counted by the per-HOST breaker, and "a source that always
// answers 401 stops being dialed after five attempts" was that rule's observable.
// Counting a 401 per host is exactly what let one account's dead credential shed
// every other account's reads of the source, so the breaker no longer sees 401 at
// all. P1-3's goal is unchanged and is now met per BINDING: five consecutive 401s
// on one (user, game, source) stop that binding being dialed, and nothing else.
//
// The probe drives the real HTTP surface, so what it measures is the shipped
// composition: the per-host breaker (which must NOT open) plus the per-binding
// cooldown (which must).
func TestZ09ASourceThatAlwaysAnswers401TripsTheBreaker(t *testing.T) {
	up := newProbeUpstream(t, http.StatusUnauthorized, "application/json", `{"error":"nope"}`, nil)
	reg := zzRegistryFor(t, up.URL, false)
	// No refresh token: callWithRefresh returns the 401 rather than rotating, so
	// every read costs exactly one upstream call until the binding cools.
	srv, mint := zzHarness(t, reg, []zzBind{
		{User: "usr_v", Game: zzGame, Source: "src", Access: "tok"},
	}, nil)
	at := mint("usr_v", zzProfileScope)

	const reads = 8
	for i := 0; i < reads; i++ {
		code, _, _ := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/profile", at)
		if i == 0 {
			t.Logf("first read => %d (source answers 401)", code)
		}
	}
	got := up.n.Load()
	t.Logf("%d reads against an always-401 source produced %d upstream requests", reads, got)
	if got == reads {
		t.Errorf("every read was dialed (%d of %d): neither the (now 401-free) breaker nor the per-binding "+
			"cooldown stopped the binding, and a source whose token cannot be refreshed is charged on every read "+
			"forever", got, reads)
	}
	if got != 5 {
		t.Errorf("upstream requests = %d, want 5 (the per-binding cooldown threshold): the closing behaviour "+
			"changed and this guard should be re-derived", got)
	}
}
