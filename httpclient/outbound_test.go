package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The default transport keeps two idle connections per host. A proxy fronting a
// handful of sources must not, or it redials on nearly every request.
func TestNewOutboundClientPoolsConnections(t *testing.T) {
	c := NewOutboundClient(OutboundConfig{})
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.Transport)
	}
	if tr.MaxIdleConnsPerHost <= 2 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want more than the standard library's 2", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxIdleConns <= 0 || tr.IdleConnTimeout <= 0 || tr.ResponseHeaderTimeout <= 0 {
		t.Fatalf("transport not fully configured: %+v", tr)
	}
	if c.Timeout <= 0 {
		t.Fatal("no overall request timeout")
	}
}

func TestNewTransportFillsDefaults(t *testing.T) {
	tr := NewTransport(TransportConfig{MaxIdleConnsPerHost: 7})
	if tr.MaxIdleConnsPerHost != 7 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want the configured 7", tr.MaxIdleConnsPerHost)
	}
	def := DefaultTransportConfig()
	if tr.MaxIdleConns != def.MaxIdleConns || tr.DialContext == nil {
		t.Fatalf("zero fields were not defaulted: %+v", tr)
	}
}

func TestNewOutboundClientWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewOutboundClient(OutboundConfig{MaxConcurrent: 4})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// The bulkhead is the whole point: eight callers against a cap of two must never
// exceed two requests in flight.
func TestBulkheadCapsConcurrency(t *testing.T) {
	var inFlight, peak int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		<-release
		atomic.AddInt32(&inFlight, -1)
	}))
	defer srv.Close()

	client := &http.Client{Transport: Bulkhead(srv.Client().Transport, 2)}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(srv.URL)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}

	// Let the four requests that can proceed reach the handler, then confirm the
	// cap held before releasing everyone.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&inFlight) < 2 {
		time.Sleep(time.Millisecond)
	}
	if got := atomic.LoadInt32(&inFlight); got > 2 {
		t.Fatalf("%d requests in flight, want at most 2", got)
	}
	close(release)
	wg.Wait()
	if got := atomic.LoadInt32(&peak); got > 2 {
		t.Fatalf("peak concurrency = %d, want at most 2", got)
	}
}

// A request that cannot get a slot must give up when its context is cancelled,
// not wait forever. A deterministic version: hold the only slot from a handler,
// then try with an already-cancelled context.
func TestBulkheadHonoursContext(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	defer srv.Close()

	rt := Bulkhead(srv.Client().Transport, 1)

	// Occupy the single slot.
	go func() {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := rt.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered // the slot is held: the handler is running

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("a cancelled request took a bulkhead slot instead of returning an error")
	}
	close(release)
}

// A non-positive cap disables the bulkhead, and the wrapper is not inserted at
// all rather than being a pass-through object.
func TestBulkheadDisabledWhenUnlimited(t *testing.T) {
	base := http.DefaultTransport
	if got := Bulkhead(base, 0); got != base {
		t.Fatalf("Bulkhead(_, 0) = %T, want the original transport", got)
	}
	if got := Bulkhead(base, -1); got != base {
		t.Fatalf("Bulkhead(_, -1) = %T, want the original transport", got)
	}
}

// The slot must cover the whole transfer, not merely the wait for headers. If it
// were released when RoundTrip returned, a caller reading a multi-megabyte body
// would be outside the cap — which is exactly the load the cap exists for.
func TestBulkheadHoldsSlotUntilBodyClosed(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Send the headers at once, then keep the body open, so the caller's
		// RoundTrip returns while the transfer is still in progress.
		_, _ = w.Write([]byte("x"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
	}))
	defer srv.Close()

	rt := Bulkhead(srv.Client().Transport, 1)
	newReq := func(ctx context.Context) *http.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	resp, err := rt.RoundTrip(newReq(context.Background()))
	if err != nil {
		t.Fatal(err)
	}

	// Headers are in and RoundTrip has returned, but the body is open. The slot
	// is still taken, so a second request with a dead context cannot get in.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rt.RoundTrip(newReq(cancelled)); err == nil {
		t.Fatal("the slot was free while a response body was still open")
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	// Double close must not release the slot twice and corrupt the count.
	_ = resp.Body.Close()

	second, err := rt.RoundTrip(newReq(context.Background()))
	if err != nil {
		t.Fatalf("the slot was not returned when the body was closed: %v", err)
	}
	close(release)
	_ = second.Body.Close()
}

// A redirect off the origin host is refused, and nothing of the request reaches
// the host it pointed at.
//
// The guard for a real leak: the client followed redirects by default, Go strips
// Authorization only when the destination is outside the same domain, and it never
// strips the body on 307/308. Every request through this client carries something
// that must not be deflected — a bearer token on the data plane, a refresh token
// and the client secret on the token exchange — so "go somewhere else" has to be
// an error, not a hop.
func TestOutboundRefusesRedirectToAnotherHost(t *testing.T) {
	var reached atomic.Bool
	var gotBody atomic.Value
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	c := NewOutboundClient(OutboundConfig{})
	req, err := http.NewRequest(http.MethodPost, source.URL+"/oauth/token",
		strings.NewReader("grant_type=refresh_token&refresh_token=SECRET-REFRESH&client_secret=SECRET-CLIENT"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer SECRET-BEARER")

	resp, err := c.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the outbound client followed a redirect to another host")
	}
	if reached.Load() {
		t.Fatalf("the request was delivered to the redirect target with body %q", gotBody.Load())
	}
}

// The refusal is about who receives the request, not about redirects as such: a
// same-host redirect still resolves, so the policy cannot be mistaken for "turn
// redirects off everywhere".
func TestOutboundAllowsASameHostRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewOutboundClient(OutboundConfig{})
	resp, err := c.Get(srv.URL + "/moved")
	if err != nil {
		t.Fatalf("a same-host redirect was refused: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the redirect followed to 200", resp.StatusCode)
	}
}

// A scheme change is a host change in the sense that matters: the request would
// leave for somewhere the operator did not configure, and an https -> http hop is
// a downgrade on top of it.
func TestNoCrossHostRedirectsRefusesASchemeChange(t *testing.T) {
	origin, err := url.Parse("https://api.example/oauth/token")
	if err != nil {
		t.Fatal(err)
	}
	via := []*http.Request{{URL: origin}}

	downgrade, err := http.NewRequest(http.MethodGet, "http://api.example/moved", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := NoCrossHostRedirects(downgrade, via); err == nil {
		t.Fatal("an https -> http redirect was allowed")
	}

	sameHost, err := http.NewRequest(http.MethodGet, "https://api.example/moved", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := NoCrossHostRedirects(sameHost, via); err != nil {
		t.Fatalf("a same-scheme, same-host redirect was refused: %v", err)
	}

	otherHost, err := http.NewRequest(http.MethodGet, "https://elsewhere.example/moved", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := NoCrossHostRedirects(otherHost, via); err == nil {
		t.Fatal("a redirect to another host was allowed")
	}
}

// The guard that keeps a configured source or IdP from being aimed at the cloud
// metadata address or another internal listener.
//
// The check runs on the resolved address at dial time, which is what a URL-level
// check cannot do: a name that answered publicly when the source was registered
// can answer 169.254.169.254 later. Loopback is where every test server lives, so
// the difference is directly observable — and the refusal has to name the setting
// that permits it, or an operator with a self-hosted source sees only "connection
// refused".
func TestTransportRefusesPrivateAddressesWhenAsked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	open := NewOutboundClient(OutboundConfig{})
	resp, err := open.Get(srv.URL)
	if err != nil {
		t.Fatalf("loopback was refused without the flag: %v", err)
	}
	_ = resp.Body.Close()

	guarded := NewOutboundClient(OutboundConfig{
		Transport: TransportConfig{DenyPrivateAddresses: true},
	})
	if _, err := guarded.Get(srv.URL); err == nil {
		t.Fatal("a loopback address was dialed with DenyPrivateAddresses set")
	} else if !strings.Contains(err.Error(), "allow_private_addresses") {
		t.Fatalf("the refusal does not name the setting that permits it: %v", err)
	}
}

// The predicate behind the hook, tested on the addresses an attacker reaches for
// rather than only on the one a test server happens to use.
func TestIsPublicAddress(t *testing.T) {
	for raw, want := range map[string]bool{
		"127.0.0.1":       false,
		"::1":             false,
		"10.0.0.5":        false,
		"172.16.3.4":      false,
		"192.168.1.1":     false,
		"169.254.169.254": false, // the cloud metadata address
		"fd00::1":         false, // IPv6 unique-local
		"fe80::1":         false,
		"100.64.0.1":      false, // carrier-grade NAT
		"0.0.0.0":         false,
		"2002:7f00:1::":   false, // 6to4 wrapping 127.0.0.1
		"64:ff9b::7f00:1": false, // NAT64 wrapping 127.0.0.1
		"8.8.8.8":         true,
		"1.1.1.1":         true,
		"2606:4700::1111": true,
	} {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := IsPublicAddress(addr); got != want {
			t.Errorf("IsPublicAddress(%s) = %v, want %v", raw, got, want)
		}
	}
}

// When a proxy carries the request the dial-time Control hook only ever sees the
// proxy's address, so the target has to be judged before the request leaves
// (S06-2). IP literals need no DNS, which is what makes this deterministic.
func TestDenyPrivateTargetJudgesTheTargetAddress(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		host    string
		wantErr bool
	}{
		{"10.0.0.5", true},
		{"127.0.0.1", true},
		{"169.254.169.254", true}, // the cloud metadata address
		{"192.168.1.1", true},
		{"100.64.0.1", true}, // carrier-grade NAT
		{"1.1.1.1", false},
		{"93.184.216.34", false},
	} {
		u := &url.URL{Scheme: "http", Host: tc.host}
		err := denyPrivateTarget(ctx, u)
		if (err != nil) != tc.wantErr {
			t.Errorf("denyPrivateTarget(%s) = %v, wantErr=%v", tc.host, err, tc.wantErr)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), "allow_private_addresses") {
			t.Errorf("denyPrivateTarget(%s) = %v, want it to name the setting that permits it", tc.host, err)
		}
	}
}
