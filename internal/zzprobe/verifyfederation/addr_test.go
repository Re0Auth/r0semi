//go:build audit5

package zzprobe_verifyfederation

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
)

// TestVerifyZeroEightPredicateGap pins the predicate side of FO-03: 0.0.0.0/8 is
// not a public destination, so IsPublicAddress must refuse it. It was a
// finding-demonstrator (the whole /8 used to be admitted); it is now the
// regression guard for the fix, and the anti-vacuity rows below keep it honest.
func TestVerifyZeroEightPredicateGap(t *testing.T) {
	cases := []struct {
		addr string
		want bool // true = admitted (judged public)
	}{
		{"0.0.0.0", false},         // unspecified
		{"0.0.0.1", false},         // 0.0.0.0/8, refused since FO-03
		{"0.1.2.3", false},         // 0.0.0.0/8
		{"0.255.255.255", false},   // 0.0.0.0/8 upper edge
		{"::ffff:0.1.2.3", false},  // IPv4-mapped form of the same
		{"127.0.0.1", false},       // loopback (anti-vacuity)
		{"10.0.0.5", false},        // RFC1918
		{"169.254.169.254", false}, // link-local metadata (anti-vacuity)
		{"100.64.0.1", false},      // CGNAT, listed in nonPublicPrefixes
		{"192.0.0.1", false},       // IETF, listed
		{"240.0.0.1", false},       // reserved, listed
		{"255.255.255.255", false}, // limited broadcast
		{"8.8.8.8", true},          // public (anti-vacuity)
		{"192.88.99.1", true},      // 6to4 relay anycast, NOT listed
		{"::ffff:8.8.8.8", true},   // Unmap -> public, correct
		{"2606:4700:4700::1111", true},
	}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		got := httpclient.IsPublicAddress(addr)
		t.Logf("IsPublicAddress(%-24s) = %-5v", c.addr, got)
		if got != c.want {
			t.Errorf("IsPublicAddress(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestVerifyZeroEightRoutesToLoopbackOnThisPlatform is the step the audit left as
// HYPOTHESIS: does a destination inside 0.0.0.0/8 reach a listener bound to
// loopback? It is executed here (Windows 11) against the real guarded client, so
// the answer is platform-specific evidence rather than an assumption.
func TestVerifyZeroEightRoutesToLoopbackOnThisPlatform(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = ln.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	hit := make(chan string, 32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(hit)
				return
			}
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			hit <- strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok")
			_ = conn.Close()
		}
	}()

	// 1. Raw dial: answers the kernel-routing question directly.
	for _, host := range []string{"127.0.0.1", "0.0.0.0", "0.0.0.1", "0.1.2.3", "0.255.255.255"} {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort(host, strconv.Itoa(port)), 1500*time.Millisecond)
		if err != nil {
			t.Logf("raw dial %-16s -> refused/failed: %v", host, err)
			continue
		}
		_ = conn.Close()
		t.Logf("raw dial %-16s -> CONNECTED to the loopback listener", host)
	}

	// 2. The real data-plane client, guard ON, against a 0/8 URL. NO_PROXY covers
	// 0.0.0.0/8, so the proxy that TestMain installs does not intercept this.
	client := httpclient.NewOutboundClient(httpclient.OutboundConfig{
		Timeout:   3 * time.Second,
		Transport: httpclient.TransportConfig{DenyPrivateAddresses: true},
	})
	for _, host := range []string{"0.1.2.3", "0.0.0.1", "169.254.169.254", "127.0.0.1"} {
		u := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/probe"
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Logf("guarded GET %-22s -> refused: %v", u, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Logf("guarded GET %-22s -> %d %q  <-- the guard admitted it", u, resp.StatusCode, body)
	}

	// Close first, then drain: Accept has to be released before the channel closes.
	closed = true
	_ = ln.Close()
	var reached []string
	for {
		select {
		case line, ok := <-hit:
			if !ok {
				t.Logf("requests the loopback listener actually served: %v", reached)
				return
			}
			reached = append(reached, line)
		case <-time.After(500 * time.Millisecond):
			t.Logf("requests the loopback listener actually served: %v", reached)
			return
		}
	}
}

// TestVerifyProxyGuardJudgesTheProxyNotTheTarget pins the S06-2 fix. The name is
// historical: before the fix the refusal named the PROXY, because the address
// guard ran only on the dial; the target guard now runs before the request
// leaves, so the refusal names the TARGET. This probe was a finding-demonstrator
// and is now the regression guard for that direction. http.ProxyFromEnvironment
// is read once per process, so HTTP_PROXY is installed in TestMain.
func TestVerifyProxyGuardJudgesTheProxyNotTheTarget(t *testing.T) {
	if proxyAddr == "" {
		t.Skip("no test proxy was started")
	}
	// Fail-closed direction: the target is RFC1918, so the target guard refuses
	// before the proxy is ever dialed, and the refusal names the target.
	guarded := httpclient.NewOutboundClient(httpclient.OutboundConfig{
		Timeout:   3 * time.Second,
		Transport: httpclient.TransportConfig{DenyPrivateAddresses: true},
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.0.0.5/secret", nil)
	resp, err := guarded.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a private target was carried through the proxy with the guard on: %d", resp.StatusCode)
	}
	t.Logf("guard ON, target http://10.0.0.5/secret, proxy %s -> %v", proxyAddr, err)
	if !strings.Contains(err.Error(), "10.0.0.5") {
		t.Errorf("the refusal does not name the TARGET address, so the guard still judges the proxy: %v", err)
	}
	if strings.Contains(err.Error(), proxyAddr) {
		t.Errorf("the refusal names the proxy address (%s) instead of the target: %v", proxyAddr, err)
	}
	if !strings.Contains(err.Error(), "allow_private_addresses") {
		t.Errorf("the refusal does not name the setting that permits it: %v", err)
	}

	// The other direction: with the guard off, the same request goes THROUGH the
	// proxy, which receives the absolute target URI and is the only thing dialed.
	open := httpclient.NewOutboundClient(httpclient.OutboundConfig{Timeout: 3 * time.Second})
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.0.0.5/secret", nil)
	resp2, err := open.Do(req2)
	if err != nil {
		t.Fatalf("unguarded request through the test proxy failed: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	t.Logf("guard OFF, target http://10.0.0.5/secret -> %d %s", resp2.StatusCode, body)

	proxyMu.Lock()
	saw := append([]string(nil), proxySaw...)
	proxyMu.Unlock()
	if len(saw) == 0 {
		t.Fatal("the test proxy saw nothing; the probe measured nothing")
	}
	t.Logf("the proxy received: %v", saw)
	if !strings.Contains(strings.Join(saw, " "), "10.0.0.5") {
		t.Errorf("the proxy did not receive the target as an absolute URI: %v", saw)
	}
}

var (
	proxyAddr string
	proxyMu   sync.Mutex
	proxySaw  []string
)

func TestMain(m *testing.M) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		proxyAddr = ln.Addr().String()
		go serveFakeProxy(ln)
		// ProxyFromEnvironment resolves the environment once per process, so this
		// has to happen before the first client is built.
		for k, v := range map[string]string{
			"HTTP_PROXY":  "http://" + proxyAddr,
			"http_proxy":  "http://" + proxyAddr,
			"NO_PROXY":    "0.0.0.0/8,127.0.0.0/8,::1",
			"no_proxy":    "0.0.0.0/8,127.0.0.0/8,::1",
			"HTTPS_PROXY": "",
		} {
			_ = os.Setenv(k, v)
		}
	}
	code := m.Run()
	if ln != nil {
		_ = ln.Close()
	}
	os.Exit(code)
}

// serveFakeProxy is a plain HTTP forward proxy: it records the absolute URI it was
// asked for and answers 200 without dialing anything.
func serveFakeProxy(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 2048)
			n, _ := c.Read(buf)
			line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
			fields := strings.Fields(line)
			target := line
			if len(fields) >= 2 {
				target = fields[1]
			}
			proxyMu.Lock()
			proxySaw = append(proxySaw, target)
			proxyMu.Unlock()
			fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 17\r\nContent-Type: text/plain\r\n\r\nproxy-saw-target\n")
		}(conn)
	}
}
