//go:build audit5

// Adversarial verification probes for
// docs/audit-5/findings/config-startup-disclosure.md (CS-2).
//
// The original probe (cmd/re0auth/zzprobe_startup_test.go,
// TestProbeTwoListenersOnOnePort) shows that two binds on one port number
// SUCCEED. It never asks the question the security claim rests on: which of the
// two listeners actually receives a connection. This package asks that.
//
// Read-only: tests only, in a new package.
package verifyconfig

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// listenerWithAnswer binds addr and serves a one-line body naming itself.
func listenerWithAnswer(t *testing.T, addr, name string) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("bind %s (%s): %v", addr, name, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", name)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln, name
}

func ask(t *testing.T, hostport string) string {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + hostport + "/probe")
	if err != nil {
		return "ERROR:" + err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

// portOf returns the port of a bound listener.
func portOf(t *testing.T, ln net.Listener) string {
	t.Helper()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// nonLoopbackIPv4 returns the first routable IPv4 address of this host, so the
// test can ask "what does a connection from off-host reach?" — which is the only
// question that matters for "is the operational surface on the public
// interface?".
func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no interface table: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String()
	}
	return ""
}

// CS2-V1: with addr="0.0.0.0:P" (public) bound first and internal_addr a loopback
// spelling of the same port bound second, which listener answers where?
//
// This is the load-bearing measurement for CS-2's impact: "two listeners on one
// port number" is only a security statement if the operational surface becomes
// reachable through the public one, or the public one becomes unreachable.
func TestV_BothListenersBindAndWhichOneAnswersWhere(t *testing.T) {
	first, _ := listenerWithAnswer(t, "0.0.0.0:0", "PUBLIC")
	port := portOf(t, first)
	t.Logf("public listener bound 0.0.0.0:%s (resolved %s)", port, first.Addr())

	for _, second := range []string{"127.0.0.1", "[::1]", "localhost"} {
		ln, err := net.Listen("tcp", second+":"+port)
		if err != nil {
			t.Logf("bind %-16s:%s -> REFUSED (%v)", second, port, err)
			continue
		}
		t.Logf("bind %-16s:%s -> SUCCEEDED, resolved to %s", second, port, ln.Addr())
		_ = ln.Close()
	}

	// Now bind the loopback one for real and ask both sides.
	opsLn, _ := listenerWithAnswer(t, "127.0.0.1:"+port, "OPS")
	t.Logf("after binding 127.0.0.1:%s as OPS (resolved %s):", port, opsLn.Addr())
	t.Logf("  GET 127.0.0.1:%s   -> %s", port, ask(t, "127.0.0.1:"+port))
	t.Logf("  GET localhost:%s   -> %s", port, ask(t, "localhost:"+port))
	if public := nonLoopbackIPv4(t); public != "" {
		t.Logf("  GET %s:%s -> %s", public, port, ask(t, public+":"+port))
	} else {
		t.Log("  (no non-loopback IPv4 on this host)")
	}
}

// CS2-V2: the same question for the spelling pair the loader actually accepts
// without an acknowledgement, i.e. `addr="0.0.0.0:P"` + `internal_addr=":P"`.
//
// `:P` and `0.0.0.0:P` are the same socket on Windows: the second bind is
// refused, so the process dies at "internal listen". That is fail-closed, and it
// is worth pinning because it changes CS-2's severity from "hidden second
// operational listener" to "confusing startup failure".
func TestV_WildcardSpellingCollidesAndFailsClosed(t *testing.T) {
	first, _ := listenerWithAnswer(t, "0.0.0.0:0", "PUBLIC")
	port := portOf(t, first)

	for _, second := range []string{":" + port, "0.0.0.0:" + port, "[::]:" + port} {
		ln, err := net.Listen("tcp", second)
		if err != nil {
			t.Logf("bind %-18s -> REFUSED: %v", second, err)
			continue
		}
		t.Logf("bind %-18s -> SUCCEEDED as %s", second, ln.Addr())
		_ = ln.Close()
	}
}

// CS2-V3: what does Go's net.Listen do with the hostname "localhost"? The loader
// treats it as loopback without an acknowledgement (config.go:852-854), so the
// bind has to agree for that shortcut to be safe.
func TestV_WhereDoesLocalhostActuallyBind(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(localhost:0): %v", err)
	}
	defer func() { _ = ln.Close() }()
	t.Logf("net.Listen(\"tcp\", \"localhost:0\") resolved to %s", ln.Addr())

	ip, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("not an IP: %q", ip)
	}
	if !parsed.IsLoopback() {
		t.Errorf("localhost bound to a NON-loopback address %s: the loader's "+
			"internalAddrIsLocal shortcut would be wrong, not merely lax", ip)
	} else {
		t.Logf("localhost binds loopback (%s): the loader's shortcut and the bind agree", ip)
	}
}
