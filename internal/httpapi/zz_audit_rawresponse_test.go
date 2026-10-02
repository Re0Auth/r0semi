//go:build audit || audit6

package httpapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

// zz_audit_rawresponse_test.go — audit probe, rewritten as a regression guard.
//
// Question: the raw passthrough hands the upstream's status, media type and body
// to the caller "verbatim" (federation_routes.go:259-...). A response is not only
// those three things. This probe answers the upstream with hand-written bytes (a
// real TCP peer, not net/http), so the response can carry exactly what an
// attacker-controlled source could send:
//
//   - Set-Cookie, so a credential for THIS origin could be planted;
//   - Location on a 3xx, so the caller could be redirected;
//   - hop-by-hop framing headers;
//   - a Content-Type whose value carries CR / NUL, to see whether the value that
//     gets copied into OUR response can split our own headers.
//
// The fixture must reach the raw forwarding path at all. Since Z20-2 the raw
// passthrough is gated on the game's explicit `<game>.raw.read` scope
// (federation_routes.go:263-274), so the OP catalogue and the client both carry
// it — exactly as cmd/re0auth's registerRawScopes does. Without it the fixture
// measured a 403 problem document, not the proxy.
func zzAuditRawUpstream(t *testing.T, contentType string) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// hits proves a request actually reached the upstream: a 403/404 from the
	// gate never does, and would otherwise let the header assertions pass by
	// measuring our own problem document.
	hits := &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				hits.Add(1)
				body := "RAW-BODY"
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\n"+
					"Content-Type: %s\r\n"+
					"Content-Length: %d\r\n"+
					"Set-Cookie: zz_audit_session=planted; Path=/; HttpOnly\r\n"+
					"Connection: close, X-Hop-By-Hop\r\n"+
					"X-Hop-By-Hop: 1\r\n"+
					"X-Upstream-Secret: leak-me\r\n"+
					"\r\n%s", contentType, len(body), body)
			}(conn)
		}
	}()
	return ln.Addr().String(), hits
}

// zzAuditRawServer builds the whole server with one raw source pointed at addr,
// and returns it together with an access token that carries the source's scope.
func zzAuditRawServer(t *testing.T, addr string) (*httptest.Server, string) {
	t.Helper()
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "rawsrc", DisplayName: "Raw", Issuer: "https://unused.example",
		RawBase: "http://" + addr + "/v1", TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	binding := federation.Binding{User: "usr_test", Game: "phigros", Source: "rawsrc", Version: 1}
	if err := bindings.Put(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	seedBindingSecret(t, v, binding, "up-token")

	fed, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v, Doer: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Z20-2: raw is gated on `<game>.raw.read`, which the built-in catalogue does
	// not describe. Register it with the OP (rawRegistry) and allow it on the
	// client, or mintToken dies on invalid_scope and the data plane answers 403
	// `scope_not_granted` before handleGameRaw runs.
	raw := rawScopeFor("phigros")
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{fedRedirect},
		[]oauth.Scope{oauth.ScopePhigrosProfile, raw})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackendRegistry(t, "https://re0auth.test", clients, nil, rawRegistry(t, "phigros"))
	api, err := New(Config{
		Issuer: "https://re0auth.test", OIDC: opHandler, TokenIntrospector: opHandler,
		GrantStore: store, DeviceStore: store, Federation: fed,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	at := mintToken(t, api.Handler(), store, "cli", "usr_test", oauth.ScopePhigrosProfile, raw)
	resp := authedGet(t, srv.URL+"/v1/games/phigros/sources/rawsrc/raw/native/x", at)
	t.Cleanup(func() { _ = resp.Body.Close() })

	// The response is handed back through a mutable struct so the caller can read
	// its headers; the body is read here to prove it is not a problem document.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	t.Logf("downstream status = %d body=%q", resp.StatusCode, string(body))
	t.Logf("  raw header block: %v", resp.Header)
	// No fatal here: the gate's refusal and a malformed upstream are both
	// interesting to the caller's own assertions. Each test proves the request
	// reached the upstream through the hit counter.
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	return srv, at
}

func TestZZAuditRawProxyDoesNotRelayUpstreamResponseHeaders(t *testing.T) {
	addr, hits := zzAuditRawUpstream(t, "text/plain")
	srv, at := zzAuditRawServer(t, addr)

	// Re-issue through the same server to inspect headers cleanly.
	before := hits.Load()
	resp := authedGet(t, srv.URL+"/v1/games/phigros/sources/rawsrc/raw/native/x", at)
	defer resp.Body.Close()
	if after := hits.Load(); after <= before {
		t.Fatalf("the re-issued request never reached the raw upstream (hits %d -> %d); the header block below is our own error, not the proxy's", before, after)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw status = %d, want 200", resp.StatusCode)
	}
	for _, h := range []string{"Content-Type", "Content-Security-Policy", "Content-Disposition",
		"Set-Cookie", "Location", "Connection", "X-Hop-By-Hop", "X-Upstream-Secret"} {
		t.Logf("  header %-22s = %q", h, resp.Header.Get(h))
	}
	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Errorf("the upstream's Set-Cookie reached the caller: %q", got)
	}
	if got := resp.Header.Get("Location"); got != "" {
		t.Errorf("the upstream's Location reached the caller: %q", got)
	}
	if got := resp.Header.Get("X-Hop-By-Hop"); got != "" {
		t.Errorf("a hop-by-hop header reached the caller: %q", got)
	}
	if got := resp.Header.Get("X-Upstream-Secret"); got != "" {
		t.Errorf("an upstream header reached the caller: %q", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("the upstream media type was not passed through: %q", got)
	}
}

func TestZZAuditRawProxyWithACRLacedContentType(t *testing.T) {
	// A CR inside a header value is what a header-injection attempt looks like at
	// the byte level. Go's own response parser may refuse the whole message; if it
	// does not, the value must not split our response. Either way the request must
	// reach the proxy — a gate refusal would make the assertions pass vacuously.
	addr, hits := zzAuditRawUpstream(t, "text/plain\rX-Injected-By-CR: yes")
	srv, at := zzAuditRawServer(t, addr)
	before := hits.Load()
	resp := authedGet(t, srv.URL+"/v1/games/phigros/sources/rawsrc/raw/native/x", at)
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if after := hits.Load(); after <= before {
		t.Fatalf("the CR-laced request never reached the raw upstream (hits %d -> %d)", before, after)
	}

	for _, h := range []string{"X-Injected-By-CR", "Content-Type", "Content-Length"} {
		t.Logf("  header %-18s = %q", h, resp.Header.Get(h))
	}
	if got := resp.Header.Get("X-Injected-By-CR"); got != "" {
		t.Fatalf("a CR in the upstream's Content-Type split our response headers: %q", got)
	}
	if ct := resp.Header.Get("Content-Type"); strings.ContainsAny(ct, "\r\n") {
		t.Errorf("a newline survived into the response's Content-Type: %q", ct)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		// Go's client parsed the message; the media type must still pass through.
		if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
			t.Errorf("CR-laced media type was neither refused nor passed through: %q", got)
		}
	case http.StatusBadGateway:
		// The safe outcome: net/http refuses the malformed upstream message
		// wholesale, so handleGameRaw maps it to an upstream_unavailable problem
		// document and none of the upstream's bytes reach the caller.
		if !strings.Contains(string(body), "upstream_unavailable") {
			t.Errorf("502 body = %q, want upstream_unavailable", body)
		}
	default:
		t.Errorf("CR-laced upstream -> %d, want 200 (sanitized pass-through) or 502 (refused)", resp.StatusCode)
	}
}
