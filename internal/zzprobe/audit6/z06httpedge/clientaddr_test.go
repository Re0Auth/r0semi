//go:build audit6

// Client-address and rate-limit-key probes for zone 06 (round 6). The P0-4 fix
// made the bucket key "the rightmost hop of the declared header, read only
// from a trusted peer, falling back to the peer whenever anything about that
// entry is off". These probes attack the edges of exactly that: IPv6-mapped
// spellings (which could mint new buckets or spoof a trusted hop), textual
// normalization (an attacker wants MORE buckets, so two spellings of one
// address must land in one bucket), multi-line and comma-joined XFF, entries
// with ports, and other forwarding headers that must be ignored.
package z06httpedge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// TestZ06ForwardedKeyEdgeShapes walks XFF shapes against a deployment that
// declares x-forwarded-for and trusts 10.0.0.0/8. For each shape the question
// is: does the attacker get to choose its own bucket key (a NEW bucket per
// request), and does a trusted-looking spelling ever displace what the real
// proxy appended?
func TestZ06ForwardedKeyEdgeShapes(t *testing.T) {
	// Each sub-case gets its own server so bucket state cannot leak between
	// cases; each request from a distinct public peer so the only variable is
	// the header.
	newServer := func() http.Handler {
		return edgeServer(t, func(c *httpapi.Config) {
			c.Limiter = ratelimit.New(noRefill, 1)
			c.TrustedProxies = trustedPrefixes(t, "10.0.0.0/8")
			c.ClientAddrHeader = httpapi.ClientAddrXForwardedFor
		}).Handler()
	}
	seq := 0
	nextPeer := func() string {
		seq++
		return fmt.Sprintf("198.51.%d.%d:5555", seq/200+1, seq%200+1)
	}
	// call issues two requests from the same fresh peer with the same XFF
	// values; the second must be 429 unless the key moved between them.
	call := func(h http.Handler, xff func(n int) []string) (int, int) {
		peer := nextPeer()
		do := func(n int) int {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.RemoteAddr = peer
			for _, v := range xff(n) {
				req.Header.Add("X-Forwarded-For", v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec.Code
		}
		return do(1), do(2)
	}
	// viaProxy issues requests from a trusted peer (10.1.2.3) so the header is
	// read at all.
	viaProxy := func(h http.Handler, xff func(n int) []string) (int, int) {
		do := func(n int) int {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.RemoteAddr = "10.1.2.3:5555"
			for _, v := range xff(n) {
				req.Header.Add("X-Forwarded-For", v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec.Code
		}
		return do(1), do(2)
	}

	t.Run("untrusted peer rotating XFF cannot pick a bucket", func(t *testing.T) {
		h := newServer()
		first, second := call(h, func(n int) []string { return []string{fmt.Sprintf("203.0.113.%d", n)} })
		if first != http.StatusUnauthorized {
			t.Fatalf("first = %d, want 401", first)
		}
		if second != http.StatusTooManyRequests {
			t.Fatalf("rotating XFF from an untrusted peer escaped the bucket: %d, want 429", second)
		}
	})

	t.Run("IPv6 mapped spelling of a trusted hop cannot spoof trust", func(t *testing.T) {
		h := newServer()
		// The caller writes a mapped form of a trusted address; the appended
		// entry is unmapped before the trust check, so this must fall back to
		// the PEER, not hand the caller a chosen key.
		first, second := viaProxy(h, func(n int) []string {
			return []string{fmt.Sprintf("198.51.100.%d, ::ffff:10.9.9.9", n)}
		})
		if first != http.StatusUnauthorized {
			t.Fatalf("first = %d, want 401", first)
		}
		if second != http.StatusTooManyRequests {
			t.Fatalf("a mapped-IPv6 trusted hop let the caller pick its key: %d, want 429", second)
		}
	})

	t.Run("IPv6 spellings of one address share one bucket", func(t *testing.T) {
		h := newServer()
		// 2001:db8::1 has many textual spellings; if the key kept the raw
		// text, each spelling would be a fresh bucket.
		spellings := []string{
			"2001:db8::1", "2001:0db8::1", "2001:db8:0::1", "2001:DB8::1",
		}
		peer := nextPeer()
		codes := make([]int, len(spellings))
		for i, s := range spellings {
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.RemoteAddr = "10.1.2.3:5555"
			req.Header.Set("X-Forwarded-For", s)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			codes[i] = rec.Code
			_ = peer
		}
		if codes[0] != http.StatusUnauthorized {
			t.Fatalf("first spelling = %d, want 401", codes[0])
		}
		for i, c := range codes[1:] {
			if c != http.StatusTooManyRequests {
				t.Fatalf("spelling %q minted a new bucket: %d, want 429", spellings[i+1], c)
			}
		}
	})

	t.Run("entries with ports are untrusted, not skipped", func(t *testing.T) {
		h := newServer()
		// "198.51.100.7:1234" is not an address; the whole header must fall
		// back to the peer rather than letting the caller vary the text.
		first, second := viaProxy(h, func(n int) []string {
			return []string{fmt.Sprintf("203.0.113.%d:9999", n)}
		})
		if first != http.StatusUnauthorized {
			t.Fatalf("first = %d, want 401", first)
		}
		if second != http.StatusTooManyRequests {
			t.Fatalf("an XFF entry with a port let the caller pick its key: %d, want 429", second)
		}
	})

	t.Run("multi-line XFF is one list, rightmost wins", func(t *testing.T) {
		h := newServer()
		// The proxy wrote the second line (constant); the first line is
		// caller text and varies per call.
		first, second := viaProxy(h, func(n int) []string {
			return []string{fmt.Sprintf("203.0.113.%d", n), "198.51.100.7"}
		})
		if first != http.StatusUnauthorized {
			t.Fatalf("first = %d, want 401", first)
		}
		if second != http.StatusTooManyRequests {
			t.Fatalf("varying an earlier line changed the key: %d, want 429", second)
		}
	})

	t.Run("empty entries and commas do not move the key", func(t *testing.T) {
		h := newServer()
		first, second := viaProxy(h, func(n int) []string {
			return []string{fmt.Sprintf(", %s, , 198.51.100.7, ,", fmt.Sprintf("203.0.113.%d", n))}
		})
		if first != http.StatusUnauthorized {
			t.Fatalf("first = %d, want 401", first)
		}
		if second != http.StatusTooManyRequests {
			t.Fatalf("comma noise let the caller pick its key: %d, want 429", second)
		}
	})

	otherHeaders := []string{
		"X-Real-IP", "X-Client-IP", "Cf-Connecting-Ip", "True-Client-Ip",
		"Fastly-Client-Ip", "X-Forwarded-Host", "Forwarded",
	}
	for _, name := range otherHeaders {
		t.Run(name+" is not a key", func(t *testing.T) {
			h := newServer()
			do := func(n int) int {
				req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
				req.RemoteAddr = "10.1.2.3:5555"
				// The proxy's entry is constant; the other header varies per call.
				req.Header.Set("X-Forwarded-For", "198.51.100.1")
				req.Header.Set(name, fmt.Sprintf("203.0.113.%d", n))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec.Code
			}
			if first := do(1); first != http.StatusUnauthorized {
				t.Fatalf("first = %d, want 401", first)
			}
			if second := do(2); second != http.StatusTooManyRequests {
				t.Fatalf("%s changed the bucket key", name)
			}
		})
	}
}
