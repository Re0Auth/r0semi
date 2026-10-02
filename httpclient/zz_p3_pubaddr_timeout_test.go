package httpclient

import (
	"net"
	"net/netip"
	"testing"
)

// FO-03 — 0.0.0.0/8 ("this network", RFC 1122 §3.2.1.3) is not private, not
// loopback and not link-local, so netip called every address in it global
// unicast and the allow-list admitted it. Linux routes it to the loopback when
// no more specific route exists, which makes it an SSRF alias for 127.0.0.0/8.
//
// The IPv4-mapped spelling is covered by IsPublicAddress's Unmap, so it is part
// of the same fact and asserted here rather than left implied.
func TestIsPublicAddressRefusesTheThisNetworkBlock(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0",        // unspecified, never public
		"0.0.0.1",        // 0.0.0.0/8
		"0.1.2.3",        // 0.0.0.0/8
		"0.255.255.255",  // 0.0.0.0/8 upper edge
		"::ffff:0.0.0.1", // IPv4-mapped 0/8
		"::ffff:0.255.255.255",
	} {
		addr := netip.MustParseAddr(raw)
		if IsPublicAddress(addr) {
			t.Errorf("IsPublicAddress(%s) = true; the 0/8 block is not a public destination", raw)
		}
	}

	// Anti-vacuity: the fix must not turn the allow-list into "nothing is public".
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("IsPublicAddress(%s) = false; the guard became over-broad", raw)
		}
	}
}

// The dial-time hook must refuse 0/8 too, not only the predicate: the guard is
// the union of both, and a predicate fix that the dialer does not consult would
// be a half fix. No connection is attempted — the Control hook runs against the
// literal address with no DNS.
func TestDenyPrivateAddressRefuses0By8AtDialTime(t *testing.T) {
	for _, addr := range []string{"0.1.2.3:80", "0.0.0.1:443", "0.255.255.255:8080"} {
		if err := denyPrivateAddress("tcp", addr, nil); err == nil {
			t.Errorf("denyPrivateAddress(%q) = nil; 0/8 was admitted at dial time", addr)
		}
	}
	// Contrapositive control: a genuinely public literal is still dialable.
	host, port, err := net.SplitHostPort("8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := denyPrivateAddress("tcp", net.JoinHostPort(host, port), nil); err != nil {
		t.Errorf("denyPrivateAddress(8.8.8.8:443) = %v; a public address was refused", err)
	}
}

// Z11-6 — the transport's ResponseHeaderTimeout must sit below the client's
// overall Timeout, which is what the field's own comment promises. It used to be
// 30s against a 20s default, so a hung source always surfaced as the overall
// deadline instead of naming the headers.
func TestResponseHeaderTimeoutSitsBelowTheOverallTimeout(t *testing.T) {
	def := DefaultTransportConfig()
	if def.ResponseHeaderTimeout <= 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want positive", def.ResponseHeaderTimeout)
	}
	if def.ResponseHeaderTimeout >= defaultOutboundTimeout {
		t.Errorf("default ResponseHeaderTimeout = %v, want below the %v overall timeout",
			def.ResponseHeaderTimeout, defaultOutboundTimeout)
	}
	// The zero-value config must land on the same relationship, since that is
	// what NewOutboundClient{Timeout:0} builds.
	c := NewOutboundClient(OutboundConfig{})
	if c.Timeout != defaultOutboundTimeout {
		t.Fatalf("client Timeout = %v, want %v", c.Timeout, defaultOutboundTimeout)
	}
	if c.Timeout <= def.ResponseHeaderTimeout {
		t.Errorf("client Timeout %v does not exceed ResponseHeaderTimeout %v",
			c.Timeout, def.ResponseHeaderTimeout)
	}
}
