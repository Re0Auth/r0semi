//go:build audit5

package pubaddr

import (
	"net/netip"
	"testing"

	"github.com/Re0Auth/r0semi/httpclient"
)

// TestPubAddrRanges pins which addresses the SSRF guard refuses. It used to build
// a per-case verdict string and only LOG it (Z16-6): a wrong expectation for any
// of its cases passed in silence, because nothing in the function could fail. The
// assertion is now per case, with the table length checked so a truncated table
// cannot make the loop vacuous.
func TestPubAddrRanges(t *testing.T) {
	cases := []struct {
		a    string
		want string // "public" or "nonpublic"
	}{
		{"8.8.8.8", "public"},
		{"1.1.1.1", "public"},
		{"10.0.0.1", "nonpublic"},
		{"192.168.1.1", "nonpublic"},
		{"169.254.169.254", "nonpublic"},
		{"127.0.0.1", "nonpublic"},
		{"100.64.0.1", "nonpublic"},
		{"192.0.2.1", "nonpublic"},
		{"203.0.113.1", "nonpublic"},
		{"198.18.0.1", "nonpublic"},
		{"240.0.0.1", "nonpublic"},
		{"0.0.0.0", "nonpublic"},
		{"0.1.2.3", "nonpublic"},
		{"255.255.255.255", "nonpublic"},
		{"::1", "nonpublic"},
		{"fd00::1", "nonpublic"},
		{"fe80::1", "nonpublic"},
		{"::ffff:10.0.0.1", "nonpublic"},
		{"64:ff9b::7f00:1", "nonpublic"},
		{"2002:7f00:0001::1", "nonpublic"},
		{"192.0.0.170", "nonpublic"}, // NAT64 discovery
		{"224.0.0.1", "nonpublic"},
		// 192.88.99.0/24 (RFC 3068 6to4 relay anycast) is deliberately NOT in
		// httpclient's non-public prefixes: RFC 7526 deprecated it and the audit's
		// verified federation findings record it as out of the threat model
		// (docs/audit-5/findings/federation.md §"192.88.99.1 不作为发现"). The
		// predicate therefore judges it public, and this table records the accepted
		// decision rather than the round-5 auditor's first draft.
		{"192.88.99.1", "public"},
		{"2606:4700:4700::1111", "public"},
	}
	if len(cases) < 24 {
		t.Fatalf("only %d cases; the table was truncated and the loop would be vacuous", len(cases))
	}
	public, nonpublic := 0, 0
	for _, c := range cases {
		got := httpclient.IsPublicAddress(netip.MustParseAddr(c.a))
		verdict := "nonpublic"
		if got {
			verdict = "public"
			public++
		} else {
			nonpublic++
		}
		if verdict != c.want {
			t.Errorf("IsPublicAddress(%s) = %s, want %s", c.a, verdict, c.want)
		}
	}
	// Anti-vacuity in both directions: the table must contain both verdicts, or a
	// guard that answered one value for everything could pass it.
	if public == 0 || nonpublic == 0 {
		t.Fatalf("the table produced %d public and %d nonpublic verdicts; a single-valued table would "+
			"pass this guard vacuously", public, nonpublic)
	}
}
