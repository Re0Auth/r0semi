//go:build audit5

package pubaddr

import (
	"net/netip"
	"testing"

	"github.com/Re0Auth/r0semi/httpclient"
)

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
		{"192.88.99.1", "nonpublic"}, // RFC3068 6to4 relay anycast
		{"192.0.0.170", "nonpublic"}, // NAT64 discovery
		{"224.0.0.1", "nonpublic"},
		{"2606:4700:4700::1111", "public"},
	}
	for _, c := range cases {
		got := httpclient.IsPublicAddress(netip.MustParseAddr(c.a))
		verdict := "nonpublic"
		if got {
			verdict = "public"
		}
		status := "OK"
		if verdict != c.want {
			status = "MISMATCH"
		}
		t.Logf("%-24s %-9s want=%-9s %s", c.a, verdict, c.want, status)
	}
}
