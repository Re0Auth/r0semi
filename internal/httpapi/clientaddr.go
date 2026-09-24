package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientAddr returns the address a request should be attributed to.
//
// It is the peer address by default. Only when the peer is one of the configured
// trusted proxies is X-Forwarded-For consulted, and even then the chain is walked
// from the right, past the proxies we trust, to the first address we do not.
//
// Reading from the right is what makes the header usable: each proxy appends the
// address it received the request from, so the rightmost entry was written by the
// nearest proxy — the one we are talking to. Everything to its left is what that
// proxy was told, and is trustworthy only as far as the hops between us are. A
// fabricated X-Forwarded-For from a peer we do not trust is ignored entirely,
// which is the whole reason the trust list exists: without it a caller picks its
// own rate-limit bucket by choosing the header value.
func clientAddr(r *http.Request, trusted []netip.Prefix) string {
	peer := hostOnly(r.RemoteAddr)
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		// Not an address at all (a test's "pipe", say). Hand it back unchanged
		// rather than invent one.
		return peer
	}
	addr = addr.Unmap()
	if !trustedBy(addr, trusted) {
		return addr.String()
	}
	return forwardedClient(r, addr, trusted)
}

// forwardedClient resolves the client from X-Forwarded-For, given that the peer
// is a trusted proxy. It returns peer when the header is absent or malformed.
func forwardedClient(r *http.Request, peer netip.Addr, trusted []netip.Prefix) string {
	var hops []netip.Addr
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(header, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			a, err := netip.ParseAddr(part)
			if err != nil {
				// A hop we cannot read makes the rest of the chain
				// unverifiable, so the header is not trusted at all rather than
				// partially. Falling back to the peer is the safe direction: it
				// can only make the bucket coarser, never let a caller pick it.
				return peer.String()
			}
			hops = append(hops, a.Unmap())
		}
	}

	// Walk from the nearest hop outward, skipping proxies we trust. The first
	// address we do not trust is the client.
	for i := len(hops) - 1; i >= 0; i-- {
		if trustedBy(hops[i], trusted) {
			continue
		}
		return hops[i].String()
	}
	// Every hop is a trusted proxy, so the client is not in the chain: the
	// leftmost entry is the closest thing to an origin. With no header at all,
	// it is the peer.
	if len(hops) > 0 {
		return hops[0].String()
	}
	return peer.String()
}

// hostOnly strips the port from a RemoteAddr, leaving the host.
func hostOnly(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// trustedBy reports whether addr is inside any trusted prefix.
func trustedBy(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
