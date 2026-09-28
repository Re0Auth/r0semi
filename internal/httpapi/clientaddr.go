package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientAddrHeader names the header a deployment declares its nearest reverse proxy
// WRITES with the client address.
//
// It is a deployment-level statement rather than a request-level one, because
// nothing in a request can prove who wrote a header. The distinction matters
// exactly once — the rate limiter's bucket key — and it is the difference between
// a budget per client and a budget the client chooses for itself.
type ClientAddrHeader int

const (
	// ClientAddrPeer reads no header: the peer address is the client.
	//
	// This is the zero value, and it is the only safe answer for a deployment whose
	// proxy forwards the caller's own X-Forwarded-For verbatim — a case no parser
	// can detect, which is why it must be the default rather than a fallback.
	ClientAddrPeer ClientAddrHeader = iota
	// ClientAddrXForwardedFor takes the RIGHTMOST entry of X-Forwarded-For, and
	// only from a peer inside Config.TrustedProxies.
	//
	// Setting it asserts that the nearest reverse proxy OVERWRITES that header
	// (`proxy_set_header X-Forwarded-For $remote_addr;`) or appends to it
	// (`$proxy_add_x_forwarded_for`). A proxy that passes the caller's own value
	// through verbatim hands the caller its bucket key, and no setting can detect
	// that from the request.
	ClientAddrXForwardedFor
)

// String names the mode for logs and config diagnostics.
func (h ClientAddrHeader) String() string {
	if h == ClientAddrXForwardedFor {
		return "x-forwarded-for"
	}
	return "none"
}

// ParseClientAddrHeader reads a configured value. Anything but "none" and
// "x-forwarded-for" is an error rather than a silent fallback: a mistyped name that
// quietly turns attribution off is the failure this option exists to prevent, and
// it would look applied in the config file.
func ParseClientAddrHeader(v string) (ClientAddrHeader, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none":
		return ClientAddrPeer, nil
	case "x-forwarded-for":
		return ClientAddrXForwardedFor, nil
	default:
		return ClientAddrPeer, fmt.Errorf("%q is not \"none\" or \"x-forwarded-for\"", v)
	}
}

// clientAddr returns the address a request should be attributed to.
//
// The rate limiter's bucket key is derived from it, so this is the one function in
// the package that must not return a value the caller wrote. The peer address is
// the answer unless the deployment declares BOTH that the peer is its own reverse
// proxy (trustedProxies) and which header that proxy writes (header). With no such
// declaration a fabricated X-Forwarded-For is ignored entirely — which is the whole
// reason both settings exist.
func clientAddr(r *http.Request, trusted []netip.Prefix, header ClientAddrHeader) string {
	peer := hostOnly(r.RemoteAddr)
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		// Not an address at all (a test's "pipe", say). Hand it back unchanged
		// rather than invent one.
		return peer
	}
	addr = addr.Unmap()
	if header != ClientAddrXForwardedFor || !trustedBy(addr, trusted) {
		return addr.String()
	}
	return forwardedClient(r, addr, trusted)
}

// forwardedClient resolves the client from the header the nearest proxy wrote,
// given that the peer is a trusted proxy.
//
// It reads exactly ONE value — the rightmost entry — and never walks leftward.
// Each proxy appends what it saw, so the rightmost entry is what our nearest proxy
// wrote; everything to its left is what that proxy was told, which is the caller's
// own text.
//
// Walking left to the first untrusted hop was the defect. It returns a
// caller-written address in two shapes that are ordinary in production: a proxy
// that forwards the caller's header verbatim (nginx redefines only Host and
// Connection by default), and a chain where the appended hop is itself inside the
// trust list (k8s SNAT, a service mesh, an internal load balancer). The old
// "every hop is trusted" branch was worse still: it returned the leftmost entry,
// which is caller-written by construction.
//
// An entry that cannot be parsed, or one inside trusted, yields the peer. The
// header said nothing usable and the peer is the coarser but real answer; there is
// deliberately no third option, because a bucket key is either server-observed or
// caller-chosen.
func forwardedClient(r *http.Request, peer netip.Addr, trusted []netip.Prefix) string {
	hop, ok := rightmostHop(r)
	if !ok || trustedBy(hop, trusted) {
		return peer.String()
	}
	return hop.String()
}

// rightmostHop returns the last address in X-Forwarded-For, across repeated header
// lines and comma-separated entries, or false when there is none or it is
// unreadable.
func rightmostHop(r *http.Request) (netip.Addr, bool) {
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(values[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			part := strings.TrimSpace(parts[j])
			if part == "" {
				continue
			}
			a, err := netip.ParseAddr(part)
			if err != nil {
				// A hop we cannot read makes the value unverifiable, so the header
				// is not trusted at all rather than partially. Falling back to the
				// peer can only make the bucket coarser, never let a caller pick it.
				return netip.Addr{}, false
			}
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
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
