package httpclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/failsafe-go/failsafe-go/bulkhead"
)

// TransportConfig tunes the connection pool of an outbound *http.Transport.
//
// It exists because the standard library's defaults are wrong for this
// deployment's shape. http.DefaultTransport keeps only two idle connections per
// host; a proxy that calls one data source on behalf of every user would then
// discard and redial a connection for nearly every request, spending the
// upstream's rate limit on handshakes and leaving sockets in TIME_WAIT.
type TransportConfig struct {
	// MaxIdleConns caps idle connections across all hosts.
	MaxIdleConns int
	// MaxIdleConnsPerHost caps idle connections to a single host. This is the
	// one that matters: the standard library stops at 2.
	MaxIdleConnsPerHost int
	// IdleConnTimeout is how long an idle connection is kept before it is closed.
	IdleConnTimeout time.Duration
	// DialTimeout bounds the TCP connect.
	DialTimeout time.Duration
	// TLSHandshakeTimeout bounds the TLS handshake.
	TLSHandshakeTimeout time.Duration
	// ResponseHeaderTimeout bounds the wait for the upstream's response headers,
	// which is where a hung source shows up. It should sit below the client's
	// overall Timeout so the error names the headers rather than the deadline.
	ResponseHeaderTimeout time.Duration
	// ExpectContinueTimeout bounds the wait for a 100-continue.
	ExpectContinueTimeout time.Duration
	// DenyPrivateAddresses refuses a connection whose resolved address is not
	// public. It is checked at dial time, on the address the kernel is about to be
	// given, so it holds after DNS resolution — the point being that a name which
	// resolved to a public address at configuration time and to 169.254.169.254 at
	// request time is refused. Off by default because self-hosted data sources on a
	// private network are a supported shape; a public deployment turns it on.
	DenyPrivateAddresses bool
}

// DefaultTransportConfig is the pool sizing for a client that talks to a small
// number of data sources on behalf of many users.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		DialTimeout:           10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// NewTransport builds a pooled transport from cfg, taking any zero field from
// DefaultTransportConfig.
func NewTransport(cfg TransportConfig) *http.Transport {
	def := DefaultTransportConfig()
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = def.MaxIdleConns
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = def.MaxIdleConnsPerHost
	}
	if cfg.IdleConnTimeout <= 0 {
		cfg.IdleConnTimeout = def.IdleConnTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = def.DialTimeout
	}
	if cfg.TLSHandshakeTimeout <= 0 {
		cfg.TLSHandshakeTimeout = def.TLSHandshakeTimeout
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = def.ResponseHeaderTimeout
	}
	if cfg.ExpectContinueTimeout <= 0 {
		cfg.ExpectContinueTimeout = def.ExpectContinueTimeout
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}
			if cfg.DenyPrivateAddresses {
				// Control rather than a check on the URL: this runs on the resolved
				// address, so it also covers a hostname the peer's DNS has been made
				// to answer differently than it did when the source was registered.
				dialer.Control = denyPrivateAddress
			}
			return dialer.DialContext(ctx, network, address)
		},
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: cfg.ExpectContinueTimeout,
		ForceAttemptHTTP2:     true,
	}
}

// nonPublicPrefixes are address blocks that are not public but that
// IsPrivate/IsLoopback/IsLinkLocalUnicast do not already report: carrier-grade
// NAT, IETF protocol assignments, the documentation ranges, benchmarking, the
// reserved block, and the two IPv6 forms that embed an IPv4 address.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: the low 32 bits are an IPv4 address
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4: same embedding
}

// IsPublicAddress reports whether addr is one an outbound client may connect to
// when private addresses are refused.
//
// It is deliberately an allow-list of what is left after the special ranges are
// removed, rather than a deny-list of "interesting" addresses: the ranges an
// attacker reaches for are the ones that mean something locally (loopback, the
// link-local metadata address, the private networks), and a deny-list would have
// to keep up with them.
func IsPublicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// denyPrivateAddress is a net.Dialer.Control hook: it is handed the address about
// to be dialed, after resolution, and refuses it when it is not public.
func denyPrivateAddress(network, address string, _ syscall.RawConn) error {
	if network == "unix" || network == "unixgram" || network == "unixpacket" {
		// Not reachable through this transport, and there is no IP address to judge.
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("httpclient: cannot read the dial address %q: %w", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("httpclient: cannot read the dial address %q: %w", host, err)
	}
	if !IsPublicAddress(addr) {
		return fmt.Errorf("httpclient: refusing to connect to %s: %s is not a public address "+
			"(set upstream.allow_private_addresses to permit one)", address, addr)
	}
	return nil
}

// targetAddressGuard refuses a request whose TARGET is not public when a proxy
// will carry it (S06-2).
//
// The dial-time Control hook only sees the address the kernel is about to be
// given. When http.ProxyFromEnvironment supplies a proxy, that address is the
// PROXY's: the target is never dialed here, so a request to 10.0.0.5 sailed
// through against a public proxy. This guard resolves the target itself before
// the request leaves, so "the guard is on" means the destination was judged.
//
// It is deliberately inert when no proxy applies: there the direct dial's
// Control hook already judges the resolved address, which is strictly stronger
// because it cannot be raced by a second DNS answer. A proxy necessarily
// resolves the target on our behalf, so with a proxy this is a pre-flight
// decision and the proxy could still be steered to a different address; that
// residual is why the check fails closed on ANY non-public answer.
type targetAddressGuard struct{ next http.RoundTripper }

func (g *targetAddressGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: cannot resolve the proxy for %s: %w", req.URL.Redacted(), err)
	}
	if proxyURL != nil {
		if err := denyPrivateTarget(req.Context(), req.URL); err != nil {
			return nil, err
		}
	}
	return g.next.RoundTrip(req)
}

// denyPrivateTarget refuses a target URL whose every resolved address is not
// public. A name that resolves to a mix is refused: one reachable private
// address is enough to reach something the operator did not intend.
func denyPrivateTarget(ctx context.Context, u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("httpclient: refusing a request to %s: no host to judge", u.Redacted())
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !IsPublicAddress(addr) {
			return privateTargetError(u, addr)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("httpclient: cannot resolve the target %s: %w", u.Redacted(), err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("httpclient: the target %s resolved to no address", u.Redacted())
	}
	for _, addr := range addrs {
		if !IsPublicAddress(addr) {
			return privateTargetError(u, addr)
		}
	}
	return nil
}

func privateTargetError(u *url.URL, addr netip.Addr) error {
	return fmt.Errorf("httpclient: refusing to connect to %s: %s is not a public address "+
		"(set upstream.allow_private_addresses to permit one)", u.Redacted(), addr)
}

// bulkheadTransport bounds the number of requests in flight at once.
type bulkheadTransport struct {
	next http.RoundTripper
	// The permit is taken and returned by hand rather than by running the
	// request through the policy, because the permit has to outlive RoundTrip:
	// see Bulkhead.
	bulkhead bulkhead.Bulkhead[guardedResponse]
}

// Bulkhead bounds how many requests may be in flight through next at the same
// time. A request that finds the cap reached waits for a permit, and gives up if
// its context is cancelled first. maxConcurrent <= 0 disables the cap.
//
// Waiting rather than failing is deliberate: this is a proxy, and a read the
// user asked for is worth queueing for a moment. What it must not do is let one
// slow source turn into unbounded goroutines, each holding a buffered body.
//
// The permit is held until the response body is closed, not merely until the
// headers arrive. That distinction is the whole point here: RoundTrip returns as
// soon as the status line is in, and a caller that then reads a multi-megabyte
// body would be outside the cap if the permit had already been released. It is
// why the permit is acquired and released explicitly: a failsafe policy's scope
// is the executed function, and the work being bounded here ends when the caller
// stops reading, not when RoundTrip returns. The caller must close the body —
// which the http.Client contract requires anyway — or the permit is never
// returned.
func Bulkhead(next http.RoundTripper, maxConcurrent int) http.RoundTripper {
	if maxConcurrent <= 0 {
		return next
	}
	return &bulkheadTransport{
		next:     next,
		bulkhead: bulkhead.NewBuilder[guardedResponse](uint(maxConcurrent)).Build(),
	}
}

func (b *bulkheadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// AcquirePermit returns the request's own context error when the caller
	// gives up waiting, which is the error the caller can act on.
	if err := b.bulkhead.AcquirePermit(req.Context()); err != nil {
		return nil, err
	}

	resp, err := b.next.RoundTrip(req)
	if err != nil {
		b.bulkhead.ReleasePermit()
		return nil, err
	}
	if resp.Body == nil {
		b.bulkhead.ReleasePermit()
		return resp, nil
	}
	resp.Body = &bulkheadBody{ReadCloser: resp.Body, release: b.bulkhead.ReleasePermit}
	return resp, nil
}

// bulkheadBody returns the slot when the body is closed. Close is idempotent,
// because the standard library and callers alike may close a body more than once.
type bulkheadBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (b *bulkheadBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

// OutboundConfig describes one outbound client.
type OutboundConfig struct {
	// Timeout is the deadline for a whole request, the wait for a bulkhead slot
	// included. Defaults to 20s.
	Timeout time.Duration
	// MaxConcurrent caps requests in flight; <= 0 leaves it uncapped.
	MaxConcurrent int
	// Transport tunes the connection pool.
	Transport TransportConfig
	// Breaker, when set, adds a per-host circuit breaker. It sits outside the
	// bulkhead, so a host that is down is skipped without spending a slot.
	Breaker *BreakerOptions
}

const defaultOutboundTimeout = 20 * time.Second

// NoCrossHostRedirects is the redirect policy for every outbound client: a hop
// that changes the scheme or the host is refused, and the refusal is an error
// rather than a response the caller might mistake for the peer's answer.
//
// These calls carry material a redirect target has no business receiving — a
// bearer token in the Authorization header, and on the token exchange a refresh
// token and the client secret in the form body. Redirects were being followed by
// default, and the standard library only strips Authorization when the
// destination is outside the same domain (net/http's shouldCopyHeaderOnRedirect),
// so a sibling host keeps the header; the body is not stripped for any host on
// 307/308, because bodies are replayed verbatim. A source that is compromised,
// merely misconfigured, or reachable through a hijacked DNS answer could
// therefore point a credential at a host of its choosing — and on the raw
// passthrough the response would come back to the caller, making the service an
// SSRF pivot as well.
//
// The only safe answer to "go somewhere else" from an API endpoint is to stop:
// the operator configured the endpoint, and a redirect is not something that
// config said. Same-host redirects are allowed because they cannot change who
// receives the request.
func NoCrossHostRedirects(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	origin := via[0].URL
	if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
		// Hosts only, no paths or queries: this error is logged, and a URL on the
		// wire here can carry a code or a token.
		return fmt.Errorf("httpclient: refused a redirect from %s://%s to %s://%s",
			origin.Scheme, origin.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// NewOutboundClient builds the hardened client the data plane uses: a pooled
// transport, a per-request deadline, and a global in-flight cap. It is a plain
// *http.Client, so it satisfies Doer and can also be handed to code that wants a
// concrete client (the OAuth token exchange, say) — one client, one pool.
//
// Redirects that leave the origin host are refused (NoCrossHostRedirects); see
// that function for what following them used to cost.
func NewOutboundClient(cfg OutboundConfig) *http.Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultOutboundTimeout
	}
	rt := http.RoundTripper(NewTransport(cfg.Transport))
	if cfg.MaxConcurrent > 0 {
		rt = Bulkhead(rt, cfg.MaxConcurrent)
	}
	if cfg.Breaker != nil {
		// Outside the bulkhead: an open breaker must reject before a slot is taken.
		rt = CircuitBreaker(rt, *cfg.Breaker)
	}
	if cfg.Transport.DenyPrivateAddresses {
		// Outermost: judge the destination before a proxy can carry the request,
		// and before a breaker or bulkhead slot is spent on it (S06-2). Without a
		// proxy this is inert; the dial's Control hook does the judging.
		rt = &targetAddressGuard{next: rt}
	}
	return &http.Client{
		Timeout:       cfg.Timeout,
		Transport:     rt,
		CheckRedirect: NoCrossHostRedirects,
	}
}

var _ Doer = (*http.Client)(nil)
