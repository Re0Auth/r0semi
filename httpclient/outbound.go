package httpclient

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
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
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: cfg.ExpectContinueTimeout,
		ForceAttemptHTTP2:     true,
	}
}

// bulkheadTransport bounds the number of requests in flight at once.
type bulkheadTransport struct {
	next  http.RoundTripper
	slots chan struct{}
}

// Bulkhead bounds how many requests may be in flight through next at the same
// time. A request that finds the cap reached waits for a slot, and gives up if
// its context is cancelled first. maxConcurrent <= 0 disables the cap.
//
// Waiting rather than failing is deliberate: this is a proxy, and a read the
// user asked for is worth queueing for a moment. What it must not do is let one
// slow source turn into unbounded goroutines, each holding a buffered body.
//
// The slot is held until the response body is closed, not merely until the
// headers arrive. That distinction is the whole point here: RoundTrip returns as
// soon as the status line is in, and a caller that then reads a multi-megabyte
// body would be outside the cap if the slot had already been released. The
// caller must close the body — which the http.Client contract requires anyway —
// or the slot is never returned.
func Bulkhead(next http.RoundTripper, maxConcurrent int) http.RoundTripper {
	if maxConcurrent <= 0 {
		return next
	}
	return &bulkheadTransport{next: next, slots: make(chan struct{}, maxConcurrent)}
}

func (b *bulkheadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case b.slots <- struct{}{}:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}

	resp, err := b.next.RoundTrip(req)
	if err != nil {
		<-b.slots
		return nil, err
	}
	if resp.Body == nil {
		<-b.slots
		return resp, nil
	}
	release := func() { <-b.slots }
	resp.Body = &bulkheadBody{ReadCloser: resp.Body, release: release}
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
}

const defaultOutboundTimeout = 20 * time.Second

// NewOutboundClient builds the hardened client the data plane uses: a pooled
// transport, a per-request deadline, and a global in-flight cap. It is a plain
// *http.Client, so it satisfies Doer and can also be handed to code that wants a
// concrete client (the OAuth token exchange, say) — one client, one pool.
func NewOutboundClient(cfg OutboundConfig) *http.Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultOutboundTimeout
	}
	rt := http.RoundTripper(NewTransport(cfg.Transport))
	if cfg.MaxConcurrent > 0 {
		rt = Bulkhead(rt, cfg.MaxConcurrent)
	}
	return &http.Client{Timeout: cfg.Timeout, Transport: rt}
}

var _ Doer = (*http.Client)(nil)
