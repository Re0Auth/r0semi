//go:build audit5

// Package zzprobe_federation holds adversarial probes written by the federation /
// outbound-HTTP audit. They are deliberately in their own package so they cannot
// affect any production import graph. See docs/audit-5/BRIEF.md §4.
package zzprobe_federation

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/httpclient"
)

// ---------------------------------------------------------------------------
// A. The address predicate, enumerated.
//
// The project's claim (docs/architecture.md §"出站" and httpclient.TransportConfig)
// is: "private / loopback / link-local addresses are refused at the dial layer,
// after DNS resolution". This test asks the predicate about every range the audit
// brief names, so the answer is a table rather than a reading of the code.
// ---------------------------------------------------------------------------

func TestProbeIsPublicAddressCoversEverySpecialRange(t *testing.T) {
	deny := []struct {
		addr netip.Addr
		why  string
	}{
		{netip.MustParseAddr("127.0.0.1"), "IPv4 loopback"},
		{netip.MustParseAddr("127.255.255.254"), "IPv4 loopback block"},
		{netip.MustParseAddr("::1"), "IPv6 loopback"},
		{netip.MustParseAddr("10.0.0.1"), "RFC1918 10/8"},
		{netip.MustParseAddr("172.16.0.1"), "RFC1918 172.16/12"},
		{netip.MustParseAddr("192.168.1.1"), "RFC1918 192.168/16"},
		{netip.MustParseAddr("169.254.169.254"), "cloud metadata, IPv4 link-local"},
		{netip.MustParseAddr("169.254.0.1"), "IPv4 link-local"},
		{netip.MustParseAddr("fe80::1"), "IPv6 link-local unicast"},
		{netip.MustParseAddr("fc00::1"), "IPv6 unique-local fc00::/7"},
		{netip.MustParseAddr("fd00::1"), "IPv6 unique-local fd00::/8"},
		{netip.MustParseAddr("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "IPv6 unique-local upper edge"},
		{netip.MustParseAddr("::ffff:127.0.0.1"), "IPv4-mapped IPv6 loopback"},
		{netip.MustParseAddr("::ffff:169.254.169.254"), "IPv4-mapped metadata"},
		{netip.MustParseAddr("::ffff:10.0.0.1"), "IPv4-mapped RFC1918"},
		{netip.MustParseAddr("::ffff:100.64.0.1"), "IPv4-mapped CGNAT"},
		{netip.MustParseAddr("::ffff:192.0.0.1"), "IPv4-mapped IETF assignment"},
		{netip.MustParseAddr("::ffff:240.0.0.1"), "IPv4-mapped reserved"},
		{netip.MustParseAddr("::ffff:198.18.0.1"), "IPv4-mapped benchmarking"},
		{netip.MustParseAddr("::ffff:203.0.113.1"), "IPv4-mapped documentation"},
		{netip.MustParseAddr("0.0.0.0"), "unspecified IPv4"},
		{netip.MustParseAddr("0.1.2.3"), "0.0.0.0/8"},
		{netip.MustParseAddr("0.255.255.255"), "0.0.0.0/8 upper edge"},
		{netip.MustParseAddr("::"), "unspecified IPv6"},
		{netip.MustParseAddr("100.64.0.1"), "CGNAT 100.64/10"},
		{netip.MustParseAddr("100.127.255.255"), "CGNAT upper edge"},
		{netip.MustParseAddr("192.0.0.1"), "IETF protocol assignments"},
		{netip.MustParseAddr("192.0.2.1"), "TEST-NET-1"},
		{netip.MustParseAddr("198.18.0.1"), "benchmarking 198.18/15"},
		{netip.MustParseAddr("198.19.255.255"), "benchmarking upper edge"},
		{netip.MustParseAddr("198.51.100.1"), "TEST-NET-2"},
		{netip.MustParseAddr("203.0.113.1"), "TEST-NET-3"},
		{netip.MustParseAddr("240.0.0.1"), "reserved 240/4"},
		{netip.MustParseAddr("255.255.255.255"), "broadcast"},
		{netip.MustParseAddr("224.0.0.1"), "IPv4 multicast"},
		{netip.MustParseAddr("ff02::1"), "IPv6 multicast"},
		{netip.MustParseAddr("64:ff9b::7f00:1"), "NAT64 embedding 127.0.0.1"},
		{netip.MustParseAddr("64:ff9b::a9fe:a9fe"), "NAT64 embedding 169.254.169.254"},
		{netip.MustParseAddr("2001:db8::1"), "documentation 2001:db8::/32"},
		{netip.MustParseAddr("2002:7f00:0001::1"), "6to4 embedding 127.0.0.1"},
		{netip.MustParseAddr("2002:a9fe:a9fe::1"), "6to4 embedding 169.254.169.254"},
		// Edge cases the brief does not name but an attacker would try.
		{netip.MustParseAddr("192.0.0.170"), "NAT64 discovery 192.0.0.170"},
		{netip.MustParseAddr("::ffff:0.0.0.0"), "IPv4-mapped unspecified"},
		{netip.MustParseAddr("::ffff:0.1.2.3"), "IPv4-mapped 0/8"},
	}

	var leaked []string
	for _, c := range deny {
		if httpclient.IsPublicAddress(c.addr) {
			leaked = append(leaked, fmt.Sprintf("%s (%s) was judged PUBLIC", c.addr, c.why))
		}
	}
	if len(leaked) > 0 {
		t.Errorf("%d non-public addresses pass the guard:\n  %s", len(leaked), strings.Join(leaked, "\n  "))
	}

	// Non-vacuity: the predicate must still say yes to ordinary public addresses,
	// otherwise "everything is refused" would satisfy the loop above.
	//
	// `::ffff:8.8.8.8` is the Unmap control: the IPv4-mapped form of a public
	// address must stay public (a mapped address that flipped to non-public would
	// break every outbound call through a dual-stack resolver). It used to sit in
	// the deny list above — labelled "MUST stay public" while the loop demanded the
	// opposite — which made the whole guard fail on a correct predicate.
	//
	// `192.88.99.1` (RFC 3068 6to4 relay anycast) is deliberately not in
	// httpclient's non-public prefixes: RFC 7526 deprecated it and the audit's
	// verified federation findings record it as outside the threat model
	// (docs/audit-5/findings/federation.md). It is asserted public here and in
	// internal/zzprobe/pubaddr rather than left as a permanent red.
	for _, a := range []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("::ffff:8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("203.0.114.1"),
		netip.MustParseAddr("192.88.99.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("2001:4860:4860::8888"),
	} {
		if !httpclient.IsPublicAddress(a) {
			t.Errorf("public address %s was refused; the guard is over-broad", a)
		}
	}
}

// The guard is only a guard if the dialer actually consults it. This drives a
// real net.Dialer through the built transport and asserts the connection is
// refused for a loopback target — i.e. the check is on the dial path, not merely
// a predicate someone could forget to wire.
func TestProbeDenyPrivateAddressesBlocksTheDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reached the private listener")
	}))
	defer srv.Close()

	c := httpclient.NewOutboundClient(httpclient.OutboundConfig{
		Timeout:   3 * time.Second,
		Transport: httpclient.TransportConfig{DenyPrivateAddresses: true},
	})
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("DenyPrivateAddresses=true still reached a loopback source (%s): the guard is not on the dial path", srv.URL)
	}
	if !strings.Contains(err.Error(), "allow_private_addresses") {
		t.Fatalf("the refusal did not come from the address guard: %v", err)
	}

	// Negative control: without the flag the same client reaches it, so the
	// failure above is the guard and not a broken fixture.
	open := httpclient.NewOutboundClient(httpclient.OutboundConfig{Timeout: 3 * time.Second})
	resp, err = open.Get(srv.URL)
	if err != nil {
		t.Fatalf("control: the guard-off client could not reach the loopback source: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control: status = %d", resp.StatusCode)
	}
}

// A redirect onto a private address must be refused too. The claim in
// NewOutboundClient's comment is that the address guard holds "after DNS
// resolution", so a public host that answers 302 Location: http://127.0.0.1/ is
// the interesting shape.
//
// This cannot be driven through httptest loopback (the dial guard refuses the
// fixture itself), so it drives the guard directly at the dial address the
// transport would hand the kernel — which is exactly where the check lives.
func TestProbeDenyPrivateAddressRejectsEveryLocalNameLiteral(t *testing.T) {
	// The dial addresses Go's dialer produces for a redirect onto a local listener,
	// in the exact bracketed form it hands net.Dialer.Control.
	for _, raw := range []string{
		"127.0.0.1:80", "[::1]:80", "[::ffff:127.0.0.1]:80",
		"169.254.169.254:80", "[fd00::1]:80", "10.0.0.1:443", "0.0.0.0:80",
	} {
		host, _, err := net.SplitHostPort(raw)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q) failed: %v — denyPrivateAddress would refuse the dial with a "+
				"parse error rather than a policy error, which is a different bug", host, err)
		}
		if httpclient.IsPublicAddress(addr) {
			t.Errorf("dial address %s would be permitted", raw)
		}
	}
}

// TestProbeZonedIPv6DialAddressIsJudgedNotCrashed pins what the dial hook sees for
// an IPv6 link-local target with a scope id. It used to only print the parse
// results (Z16-6), so nothing guarded the property it names. The property is now
// asserted: the zone-qualified address parses (no crash, and the refusal is the
// link-local policy decision rather than a parse error) and is refused.
func TestProbeZonedIPv6DialAddressIsJudgedNotCrashed(t *testing.T) {
	zoned, err := netip.ParseAddr("fe80::1%eth0")
	if err != nil {
		t.Fatalf("netip.ParseAddr(\"fe80::1%%eth0\") = %v: the dial hook would refuse with a parse error "+
			"rather than the link-local policy error", err)
	}
	if zoned.Zone() != "eth0" {
		t.Errorf("the zone is %q, want eth0", zoned.Zone())
	}
	if httpclient.IsPublicAddress(zoned) {
		t.Errorf("the zone-qualified link-local address %s is judged public; the SSRF guard would dial it", zoned)
	}

	// Anti-vacuity: the same address without the zone is also non-public, so the
	// verdict is about the address and not the zone formatting.
	bare, err := netip.ParseAddr("fe80::1")
	if err != nil {
		t.Fatalf("netip.ParseAddr(\"fe80::1\") = %v", err)
	}
	if httpclient.IsPublicAddress(bare) {
		t.Errorf("the bare link-local address %s is judged public", bare)
	}
}

// ---------------------------------------------------------------------------
// B. The redirect policy, against Go's real net/http.
//
// NoCrossHostRedirects is the single guard that keeps a bearer token (and, on the
// token exchange, a refresh token plus the client secret) from following a 3xx to
// a host the operator never configured. The claim under test is "cross-host or
// downgraded redirects are refused". The variants below are the ones a naive
// string comparison lets through.
// ---------------------------------------------------------------------------

type hostRecorder struct {
	seen []string
	// follow is the Location the handler answers with.
	locations []string
}

func (h *hostRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	h.seen = append(h.seen, req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
	if len(h.locations) > 0 {
		loc := h.locations[0]
		h.locations = h.locations[1:]
		if loc != "" {
			return &http.Response{
				StatusCode: http.StatusFound,
				Status:     "302 Found",
				Header:     http.Header{"Location": []string{loc}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Request:    req,
	}, nil
}

// redirectProbe drives client through the redirect policy with a fake transport
// and reports every URL the transport was asked to fetch.
func redirectProbe(t *testing.T, start string, lastURL string, n int) []string {
	t.Helper()
	rec := &hostRecorder{}
	for i := 0; i < n; i++ {
		rec.locations = append(rec.locations, lastURL)
	}
	client := &http.Client{Transport: rec, CheckRedirect: httpclient.NoCrossHostRedirects, Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, start, nil)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret-token-value")
	resp, err := client.Do(req)
	if err != nil {
		// A refusal is an error; the interesting question is what got fetched
		// before the refusal, which rec.seen answers.
		return rec.seen
	}
	_ = resp.Body.Close()
	return rec.seen
}

func TestProbeRedirectPolicyAgainstHostVariants(t *testing.T) {
	const origin = "https://source.example"

	cases := []struct {
		name string
		loc  string
		// wantFetched is true when the redirect is allowed to reach the transport.
		wantFetched bool
		note        string
	}{
		{"identical host", "https://source.example/next", true, "control: same-host hops are legal"},
		{"identical host, explicit default port", "https://source.example:443/next", false, "host string differs, so it is refused — conservative, fine"},
		{"different host", "https://evil.example/next", false, ""},
		{"subdomain of the origin", "https://sub.source.example/next", false, ""},
		{"parent domain", "https://example/next", false, ""},
		{"scheme downgrade", "http://source.example/next", false, "the Authorization header would cross plaintext"},
		{"uppercase host", "https://SOURCE.EXAMPLE/next", false, "case variant of the same authority"},
		{"trailing dot", "https://source.example./next", false, "FQDN root-dot form of the same name"},
		{"percent-encoded host octet", "https://%73ource.example/next", false, "decodes to source.example"},
		// userinfo naming a different host while the authority is the origin host:
		// u.Host is what the guard compares, and it is the origin, so this is
		// ALLOWED. That is correct for the guard (the request still goes to
		// source.example) but it means "the URL string looked like another host"
		// is not what is being checked — a point worth pinning.
		{"userinfo naming another host", "https://evil.example@source.example/next", true, "u.Host is source.example"},
		{"userinfo, hostile", "https://source.example@evil.example/next", false, "the classic @ misread"},
		{"different port", "https://source.example:8443/next", false, "same host, other listener"},
		{"host suffix trick", "https://source.example.evil.example/next", false, ""},
		{"host prefix trick", "https://evil-source.example/next", false, ""},
		{"empty host (scheme-relative)", "//evil.example/next", false, "inherits the origin scheme"},
		{"IPv4 literal instead of name", "https://93.184.216.34/next", false, ""},
		{"hex IPv4 literal", "https://0x5db8d822/next", false, "Go may normalise this at parse time"},
		{"decimal IPv4 literal", "https://157.240.34.34/next", false, ""},
		{"trailing whitespace", "https://evil.example/next ", false, ""},
		{"tab inside host", "https://evil.exa\tmple/next", false, "Go rejects control bytes"},
		{"CRLF in Location", "https://evil.example/next\r\nX-Injected: 1", false, ""},
		{"fragment only", "https://source.example/next#frag", true, "same host; fragments never reach the server"},
		{"path traversal", "https://source.example/../../next", true, "same host; path is not an authority"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := redirectProbe(t, origin+"/start", tc.loc, 1)
			fetched := len(seen) > 1
			if fetched != tc.wantFetched {
				t.Errorf("redirect %q: fetched=%v (want %v); transport saw %v %s",
					tc.loc, fetched, tc.wantFetched, seen, tc.note)
			}
		})
	}
}

// The brief's question: "can a redirect chain reach the credential-bearing hop
// before being refused?" This asserts what the transport actually saw on a chain
// that starts same-host and then leaves, and checks where the Authorization
// header was present.
func TestProbeRedirectChainCredentialReach(t *testing.T) {
	const origin = "https://source.example"

	// hop 1 same host (allowed), hop 2 cross host (must be refused).
	rec := &chainRecorder{hops: []string{
		"https://source.example/one",
		"https://evil.example/two",
		"https://evil.example/three",
	}}
	client := &http.Client{Transport: rec, CheckRedirect: httpclient.NoCrossHostRedirects, Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, origin+"/start", nil)
	req.Header.Set("Authorization", "Bearer secret-token-value")
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}

	for _, got := range rec.authSeen {
		if strings.Contains(got.host, "evil.example") {
			t.Errorf("the Authorization header was attached to a cross-host hop: %s => %q", got.host, got.auth)
		}
	}
	// The chain must have stopped at the first cross-host hop.
	for _, got := range rec.requested {
		if strings.Contains(got, "evil.example/three") {
			t.Errorf("the chain continued past the refusal: %v", rec.requested)
		}
	}
	t.Logf("requested=%v auth=%+v err=%v", rec.requested, rec.authSeen, err)
}

type chainRecorder struct {
	hops      []string
	i         int
	requested []string
	authSeen  []struct{ host, auth string }
}

func (c *chainRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	c.requested = append(c.requested, req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
	c.authSeen = append(c.authSeen, struct{ host, auth string }{req.URL.Host, req.Header.Get("Authorization")})
	if c.i < len(c.hops) {
		loc := c.hops[c.i]
		c.i++
		return &http.Response{
			StatusCode: http.StatusFound, Status: "302 Found",
			Header:  http.Header{"Location": []string{loc}},
			Body:    io.NopCloser(strings.NewReader("")),
			Request: req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK",
		Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: req,
	}, nil
}

// 307/308 replay the body verbatim. The brief asks whether a credential-bearing
// refresh_token + client_secret form body can survive a same-host-then-cross-host
// 307 chain. This drives exactly that and records which hop saw the body.
func TestProbe307ReplayOfTokenFormBody(t *testing.T) {
	const origin = "https://source.example"
	const form = "grant_type=refresh_token&refresh_token=RT-SECRET&client_secret=CS-SECRET"

	rec := &chainRecorder{hops: []string{
		"https://source.example/token", // same host: allowed
		"https://evil.example/token",   // cross host: must be refused
	}}
	client := &http.Client{Transport: bodyRecorder{inner: rec}, CheckRedirect: httpclient.NoCrossHostRedirects, Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if br, ok := client.Transport.(bodyRecorder); ok {
		for _, b := range br.seenBodies {
			t.Logf("hop body=%q", b)
		}
		for _, h := range br.seenHosts {
			if strings.Contains(h, "evil.example") {
				t.Errorf("a cross-host hop received the token form body (%s)", h)
			}
		}
	}
	t.Logf("requested=%v err=%v", rec.requested, err)
}

type bodyRecorder struct {
	inner      http.RoundTripper
	seenBodies []string
	seenHosts  []string
}

func (b bodyRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	body := ""
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		body = string(raw)
		if req.GetBody != nil {
			if fresh, err := req.GetBody(); err == nil {
				req.Body = fresh
			}
		} else {
			req.Body = io.NopCloser(strings.NewReader(body))
		}
	}
	b.seenBodies = append(b.seenBodies, body)
	b.seenHosts = append(b.seenHosts, host)
	return b.inner.RoundTrip(req)
}

// ---------------------------------------------------------------------------
// C. Host normalisation: what Go itself does before the policy sees a URL.
// ---------------------------------------------------------------------------

// TestProbeURLHostNormalisation pins that the host the redirect policy compares is
// the one Go's own URL parser reports, not a substring of the raw URL. It used to
// only print the parsed parts (Z16-6), so the claim its name makes had no guard.
// The attacker-shaped forms — a userinfo prefix, a fragment or a query carrying
// "@source.example" — must still name evil.example as the host.
func TestProbeURLHostNormalisation(t *testing.T) {
	// Ordinary normalisation: the policy's own hostname is the configured source.
	// A URL Go refuses to parse is refused before the policy sees a host, which is
	// the safe direction, so a parse error is accepted here but counted so the loop
	// cannot pass by parsing nothing.
	parsed := 0
	for _, raw := range []string{
		"HTTPS://Source.Example/Path",
		"https://SOURCE.EXAMPLE/",
		"https://source.example:443/",
		"https://source.example./",
		"https://%73ource.example/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Logf("url.Parse(%q) = %v (refused before the host policy sees it)", raw, err)
			continue
		}
		parsed++
		if got := strings.TrimSuffix(u.Hostname(), "."); !strings.EqualFold(got, "source.example") {
			t.Errorf("url.Parse(%q).Hostname() = %q, want source.example", raw, got)
		}
	}
	if parsed < 4 {
		t.Fatalf("only %d of the normalisation cases parsed; the host assertions above are near-vacuous", parsed)
	}

	// The attacker forms: the host Go reports is the one after the '@' (userinfo)
	// or the one before '#'/'?', never source.example. A naive `strings.Contains`
	// comparison would read the decoy and follow the request to another origin.
	for _, raw := range []string{
		"https://source.example@evil.example/",
		"https://evil.example#@source.example",
		"https://evil.example?@source.example",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Errorf("url.Parse(%q) = %v", raw, err)
			continue
		}
		if strings.EqualFold(u.Hostname(), "source.example") {
			t.Errorf("url.Parse(%q).Hostname() = source.example: a naive comparison would mistake the "+
				"userinfo/fragment for the configured host and follow the request off-origin", raw)
		}
		if !strings.EqualFold(u.Hostname(), "evil.example") {
			t.Errorf("url.Parse(%q).Hostname() = %q, want evil.example", raw, u.Hostname())
		}
	}
}
