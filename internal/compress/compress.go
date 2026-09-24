// Package compress is HTTP response compression as content negotiation: it
// picks a coding from the client's Accept-Encoding, wraps the response so the
// decision can wait until the body's content type and size are known, and leaves
// everything else — routing, error formats, framing — to the handler.
//
// The framework is the expensive part: q-value negotiation, Vary management, the
// size threshold, the already-encoded guard, and the route allow/deny predicate.
// Adding a coding once it exists is a handful of lines (see GzipEncoding /
// ZstdEncoding); that asymmetry is deliberate, so a later `br` is a small,
// reviewable change rather than a second redesign.
package compress

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// DefaultMinSize is the smallest body worth compressing. Below it the coding's
// header and CPU cost outweigh the bytes saved, and a small response is exactly
// where added latency is most visible.
const DefaultMinSize = 1024

// WriteCloser is a streaming compressor that can be retargeted. Both
// *gzip.Writer and *zstd.Encoder satisfy it, which is what lets the pool reuse
// them across requests instead of allocating per response.
type WriteCloser interface {
	io.WriteCloser
	// Reset retargets the writer at w and clears its state, so a pooled writer
	// can be reused.
	Reset(w io.Writer)
	// Flush emits whatever is buffered without ending the stream.
	Flush() error
}

// Encoding is one supported content coding.
type Encoding struct {
	// Name is the token used in Accept-Encoding and Content-Encoding, lowercase.
	Name string
	// New builds a fresh writer. It is called to seed and refill the pool; the
	// writer must be usable after a Reset.
	New func() WriteCloser
}

// Config wires the middleware.
type Config struct {
	// Encodings is the server's preference order, best first. Required.
	// A client's q-values always win; this order only breaks ties.
	Encodings []Encoding
	// MinSize overrides DefaultMinSize.
	MinSize int
	// Eligible decides, before the handler runs, whether a response may be
	// compressed at all. It is where a deployment keeps a coding off a URL that
	// must not be transformed (a token response, say). Default: everything.
	Eligible func(*http.Request) bool
	// CompressibleContentType decides, after the handler sets a Content-Type,
	// whether a body of that type is worth compressing. Default:
	// compressibleContentType.
	CompressibleContentType func(string) bool
	// OnNotAcceptable writes the 406 when the client refuses every coding we
	// offer and has also forbidden identity. When nil, a minimal problem+json
	// body is written. It exists so the caller owns its plane's error format.
	OnNotAcceptable func(http.ResponseWriter, *http.Request)
}

// Compressor negotiates and applies a content coding.
type Compressor struct {
	encodings  []Encoding
	names      []string
	minSize    int
	eligible   func(*http.Request) bool
	compressib func(string) bool
	notAccept  func(http.ResponseWriter, *http.Request)
	pools      map[string]*sync.Pool
}

// New validates the configuration and pre-creates one writer per coding, so a
// construction failure surfaces at startup rather than on the first request.
func New(cfg Config) (*Compressor, error) {
	if len(cfg.Encodings) == 0 {
		return nil, errors.New("compress: at least one encoding is required")
	}
	minSize := cfg.MinSize
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	eligible := cfg.Eligible
	if eligible == nil {
		eligible = func(*http.Request) bool { return true }
	}
	compressible := cfg.CompressibleContentType
	if compressible == nil {
		compressible = compressibleContentType
	}
	notAccept := cfg.OnNotAcceptable
	if notAccept == nil {
		notAccept = defaultNotAcceptable
	}

	c := &Compressor{
		encodings:  append([]Encoding(nil), cfg.Encodings...),
		minSize:    minSize,
		eligible:   eligible,
		compressib: compressible,
		notAccept:  notAccept,
		pools:      make(map[string]*sync.Pool, len(cfg.Encodings)),
	}
	seen := make(map[string]bool, len(cfg.Encodings))
	for _, e := range c.encodings {
		name := strings.ToLower(strings.TrimSpace(e.Name))
		if name == "" {
			return nil, errors.New("compress: encoding name is required")
		}
		if e.New == nil {
			return nil, errors.New("compress: encoding " + name + " has no constructor")
		}
		if seen[name] {
			return nil, errors.New("compress: duplicate encoding " + name)
		}
		seen[name] = true
		c.names = append(c.names, name)
		// Touch the constructor once: a coding that cannot be built must fail at
		// startup, not mid-response. The close is just the probe's teardown, so
		// its error carries nothing the caller could act on.
		w := e.New()
		_ = w.Close()
		enc := e
		c.pools[name] = &sync.Pool{New: func() any { return enc.New() }}
	}
	return c, nil
}

// Handler wraps next with negotiated compression.
func (c *Compressor) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A HEAD response has no body to compress, and an ineligible route must
		// never be transformed. Both pass straight through, untouched — including
		// no Vary, because the representation does not depend on Accept-Encoding.
		if r.Method == http.MethodHead || !c.eligible(r) {
			next.ServeHTTP(w, r)
			return
		}

		coding, acceptable := negotiate(r.Header.Get("Accept-Encoding"), c.names)
		if !acceptable {
			addVary(w.Header(), "Accept-Encoding")
			c.notAccept(w, r)
			return
		}
		if coding == "" {
			// The client does not accept any coding we offer (or sent no header at
			// all). Nothing can vary, so do not wrap and do not add Vary.
			next.ServeHTTP(w, r)
			return
		}

		cw := &responseWriter{ResponseWriter: w, c: c, coding: coding, status: http.StatusOK}
		next.ServeHTTP(cw, r)
		cw.finish()
	})
}

// negotiate implements RFC 9110 §12.5.3. It returns the chosen coding ("" for
// identity) and whether any acceptable representation exists at all. serverPref
// is in server preference order; a client's q-value always outranks it.
func negotiate(header string, serverPref []string) (string, bool) {
	if strings.TrimSpace(header) == "" {
		// Absent means "no preference" in the spec; in practice it means an old
		// client that would not understand a coding. Send identity.
		return "", true
	}
	q, star, hasStar := parseAcceptEncoding(header)

	// A coding's quality: an explicit entry, else the wildcard, else not offered.
	qOf := func(name string) (float64, bool) {
		if v, ok := q[name]; ok {
			return v, true
		}
		if hasStar {
			return star, true
		}
		return 0, false
	}

	best, bestQ := "", 0.0
	for _, name := range serverPref {
		v, ok := qOf(name)
		if !ok || v <= 0 {
			continue
		}
		// Strictly greater, so an equal q keeps the earlier (preferred) coding.
		if v > bestQ {
			best, bestQ = name, v
		}
	}
	if best != "" {
		return best, true
	}

	// No coding matched. Identity is acceptable unless explicitly refused, either
	// directly or by a wildcard refusal (RFC 9110 §12.5.3).
	identityQ := 1.0
	if v, ok := q["identity"]; ok {
		identityQ = v
	} else if hasStar {
		identityQ = star
	}
	if identityQ > 0 {
		return "", true
	}
	return "", false
}

// parseAcceptEncoding returns explicit codings with their q-values, plus the
// wildcard's q-value. A malformed q is treated as 0 (do not use that coding),
// which fails safe toward identity.
func parseAcceptEncoding(header string) (explicit map[string]float64, star float64, hasStar bool) {
	explicit = make(map[string]float64)
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ";")
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		if name == "" {
			continue
		}
		value := 1.0
		for _, param := range fields[1:] {
			param = strings.TrimSpace(param)
			if len(param) < 2 || !strings.EqualFold(param[:2], "q=") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(param[2:]), 64)
			if err != nil {
				value = 0
				break
			}
			if parsed < 0 {
				parsed = 0
			}
			if parsed > 1 {
				parsed = 1
			}
			value = parsed
		}
		if name == "*" {
			star, hasStar = value, true
			continue
		}
		explicit[name] = value
	}
	return explicit, star, hasStar
}

func (c *Compressor) acquire(name string, dst io.Writer) WriteCloser {
	w := c.pools[name].Get().(WriteCloser)
	w.Reset(dst)
	return w
}

// release closes the stream (finishing the frame) and returns the writer to its
// pool. A writer that cannot be closed is dropped rather than pooled.
func (c *Compressor) release(name string, w WriteCloser) {
	if err := w.Close(); err != nil {
		return
	}
	c.pools[name].Put(w)
}

// responseWriter buffers until it knows whether the body is worth compressing,
// which is only knowable after the content type and the first MinSize bytes.
type responseWriter struct {
	http.ResponseWriter
	c           *Compressor
	coding      string
	status      int
	wroteHeader bool
	buf         []byte
	skip        bool
	compressing bool
	enc         WriteCloser
}

func (w *responseWriter) Header() http.Header { return w.ResponseWriter.Header() }

// Unwrap exposes the original writer so http.ResponseController can reach it.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status

	h := w.Header()
	switch {
	case status < 200 || status == http.StatusNoContent || status == http.StatusNotModified:
		w.skip = true
	case h.Get("Content-Encoding") != "":
		// Already encoded by the handler (a pre-compressed asset, or a raw
		// upstream body) — never double-encode.
		w.skip = true
	case h.Get("Content-Range") != "":
		// Ranges address the untransformed representation.
		w.skip = true
	case hasNoTransform(h.Get("Cache-Control")):
		w.skip = true
	case !w.c.compressib(h.Get("Content-Type")):
		w.skip = true
	}
	if w.skip {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	// This response may be compressed or not depending on the client's
	// Accept-Encoding, so caches must key on it. Set before the header is written.
	addVary(h, "Accept-Encoding")
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.skip {
		return w.ResponseWriter.Write(p)
	}
	if w.compressing {
		return w.enc.Write(p)
	}
	w.buf = append(w.buf, p...)
	if len(w.buf) < w.c.minSize {
		return len(p), nil
	}
	w.startCompress()
	_, err := w.enc.Write(w.buf)
	w.buf = nil
	return len(p), err
}

// startCompress commits to the coding: the header is sent, Content-Length is
// dropped (it described the uncompressed body), and a pooled writer takes over.
func (w *responseWriter) startCompress() {
	w.compressing = true
	h := w.Header()
	h.Set("Content-Encoding", w.coding)
	h.Del("Content-Length")
	weakenETag(h)
	w.ResponseWriter.WriteHeader(w.status)
	w.enc = w.c.acquire(w.coding, w.ResponseWriter)
}

// Flush supports streaming: once a handler flushes, waiting for more bytes to
// cross the threshold is pointless, so a compressible response starts
// compressing now.
func (w *responseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.skip && !w.compressing {
		w.startCompress()
		if len(w.buf) > 0 {
			_, _ = w.enc.Write(w.buf)
			w.buf = nil
		}
	}
	if w.compressing {
		_ = w.enc.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// finish runs after the handler returns. If nothing was written yet, the body
// is below the threshold and is sent verbatim.
func (w *responseWriter) finish() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.compressing {
		w.c.release(w.coding, w.enc)
		w.enc = nil
		return
	}
	if w.skip {
		return
	}
	w.ResponseWriter.WriteHeader(w.status)
	if len(w.buf) > 0 {
		_, _ = w.ResponseWriter.Write(w.buf)
		w.buf = nil
	}
}

// addVary adds a Vary token if it is not already present, case-insensitively and
// across comma-separated values. It writes a single merged Vary line rather than
// appending a second field line: both are legal, but one line is what
// http.Header.Get and most caches read, and the difference is easy to miss.
func addVary(h http.Header, value string) {
	values := h.Values("Vary")
	for _, line := range values {
		for _, field := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(field), value) {
				return
			}
		}
	}
	values = append(append([]string(nil), values...), value)
	h.Set("Vary", strings.Join(values, ", "))
}

// hasNoTransform reports whether Cache-Control forbids transforming the body.
func hasNoTransform(cacheControl string) bool {
	for _, directive := range strings.Split(cacheControl, ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-transform") {
			return true
		}
	}
	return false
}

// weakenETag turns a strong validator into a weak one. The bytes on the wire no
// longer match the entity the handler hashed, and saying otherwise would let a
// cache or a range request trust a validator that is no longer true.
func weakenETag(h http.Header) {
	etag := h.Get("ETag")
	if etag == "" || strings.HasPrefix(etag, "W/") {
		return
	}
	h.Set("ETag", "W/"+etag)
}

// compressibleContentType is the default allow-list rule. It is deliberately a
// deny-by-default for anything already compressed (images, audio, video, fonts,
// archives), where a second pass saves nothing and costs CPU.
func compressibleContentType(contentType string) bool {
	mediaType := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	mediaType = strings.ToLower(mediaType)
	if mediaType == "" {
		return false
	}
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	if strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml") {
		return true
	}
	switch mediaType {
	case "application/json",
		"application/problem+json",
		"application/ld+json",
		"application/javascript",
		"application/ecmascript",
		"application/xml",
		"image/svg+xml":
		return true
	default:
		return false
	}
}

func defaultNotAcceptable(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotAcceptable)
	_, _ = io.WriteString(w, `{"code":"not_acceptable","status":406,"title":"Not acceptable"}`)
}

var (
	_ http.ResponseWriter = (*responseWriter)(nil)
	_ http.Flusher        = (*responseWriter)(nil)
)
