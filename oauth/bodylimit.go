package oauth

import (
	"errors"
	"net/http"
)

// MaxFormBytes caps how large a request body either OAuth plane will read.
//
// The standard library already refuses to parse a form over 10 MB, which is a lot
// of memory to spend on requests whose real size is a few hundred bytes — and a
// caller can open many at once. The rate limiter in front of the protocol plane
// bounds the rate; it says nothing about the size.
const MaxFormBytes = 64 << 10

// ErrBodyTooLarge reports a request whose declared body already exceeds
// MaxFormBytes.
var ErrBodyTooLarge = errors.New("oauth: request body too large")

// LimitFormBody caps the request body, and reports a declared length that is over
// the limit before anything is read.
//
// It returns the error instead of writing a response on purpose. The two planes
// render refusals differently and that separation is the thing this service does
// not share between them, so a helper that wrote its own body would be the first
// crack in it; each plane turns this into its own shape.
func LimitFormBody(w http.ResponseWriter, r *http.Request) error {
	// A negative length means "unknown" — a chunked body — so this comparison is
	// false there and the cap is enforced while reading instead.
	if r.ContentLength > MaxFormBytes {
		return ErrBodyTooLarge
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	return nil
}

// IsBodyTooLarge reports whether err is the overflow MaxBytesReader raises once a
// body past MaxFormBytes is read — the shape a chunked/gzip body with no declared
// length takes when ParseForm reads it.
//
// LimitFormBody's declared-length pre-check is the only path that returns
// ErrBodyTooLarge directly, so a caller that classifies every ParseForm error as
// "malformed form body" reports an undeclared oversized body as a 400 rather than
// the 413 the cap promises (S01-13/KIT-8). The three ParseForm call sites
// (upstreamkit token/revoke/cascade) should answer 413 when this is true; the
// helper lives here, next to the cap and the sentinel, so they share one
// classification.
func IsBodyTooLarge(err error) bool {
	return errors.As(err, new(*http.MaxBytesError))
}

// FormReadStatus maps an error from reading a request form to the status an OAuth
// plane answers. A body that overflowed the shared cap is 413; every other read
// or parse failure is the 400 a malformed form has always produced.
//
// It is the one classification the callers share (S01-13/KIT-8): the kit's three
// ParseForm sites all map through this, so the cap cannot become a 400 on one
// endpoint and a 413 on another. Each plane still renders its own error shape —
// this returns a status, not a response.
func FormReadStatus(err error) int {
	if IsBodyTooLarge(err) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
