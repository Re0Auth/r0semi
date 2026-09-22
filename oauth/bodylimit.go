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
