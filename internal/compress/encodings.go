package compress

import (
	"compress/gzip"
	"io"

	"github.com/klauspost/compress/zstd"
)

// GzipEncoding is the gzip content coding. It is the compatibility floor: every
// client that can receive a coding at all understands it, and it costs nothing
// beyond the standard library.
func GzipEncoding() Encoding {
	return Encoding{
		Name: "gzip",
		New:  func() WriteCloser { return gzip.NewWriter(io.Discard) },
	}
}

// ZstdEncoding is the zstd content coding (RFC 8878). It is preferred over gzip:
// for the small JSON bodies this service returns it compresses about as well and
// far faster. Default options can never fail, so the constructor does not return
// an error.
func ZstdEncoding() Encoding {
	return Encoding{
		Name: "zstd",
		New: func() WriteCloser {
			enc, err := zstd.NewWriter(io.Discard, zstd.WithEncoderLevel(zstd.SpeedDefault))
			if err != nil {
				panic("compress: zstd: " + err.Error())
			}
			return enc
		},
	}
}

// Default produces the built-in coding set in server preference order. Adding a
// coding later (brotli) means one Encoding here and nothing else: negotiation,
// Vary, the threshold and the guards are already coding-agnostic.
func Default() []Encoding {
	return []Encoding{ZstdEncoding(), GzipEncoding()}
}
