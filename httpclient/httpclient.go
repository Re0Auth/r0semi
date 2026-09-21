// Package httpclient defines the outbound HTTP capability. Adapters and the
// federation layer never construct their own *http.Client; they take a Doer.
// That keeps connection pooling, timeouts, proxies and instrumentation under the
// caller's control, and makes adapters trivial to test against an httptest
// server.
package httpclient

import "net/http"

// Doer sends an HTTP request and returns its response. *http.Client implements
// it.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}
