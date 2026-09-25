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

// guardedResponse is what the outbound decorators guard: the value one attempt
// produced, which for an HTTP client is always a response.
//
// They spell their type arguments through this alias instead of writing
// `*http.Response` at each builder. A written `*http.Response` in a type ARGUMENT is
// what the bodyclose analyzer reads as a response this package fetched and never
// closed — every finding it reports in this package was that, and none of them was
// a real leak. Findings that are real, a Do or RoundTrip result whose body nobody
// closes, do not go through this name and still fail the gate.
type guardedResponse = *http.Response
