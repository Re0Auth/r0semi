//go:build audit5

package zzprobe_federation

import (
	"net/http"
	"net/http/httptest"
)

type httptestServer = httptest.Server

func newHTTPTestServer(h http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(h)
}
