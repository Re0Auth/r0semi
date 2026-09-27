//go:build audit5

package zzprobe_federation

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

// newTestVault mirrors the fixture the federation package's own tests use: a real
// in-memory vault with a fixed local KEK, so the vault's audit-before-use and
// zeroization behaviour is present rather than stubbed.
func newTestVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("probe", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// mustPair encodes a binding secret exactly as federation.bindingSecret does, so
// the probe's vault payload is the real shape rather than a guess at it.
func mustPair(t *testing.T, access, refresh string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// httptestClient is the transport httptest.Server.Client() would build, without
// borrowing it from a server that is about to be closed.
func httptestClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // httptest only
	}
}
