//go:build audit5

// Package zzprobe_verifyfederation is the adversarial verifier's probe package.
//
// It exists to REFUTE the federation audit's findings where they do not survive,
// and to confirm only what reproduces from a probe that can fail. It is
// deliberately independent of internal/zzprobe/federation and
// internal/zzprobe/federationhttp: those are the reported agent's files and are
// neither imported nor edited here.
package zzprobe_verifyfederation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/vault"
)

func kekBytes() []byte { return bytes.Repeat([]byte{0x17}, 32) }

func newTestVault(t *testing.T) vault.Service {
	t.Helper()
	return newTestVaultFromRepo(t, vault.NewMemoryRepo())
}

func newTestVaultFromRepo(t *testing.T, repo vault.Repo) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("verify", kekBytes())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(repo, wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

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

// secretOf reads a binding secret back out of the vault, so a probe can tell
// "the refresh wrote a new secret" apart from "the old secret is still there".
func secretOf(t *testing.T, ctx context.Context, v vault.Service, id vault.Identity) (map[string]string, bool) {
	t.Helper()
	var out map[string]string
	err := v.Use(ctx, id, func(p []byte) error { return json.Unmarshal(p, &out) })
	if err != nil {
		return nil, false
	}
	return out, true
}

// recordingServer answers every request with one body and records the request URI.
func recordingServer(t *testing.T, log *[]string, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if log != nil {
			*log = append(*log, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newAuditLogger() *audit.MemoryLogger { return audit.NewMemoryLogger() }
