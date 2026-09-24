package oauth

import (
	"context"
	"errors"
	"testing"
)

// The point of hashing is that a dump of the store is not a set of usable
// credentials. This test asserts on the memory maps directly, which is the only
// place the at-rest form is observable.
func TestMemoryStoreKeysByHashNotPlaintext(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	const (
		accessValue  = "at-plaintext-value"
		refreshValue = "rt-plaintext-value"
		codeValue    = "code-plaintext-value"
		deviceValue  = "device-plaintext-value"
	)

	if err := store.SaveAccess(ctx, accessValue, AccessToken{ClientID: "c"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRefresh(ctx, refreshValue, RefreshToken{ClientID: "c"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCode(ctx, codeValue, AuthorizationCode{ClientID: "c"}); err != nil {
		t.Fatal(err)
	}

	devices := NewMemoryDeviceStore()
	if err := devices.SaveDevice(ctx, deviceValue, DeviceAuthorizationRecord{UserCode: "BCDF-GHJK"}); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	for name, m := range map[string]map[string]bool{
		"access":  keys(store.access),
		"refresh": keys(store.refresh),
		"codes":   keys(store.codes),
	} {
		for _, plaintext := range []string{accessValue, refreshValue, codeValue} {
			if m[plaintext] {
				t.Fatalf("%s store is keyed by the plaintext token", name)
			}
		}
	}
	if _, ok := store.access[TokenHash(accessValue)]; !ok {
		t.Fatal("access token is not keyed by its hash")
	}
	if _, ok := store.refresh[TokenHash(refreshValue)]; !ok {
		t.Fatal("refresh token is not keyed by its hash")
	}
	if _, ok := store.codes[TokenHash(codeValue)]; !ok {
		t.Fatal("authorization code is not keyed by its hash")
	}

	devices.mu.Lock()
	defer devices.mu.Unlock()
	if _, leaked := devices.byDev[deviceValue]; leaked {
		t.Fatal("device store is keyed by the plaintext device code")
	}
	if _, ok := devices.byDev[TokenHash(deviceValue)]; !ok {
		t.Fatal("device code is not keyed by its hash")
	}
}

func keys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// Lookups must still work end to end after the hashing change.
func TestMemoryStoreLookupsStillWork(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.SaveAccess(ctx, "at", AccessToken{ClientID: "c", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAccess(ctx, "at")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "s" {
		t.Fatalf("record = %+v", got)
	}
	if _, err := store.GetAccess(ctx, "other"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("lookup of a wrong token = %v, want ErrTokenNotFound", err)
	}

	if err := store.SaveCode(ctx, "code", AuthorizationCode{Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeCode(ctx, "code"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeCode(ctx, "code"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("second consume = %v, want ErrTokenNotFound", err)
	}
}
