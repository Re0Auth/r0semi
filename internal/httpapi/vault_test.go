package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/vault"
)

// newTestVault builds a vault for tests that need a bound source.
func newTestVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("test", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// seedBindingSecret puts an upstream token in the vault under the binding's
// identity, mirroring what CompleteBind does. The binding store itself holds no
// secret, which is the property these tests rely on.
func seedBindingSecret(t *testing.T, v vault.Service, b federation.Binding, token string) {
	t.Helper()
	secret, err := json.Marshal(map[string]string{"access_token": token})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Enroll(context.Background(), federation.BindingIdentity(b), secret, nil); err != nil {
		t.Fatal(err)
	}
}

// bindingToken reads a bound source's upstream token back out of the vault.
func bindingToken(t *testing.T, v vault.Service, b federation.Binding) string {
	t.Helper()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := v.Use(context.Background(), federation.BindingIdentity(b), func(plain []byte) error {
		return json.Unmarshal(plain, &out)
	}); err != nil {
		t.Fatal(err)
	}
	return out.AccessToken
}
