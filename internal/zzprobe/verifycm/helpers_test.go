//go:build audit5

package verifycm

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

var (
	signerOnce sync.Once
	signerKey  *rsa.PrivateKey
)

// newSigner shares one RSA key across the probe binary: generating a 2048-bit key
// costs ~100 ms and every store needs one.
func newSigner(t *testing.T) *oidcstore.Signer {
	t.Helper()
	signerOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		signerKey = key
	})
	return oidcstore.NewSigner("verifycm", signerKey)
}
