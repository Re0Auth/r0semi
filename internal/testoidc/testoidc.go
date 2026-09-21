// Package testoidc is a minimal OpenID Provider for tests.
//
// It serves discovery, JWKS and a token endpoint whose id_token is signed by a
// generated RSA key, so tests exercise real id_token verification (signature,
// issuer, audience, expiry, nonce) rather than a stub. It is test support and
// never ships in a production path.
package testoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Server is a fake OpenID Provider.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	key     jose.JSONWebKey
	signer  jose.Signer
	nonce   string
	subject string
	name    string
	email   string
	picture string
}

// New starts a provider. The caller is responsible for Close (or t.Cleanup).
func New() *Server {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("testoidc: generate key: " + err.Error())
	}
	key := jose.JSONWebKey{
		Key: privateKey, KeyID: "test-key-1", Algorithm: string(jose.RS256), Use: "sig",
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", key.KeyID),
	)
	if err != nil {
		panic("testoidc: signer: " + err.Error())
	}

	s := &Server{
		key: key, signer: signer,
		subject: "oidc-user-1", name: "OIDC User",
		email: "oidc@example.com", picture: "https://example.com/avatar.png",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                s.URL,
			"authorization_endpoint":                s.URL + "/authorize",
			"token_endpoint":                        s.URL + "/token",
			"userinfo_endpoint":                     s.URL + "/userinfo",
			"jwks_uri":                              s.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{s.key.Public()}})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		writeJSON(w, map[string]any{
			"sub": s.subject, "name": s.name, "email": s.email, "picture": s.picture,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		nonce, subject, name, email, picture := s.nonce, s.subject, s.name, s.email, s.picture
		s.mu.Unlock()

		now := time.Now()
		claims := map[string]any{
			"iss": s.URL, "sub": subject, "aud": clientIDOf(r),
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"name": name, "email": email, "picture": picture,
		}
		if nonce != "" {
			claims["nonce"] = nonce
		}
		idToken, err := jwt.Signed(s.signer).Claims(claims).Serialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-1",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	s.Server = httptest.NewServer(mux)
	return s
}

// SetNonce sets the nonce the next id_token will carry. Tests set it to the
// value the client put in the authorization URL, so a mismatch is detectable.
func (s *Server) SetNonce(nonce string) {
	s.mu.Lock()
	s.nonce = nonce
	s.mu.Unlock()
}

// SetIdentity overrides the claims the provider asserts.
func (s *Server) SetIdentity(subject, name, email string) {
	s.mu.Lock()
	s.subject, s.name, s.email = subject, name, email
	s.mu.Unlock()
}

// SignIDToken signs an arbitrary claim set with the provider's key. It is how a
// test forges a token with a bad issuer, audience or signature.
func (s *Server) SignIDToken(claims map[string]any) (string, error) {
	return jwt.Signed(s.signer).Claims(claims).Serialize()
}

func clientIDOf(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok {
		return id
	}
	_ = r.ParseForm()
	return r.PostFormValue("client_id")
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
