package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClientType distinguishes clients that can keep a secret from those that
// cannot (desktop, CLI, mobile, SPA).
type ClientType string

const (
	ClientPublic       ClientType = "public"
	ClientConfidential ClientType = "confidential"
)

// ErrClientNotFound reports an unknown client id.
var ErrClientNotFound = errors.New("oauth: client not found")

// ErrNoSecretToRotate reports a rotation asked of a client that has no secret to
// rotate: a public client authenticates with PKCE, not a shared secret.
var ErrNoSecretToRotate = errors.New("oauth: client has no secret to rotate")

// ClientStatus is the administrative lifecycle of a registered client.
//
// A suspended client is not "denied": it is reported as unknown by every
// protocol entrance, because a ClientRegistry.Get returns ErrClientNotFound for
// it. An operator's decision should not be distinguishable from a client id that
// never existed.
type ClientStatus string

const (
	ClientActive    ClientStatus = "active"
	ClientSuspended ClientStatus = "suspended"
)

// A Client is a registered downstream application. The secret is stored only as
// a salted PBKDF2-HMAC-SHA256 verifier (see NewSecretHash); the plaintext is
// never persisted.
type Client struct {
	ID            string
	Name          string
	Type          ClientType
	Status        ClientStatus
	CreatedAt     time.Time
	RedirectURIs  []string
	AllowedScopes []Scope
	// AllowMissingPKCE opts this client out of the mandatory-PKCE rule the
	// protocol plane enforces on every authorization code request. It exists for
	// clients that cannot send a code_challenge (a certification suite, a legacy
	// RP) and is set only by an explicit `[client] allow_missing_pkce = true`.
	//
	// The zero value is false, so every client built by NewClient, restored from
	// storage, or created through the admin API still requires PKCE; the exemption
	// cannot be reached by accident, by a missing field, or by a request
	// parameter.
	AllowMissingPKCE bool

	secretHash []byte
}

// WithAllowMissingPKCE returns a copy of c with the exemption set. It is the only
// way to grant the exemption, so the call sites are greppable: registration of
// the configured first-party client, and the tests that pin this behaviour.
func (c Client) WithAllowMissingPKCE(allow bool) Client {
	c.AllowMissingPKCE = allow
	return c
}

// NewClient validates and constructs a client. A confidential client must have
// a secret; a public client must not.
//
// It writes the slow PBKDF2 verifier (S01-10) for every secret, which is the
// right default for a secret this process did not generate. Callers that know a
// secret came from a CSPRNG use NewClientWithVerifier with VerifierGenerated.
func NewClient(id, name string, typ ClientType, secret string, redirects []string, allowed []Scope) (Client, error) {
	return newClient(id, name, typ, secret, redirects, allowed, NewSecretHash)
}

// NewClientWithVerifier is NewClient with an explicit verifier policy. Use
// VerifierGenerated only for a high-entropy generated secret (R10-138): it costs
// microseconds to verify instead of ~23 ms, and the slow KDF buys nothing against
// an offline guess at 256 random bits.
func NewClientWithVerifier(id, name string, typ ClientType, secret string, redirects []string, allowed []Scope, policy VerifierPolicy) (Client, error) {
	hash := NewSecretHash
	if policy == VerifierGenerated {
		hash = NewGeneratedSecretHash
	}
	return newClient(id, name, typ, secret, redirects, allowed, hash)
}

// newClient is the shared constructor; hash is the verifier writer the chosen
// policy selected.
func newClient(id, name string, typ ClientType, secret string, redirects []string, allowed []Scope, hash func(string) []byte) (Client, error) {
	if id == "" {
		return Client{}, errors.New("oauth: client id is required")
	}
	if typ != ClientPublic && typ != ClientConfidential {
		return Client{}, fmt.Errorf("oauth: invalid client type %q", typ)
	}
	if typ == ClientConfidential && secret == "" {
		return Client{}, errors.New("oauth: confidential client requires a secret")
	}
	if typ == ClientPublic && secret != "" {
		return Client{}, errors.New("oauth: public client must not have a secret")
	}
	if len(redirects) == 0 {
		return Client{}, errors.New("oauth: at least one redirect URI is required")
	}
	for _, r := range redirects {
		if err := validRedirectURI(r); err != nil {
			return Client{}, fmt.Errorf("oauth: invalid redirect URI %q: %w", r, err)
		}
	}

	c := Client{
		ID:            id,
		Name:          name,
		Type:          typ,
		Status:        ClientActive,
		CreatedAt:     time.Now().UTC(),
		RedirectURIs:  append([]string(nil), redirects...),
		AllowedScopes: append([]Scope(nil), allowed...),
	}
	if secret != "" {
		c.secretHash = hash(secret)
	}
	return c, nil
}

// Verifier parameters for client secrets.
//
// S01-10: the digest used to be a bare unsalted SHA-256 of the secret. That is a
// fast hash with no per-secret salt, so a dumped registry could be tested against
// a wordlist (and two clients sharing a secret were visibly identical) at GPU
// speed. The verifier is now a salted, deliberately slow PBKDF2-HMAC-SHA256 with
// its algorithm and parameters carried in the stored string, so the format itself
// is part of the contract and the work factor can be raised later without a new
// column.
//
// Argon2id (golang.org/x/crypto/argon2) was the first choice, but x/crypto is not
// a dependency of this module (go.mod has no require for it) and the task's write
// scope excludes go.mod/go.sum. crypto/pbkdf2 is standard library as of Go 1.24,
// needs no new module, and the parameters below are tuned for a generated,
// high-entropy client secret rather than a human password.
const (
	// secretHashAlgorithm is the scheme name stored as the second field.
	secretHashAlgorithm = "pbkdf2-sha256"
	// secretHashIterations is the PBKDF2 iteration count written into every new
	// verifier. A verifier stores its own count, so raising this does not
	// invalidate already-stored secrets.
	secretHashIterations = 210_000
	// secretHashMaxIterations bounds what a stored verifier may ask a reader to
	// compute, so a corrupted or hostile row cannot turn one authentication into
	// an unbounded amount of work.
	secretHashMaxIterations = 4_000_000
	// secretHashSaltBytes is the per-secret random salt.
	secretHashSaltBytes = 16
	// secretHashKeyBytes is the derived verifier length.
	secretHashKeyBytes = 32

	// secretHashFastAlgorithm is the scheme for a server-generated,
	// high-entropy secret (R10-138): a salted HMAC-SHA256 verifier. A 256-bit
	// random secret needs no slow KDF to resist an offline guess, while the
	// PBKDF2 work factor made every confidential-client authentication cost ~23 ms
	// of CPU — the token and introspection endpoints' dominant cost, and an
	// anonymous CPU amplifier (a public client id plus any secret reaches it).
	// Human-chosen or operator-supplied secrets keep the PBKDF2 verifier; the
	// scheme is stored per row, so both verify through Authenticate.
	secretHashFastAlgorithm = "hmac-sha256"
	// secretHashFastVersion is the fast scheme's own version field, so the shape
	// can change later without ambiguity.
	secretHashFastVersion = "v=1"
	// secretHashFastDomain separates this HMAC from every other use of the salt.
	secretHashFastDomain = "r0semi:client-secret:v2\x00"
)

// VerifierPolicy selects which verifier NewClientWithVerifier writes for a new
// client secret.
type VerifierPolicy int

const (
	// VerifierPBKDF2 is the slow, salted KDF (S01-10). It is the zero value and
	// what NewClient uses, so nothing changes unless a caller asks.
	VerifierPBKDF2 VerifierPolicy = iota
	// VerifierGenerated is the fast salted-HMAC verifier, for a secret this
	// process generated (or one an operator declared high-entropy).
	VerifierGenerated
)

// NewSecretHash returns the stored digest of a client secret. Registration and
// rotation use it to turn a freshly generated secret into the form a registry
// persists; Authenticate is its counterpart.
//
// The returned bytes are a PHC-like ASCII string
// "$pbkdf2-sha256$i=<iterations>$<salt>$<dk>", where salt and dk are unpadded
// standard base64. Every call draws a fresh salt, so two hashes of the same
// secret are different bytes; equality of two stored digests is therefore NOT a
// statement about the secrets. Callers that need to compare a configured secret
// against a stored one must call Authenticate.
//
// It panics only when the system CSPRNG fails. That is not a condition under
// which a process may keep registering credentials, and a fallback would be a
// silent downgrade of exactly the property this function exists to provide.
func NewSecretHash(secret string) []byte {
	encoded, err := hashSecret(secret)
	if err != nil {
		panic("oauth: NewSecretHash: " + err.Error())
	}
	return encoded
}

// hashSecret is NewSecretHash with the entropy failure returned rather than
// panicked, for the one caller that can still refuse.
func hashSecret(secret string) ([]byte, error) {
	salt := make([]byte, secretHashSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("client secret salt: %w", err)
	}
	dk, err := pbkdf2.Key(sha256.New, secret, salt, secretHashIterations, secretHashKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("client secret hash: %w", err)
	}
	return []byte("$" + secretHashAlgorithm + "$i=" + strconv.Itoa(secretHashIterations) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// NewGeneratedSecretHash returns the fast verifier for a secret this process
// generated. It panics only when the system CSPRNG fails, like NewSecretHash.
func NewGeneratedSecretHash(secret string) []byte {
	encoded, err := hashGeneratedSecret(secret)
	if err != nil {
		panic("oauth: NewGeneratedSecretHash: " + err.Error())
	}
	return encoded
}

// hashGeneratedSecret is NewGeneratedSecretHash with the entropy failure
// returned rather than panicked.
func hashGeneratedSecret(secret string) ([]byte, error) {
	salt := make([]byte, secretHashSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("client secret salt: %w", err)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(secretHashFastDomain))
	mac.Write([]byte(secret))
	dk := mac.Sum(nil)
	return []byte("$" + secretHashFastAlgorithm + "$" + secretHashFastVersion + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// LooksGeneratedSecret reports whether secret has the shape of a CSPRNG output
// rather than a human-chosen password. It accepts the recipes this repository
// documents — 64 lowercase hex (`openssl rand -hex 32`) and base64/base64url of
// at least 32 random bytes — and nothing else. A caller uses it to choose
// VerifierGenerated; a false negative only costs the slow KDF, so the shape is
// deliberately strict.
func LooksGeneratedSecret(secret string) bool {
	if len(secret) == 64 {
		lowerHex := true
		for i := 0; i < len(secret); i++ {
			c := secret[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				lowerHex = false
				break
			}
		}
		if lowerHex {
			return true
		}
	}
	if len(secret) < 43 {
		// Base64 of 32 random bytes is 44 chars with padding, 43 raw. Anything
		// shorter than the recipe cannot be a CSPRNG output of the documented size.
		return false
	}
	distinct := make(map[byte]struct{}, 16)
	hasLetter, hasDigit := false, false
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasLetter = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '+' || c == '/' || c == '-' || c == '_' || c == '=':
		default:
			return false
		}
		distinct[c] = struct{}{}
	}
	return hasLetter && hasDigit && len(distinct) >= 16
}

// splitSecretHash parses a stored verifier, returning its salt, derived key and
// work factor. It is the only reader of the encoding, so RestoreClient's
// admission and Authenticate's verification cannot disagree about what a
// well-formed digest is. An unparseable value reports ok=false; the old bare
// SHA-256 digest is unparseable here on purpose (S01-10: no legacy verify path).
func splitSecretHash(encoded []byte) (salt, dk []byte, iterations int, ok bool) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != secretHashAlgorithm {
		return nil, nil, 0, false
	}
	rawIter, found := strings.CutPrefix(parts[2], "i=")
	if !found {
		return nil, nil, 0, false
	}
	iterations, err := strconv.Atoi(rawIter)
	if err != nil || iterations < 1 || iterations > secretHashMaxIterations {
		return nil, nil, 0, false
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < 8 {
		return nil, nil, 0, false
	}
	dk, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(dk) != secretHashKeyBytes {
		return nil, nil, 0, false
	}
	return salt, dk, iterations, true
}

// splitFastSecretHash parses a fast (generated-secret) verifier.
func splitFastSecretHash(encoded []byte) (salt, dk []byte, ok bool) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != secretHashFastAlgorithm || parts[2] != secretHashFastVersion {
		return nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < 8 {
		return nil, nil, false
	}
	dk, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(dk) != secretHashKeyBytes {
		return nil, nil, false
	}
	return salt, dk, true
}

// validSecretHash reports whether encoded is a verifier this package produced, so
// a registry cannot persist a digest that no later process can authenticate
// against.
func validSecretHash(encoded []byte) bool {
	if _, _, _, ok := splitSecretHash(encoded); ok {
		return true
	}
	_, _, ok := splitFastSecretHash(encoded)
	return ok
}

// ValidSecretHash reports whether encoded is a client-secret verifier this
// package's NewSecretHash produced — the shape both RestoreClientWithStatus and
// RotateSecret admit. It is exported for a ClientAdmin registry that stores the
// digest outside oauth: an invalid or legacy digest must be refused at rotation,
// not accepted and then turned into an unknown client at the next RestoreClient.
//
// It is a shape check only; it does not authenticate. Use Client.Authenticate to
// compare a plaintext secret against a stored verifier.
func ValidSecretHash(encoded []byte) bool {
	return validSecretHash(encoded)
}

// verifySecretHash recomputes the verifier for secret and compares it in constant
// time. The scheme is carried in the stored encoding, so a PBKDF2 row keeps the
// slow path (and its own work factor) while a generated-secret row takes the fast
// one.
func verifySecretHash(encoded []byte, secret string) bool {
	if salt, want, ok := splitFastSecretHash(encoded); ok {
		mac := hmac.New(sha256.New, salt)
		mac.Write([]byte(secretHashFastDomain))
		mac.Write([]byte(secret))
		return subtle.ConstantTimeCompare(want, mac.Sum(nil)) == 1
	}
	salt, want, iterations, ok := splitSecretHash(encoded)
	if !ok {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, secret, salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}

// Authenticate checks a client secret in constant time.
//
// It is the only correct way to compare a configured plaintext secret with a
// Client, because the stored digest is salted and differs on every construction.
func (c Client) Authenticate(secret string) bool {
	if len(c.secretHash) == 0 {
		return false
	}
	return verifySecretHash(c.secretHash, secret)
}

// SecretHash returns the stored digest of the client secret, for persistence.
// It is empty for a public client. A registry persists this, never the
// plaintext secret.
func (c Client) SecretHash() []byte { return append([]byte(nil), c.secretHash...) }

// RestoreClient rebuilds a client from persisted fields. It is the inverse of
// NewClient plus SecretHash, and is what a persistent ClientRegistry uses;
// NewClient is for registration, where the plaintext secret is still known.
func RestoreClient(id, name string, typ ClientType, secretHash []byte, redirects []string, allowed []Scope, createdAt time.Time) (Client, error) {
	return RestoreClientWithStatus(id, name, typ, ClientActive, secretHash, redirects, allowed, createdAt)
}

// RestoreClientWithStatus is RestoreClient plus the persisted lifecycle status,
// for a registry that stores it.
//
// The PKCE exemption is deliberately NOT a parameter here: a store that persists
// it applies WithAllowMissingPKCE to the result after restoring, so a storage
// layer that never learned the field cannot silently grant the exemption.
func RestoreClientWithStatus(id, name string, typ ClientType, status ClientStatus, secretHash []byte, redirects []string, allowed []Scope, createdAt time.Time) (Client, error) {
	if status != ClientActive && status != ClientSuspended {
		return Client{}, fmt.Errorf("oauth: invalid client status %q", status)
	}
	switch {
	case id == "":
		return Client{}, errors.New("oauth: client id is required")
	case typ != ClientPublic && typ != ClientConfidential:
		return Client{}, fmt.Errorf("oauth: invalid client type %q", typ)
	case typ == ClientConfidential && !validSecretHash(secretHash):
		return Client{}, errors.New("oauth: confidential client requires a secret hash")
	case typ == ClientPublic && len(secretHash) != 0:
		return Client{}, errors.New("oauth: public client must not have a secret hash")
	case len(redirects) == 0:
		return Client{}, errors.New("oauth: at least one redirect URI is required")
	}
	return Client{
		ID:            id,
		Name:          name,
		Type:          typ,
		Status:        status,
		CreatedAt:     createdAt,
		RedirectURIs:  append([]string(nil), redirects...),
		AllowedScopes: append([]Scope(nil), allowed...),
		secretHash:    append([]byte(nil), secretHash...),
	}, nil
}

// AllowsRedirect reports whether uri is an exact registered redirect URI.
func (c Client) AllowsRedirect(uri string) bool {
	return c.RegisteredRedirect(uri) != ""
}

// RegisteredRedirect returns the registered redirect URI that equals uri, or ""
// when the client has none. It is AllowsRedirect plus the value, for the callers
// that then redirect: what a redirect target is built from must be the URI the
// client registered, not the string the request carried. The two are equal — that
// is what the check means — but only one of them is a value this server chose, and
// a reader (or a taint analyser, gosecurity:S5146) cannot tell an echoed request
// value from an attacker-chosen destination by looking at the variable alone.
func (c Client) RegisteredRedirect(uri string) string {
	// A registered URI that targets a scheme no redirect may use never matches,
	// even against itself. RestoreClient deliberately does not re-validate what
	// an earlier policy admitted, so a registry can still carry such a row and
	// the authorize path has no second check of its own (KIT-6). The test here is
	// narrower than validRedirectURI on purpose: applying the registration rules
	// retroactively would turn a tightened rule into a client that cannot use a
	// URI it registered while they were in force, whereas a scheme a document
	// interpreter executes is the case where "registered" must not mean "usable".
	if forbiddenRedirectScheme(uri) {
		return ""
	}
	for _, r := range c.RedirectURIs {
		if r == uri && !forbiddenRedirectScheme(r) {
			return r
		}
	}
	return ""
}

// forbiddenRedirectScheme reports whether raw targets a scheme a redirect must
// never use. It parses the way validRedirectURI does, so the two agree about
// which part of the string is the scheme; a URI that does not parse is treated
// as forbidden because the caller is about to hand it to a browser.
func forbiddenRedirectScheme(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	return forbiddenRedirectSchemes[strings.ToLower(u.Scheme)]
}

// forbiddenRedirectSchemes are schemes a redirect must never target. Each one
// either carries a document a browser interprets (javascript:, data:, vbscript:)
// or addresses the local machine rather than a client (file:, blob:, about:).
var forbiddenRedirectSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"vbscript":   true,
	"file":       true,
	"blob":       true,
	"about":      true,
}

// validRedirectURI validates a redirect URI at registration time.
//
// Registration is where this belongs, and it is deliberately *not* applied by
// RestoreClient: a URI already in the registry was accepted under whatever policy
// was in force when it was written, and refusing to load it would turn a
// tightened rule into a deployment that cannot start.
//
// The rules are RFC 6749 §3.1.2 (no fragment) plus RFC 8252: https anywhere, http
// only for a loopback host (§7.3 — a native client's local listener), and any
// reverse-DNS private-use scheme (§7.1 — com.example.app:/cb, how a desktop or
// mobile app receives a code). Everything else is refused. Without this the check
// was "does url.Parse find a scheme", which accepts http:// for a host nobody can
// protect and never rejects javascript:.
func validRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("it does not parse as a URL")
	}
	if u.Scheme == "" {
		return errors.New("it has no scheme")
	}
	if u.Fragment != "" {
		return errors.New("RFC 6749 §3.1.2 forbids a fragment")
	}
	if u.User != nil {
		return errors.New("it carries userinfo, which no client needs and a phisher does")
	}
	scheme := strings.ToLower(u.Scheme)
	if forbiddenRedirectSchemes[scheme] {
		return fmt.Errorf("the %s: scheme is never a redirect target", scheme)
	}
	switch scheme {
	case "https":
		if u.Host == "" {
			return errors.New("an https redirect URI needs a host")
		}
		return nil
	case "http":
		if !loopbackHost(strings.ToLower(u.Hostname())) {
			return errors.New("http is allowed only for a loopback host (RFC 8252 §7.3); use https")
		}
		return nil
	default:
		// A private-use URI scheme in reverse-DNS notation (RFC 8252 §7.1). The
		// dot is required: `app:` alone is what a device might already have
		// registered for something else.
		if !strings.Contains(scheme, ".") {
			return errors.New("a custom scheme must be in reverse-DNS notation (RFC 8252 §7.1), e.g. com.example.app")
		}
		if u.Opaque == "" && u.Path == "" && u.Host == "" {
			return errors.New("it names no target")
		}
		return nil
	}
}

// loopbackHost reports whether host is the local machine, the one place RFC 8252
// §7.3 allows a plain http redirect.
func loopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AllowsScope reports whether the client was registered for the scope.
func (c Client) AllowsScope(s Scope) bool {
	for _, a := range c.AllowedScopes {
		if a == s {
			return true
		}
	}
	return false
}

// ClientRegistry stores registered clients.
type ClientRegistry interface {
	Create(ctx context.Context, c Client) error
	Get(ctx context.Context, id string) (Client, error)
}

// ClientNameLookup is implemented by a registry that can resolve many display
// names at once. It exists because the grants view asked for one client at a time
// from inside a loop over its rows: N round trips for a page whose whole content
// is N names.
//
// Callers type-assert rather than require it: a registry that does not implement
// it keeps working, one Get per id, which is what every caller did before.
type ClientNameLookup interface {
	ClientNames(ctx context.Context, ids []string) (map[string]string, error)
}

// LookupClientNames resolves display names for ids: in one call when the registry
// can, one id at a time when it cannot.
//
// Names are cosmetic, so nothing here is fatal. A bulk lookup that fails does not
// take the view down with it, and an id it did not answer is filled in
// individually — which is also the whole path for a registry without the bulk
// method. An id that resolves to nothing keeps an empty name, exactly as the
// per-id code left it.
func LookupClientNames(ctx context.Context, reg ClientRegistry, ids []string) map[string]string {
	out := make(map[string]string, len(ids))
	if reg == nil || len(ids) == 0 {
		return out
	}
	if bulk, ok := reg.(ClientNameLookup); ok {
		if names, err := bulk.ClientNames(ctx, ids); err == nil {
			for id, name := range names {
				out[id] = name
			}
		}
	}
	for _, id := range ids {
		if _, resolved := out[id]; resolved {
			continue
		}
		if c, err := reg.Get(ctx, id); err == nil {
			out[id] = c.Name
		}
	}
	return out
}

// Client-page bounds. Every ListClients implementation resolves a caller's
// limit with ResolveClientPageLimit, so the default and the ceiling cannot drift
// between the in-memory and Postgres registries, and a caller that passes a bad
// limit is refused (ErrInvalidClientLimit) rather than silently clamped.
//
// The default is the ceiling on purpose: an operator inventory is small, so a
// request that names no limit gets the largest page this endpoint will serve.
const (
	DefaultClientPageSize = 100
	MaxClientPageSize     = 100
)

// ErrInvalidClientLimit reports a limit outside [1, MaxClientPageSize].
var ErrInvalidClientLimit = errors.New("oauth: invalid client page limit")

// ErrInvalidClientCursor reports a cursor this package did not issue: a cursor
// that fails to decode, or whose payload is not one of ours. It is a typed error
// so the HTTP layer can answer 400 instead of treating an unreadable cursor as a
// store fault — or, worse, quietly starting over from the first page, which would
// make a caller's paging loop repeat data forever.
var ErrInvalidClientCursor = errors.New("oauth: invalid client cursor")

// clientCursorPrefix versions the decoded cursor payload. The prefix is checked
// on decode, so a value that decodes to bytes this package did not write — a
// cursor from another endpoint, or a forged one — is refused rather than
// interpreted as a client id.
const clientCursorPrefix = "cl1:"

// EncodeClientCursor turns the last row's sort key (the client id) into the
// opaque cursor a caller passes back as `cursor`. base64url without padding
// keeps it safe in a query string, and the version prefix keeps it from being
// confused with any other endpoint's cursor.
//
// The key is not encrypted: it names a client id that the same caller can
// already read from the page. It is opaque only in the sense that its shape is
// not part of the API — clients must treat it as a value to echo, and a value
// the server did not produce is rejected.
func EncodeClientCursor(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(clientCursorPrefix + id))
}

// DecodeClientCursor reverses EncodeClientCursor. An empty cursor means "the
// first page" and is not an error; anything else must decode to a non-empty
// payload with this package's prefix.
func DecodeClientCursor(cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", fmt.Errorf("%w: it is not base64url", ErrInvalidClientCursor)
	}
	after, found := strings.CutPrefix(string(raw), clientCursorPrefix)
	if !found || after == "" {
		return "", fmt.Errorf("%w: it does not carry a client key", ErrInvalidClientCursor)
	}
	return after, nil
}

// ResolveClientPageLimit applies the page-size contract: zero means "the
// caller did not ask", which becomes DefaultClientPageSize; anything outside
// [1, MaxClientPageSize] is refused with ErrInvalidClientLimit.
//
// A limit above the ceiling is an error rather than a clamp because a caller
// that asked for 10,000 rows and silently received 100 would page wrong — it
// would take the short page as the end of the list.
func ResolveClientPageLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultClientPageSize, nil
	}
	if limit < 1 || limit > MaxClientPageSize {
		return 0, fmt.Errorf("%w: it must be between 1 and %d", ErrInvalidClientLimit, MaxClientPageSize)
	}
	return limit, nil
}

// ClientAdmin is the management side of a registry: the operations an operator
// uses to review and revoke clients. It is separate from ClientRegistry so the
// protocol plane depends only on what it needs to serve requests, and so a
// read-only or third-party registry remains a valid ClientRegistry.
type ClientAdmin interface {
	// ListClients returns one page of clients ordered by id ascending, suspended
	// ones included, plus the cursor that fetches the next page.
	//
	// Ordering is deterministic and total because the id is the sort key and is
	// unique: a page boundary is a client id, not an offset, so a row inserted
	// between two pages cannot duplicate or skip one the way an OFFSET would.
	//
	// limit is resolved with ResolveClientPageLimit (0 means the default; an
	// out-of-range value is ErrInvalidClientLimit). cursor is a value a previous
	// call returned as nextCursor; empty starts at the first page, and a value
	// this package did not issue is ErrInvalidClientCursor. The returned cursor is
	// empty exactly when the page is the last one.
	ListClients(ctx context.Context, limit int, cursor string) ([]Client, string, error)
	// SetStatus changes the lifecycle. An unknown id is ErrClientNotFound.
	SetStatus(ctx context.Context, id string, status ClientStatus) error
	// RotateSecret replaces a confidential client's secret digest. An unknown id
	// is ErrClientNotFound; a public client is ErrNoSecretToRotate, because it has
	// no secret and giving it one would break RestoreClient's validation. The
	// digest must be one NewSecretHash produced — the one encoding RestoreClient
	// admits: "$pbkdf2-sha256$i=<iterations>$<salt>$<dk>" — so a wrong or legacy
	// digest is refused instead of being stored and silently locking the client
	// out on the next restart.
	RotateSecret(ctx context.Context, id string, secretHash []byte) error
	// Delete removes the registration AND revokes every credential the client
	// holds: access and refresh tokens, unspent authorization codes,
	// spent-refresh tombstones, pending authorization requests and device
	// authorizations.
	//
	// Revoking is part of the operation, not a follow-up. A deleted client must
	// not keep acting through a token it already obtained: the protocol plane
	// reports a deleted client as unknown, but a token that is still a live row
	// remains a capability until it expires, and an unredeemed code can mint a
	// fresh pair. Either one would make "the client was deleted" a claim the
	// deployment cannot back.
	//
	// A registry that keeps client rows and token rows in separate engines cannot
	// satisfy this by itself; the engine that mints the tokens publishes itself
	// through TokenRevokerSetter, and Delete then fans the revocation out. A
	// registry wired with no revoker has no tokens to revoke.
	//
	// Deleting an absent client is not an error, which keeps an operator's retry
	// idempotent; revoking is idempotent for the same reason.
	Delete(ctx context.Context, id string) error
}

// TokenRevokerSetter is implemented by a ClientAdmin whose clients' tokens live
// in a separate engine. The engine that mints the tokens calls SetTokenRevoker
// with itself, so Delete can honour the ClientAdmin.Delete contract.
//
// It is an optional extension rather than part of ClientAdmin: a registry that
// owns its tokens does not implement it and does not need it, and the assertion
// is what keeps the wiring out of the interface every registry must satisfy.
type TokenRevokerSetter interface {
	// SetTokenRevoker records the token engine Delete must revoke through. It is
	// called once, at composition, before any request is served.
	SetTokenRevoker(rev TokenAdmin)
}

// MemoryClientRegistry is a non-durable ClientRegistry for development and tests.
type MemoryClientRegistry struct {
	mu   sync.RWMutex
	byID map[string]Client
	// tokens, when set, is the token engine the clients of this registry were
	// issued tokens by. Delete revokes through it to honour the
	// ClientAdmin.Delete contract; a registry that was never wired (used on its
	// own, with no token store) has nothing to revoke and leaves the field nil.
	//
	// It is written once at composition — by NewService for the hand-rolled
	// engine, by memory.NewOIDCStore for the OpenID Provider — through
	// SetTokenRevoker, and read under mu from then on.
	tokens TokenAdmin
}

// NewMemoryClientRegistry returns an empty registry.
func NewMemoryClientRegistry() *MemoryClientRegistry {
	return &MemoryClientRegistry{byID: make(map[string]Client)}
}

// SetTokenRevoker implements TokenRevokerSetter: it names the engine Delete
// revokes through.
func (r *MemoryClientRegistry) SetTokenRevoker(rev TokenAdmin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = rev
}

// tokenRevoker reads the wired revoker. The lock is released before the caller
// uses it: RevokeTokens takes the token store's own lock, and holding this
// registry's while calling out would order the two locks the wrong way round
// against anything that reads a client while holding the token store.
func (r *MemoryClientRegistry) tokenRevoker() TokenAdmin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tokens
}

// Create implements ClientRegistry.
func (r *MemoryClientRegistry) Create(_ context.Context, c Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[c.ID]; exists {
		return fmt.Errorf("oauth: client %s already exists", c.ID)
	}
	r.byID[c.ID] = c
	return nil
}

// Get implements ClientRegistry. A suspended client is reported as not found,
// so the protocol plane treats it exactly like an id that was never registered.
func (r *MemoryClientRegistry) Get(_ context.Context, id string) (Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[id]
	if !ok || c.Status == ClientSuspended {
		return Client{}, ErrClientNotFound
	}
	return c, nil
}

// ClientNames implements ClientNameLookup: one read lock for the whole page.
//
// Unlike Get it does not hide a suspended client. What a name is asked for here
// is a view of tokens that were issued to somebody, and an operator suspending a
// client does not make the user's grant stop existing — the list would show an
// unnamed client for exactly the entry the user most needs to recognise and
// revoke.
func (r *MemoryClientRegistry) ClientNames(_ context.Context, ids []string) (map[string]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		if c, ok := r.byID[id]; ok {
			out[id] = c.Name
		}
	}
	return out, nil
}

// ListClients implements ClientAdmin. Ids sort bytewise (Go's string order),
// which is the collation the Postgres implementation orders by for the ASCII
// client ids NewClient and the admin plane generate.
func (r *MemoryClientRegistry) ListClients(_ context.Context, limit int, cursor string) ([]Client, string, error) {
	limit, err := ResolveClientPageLimit(limit)
	if err != nil {
		return nil, "", err
	}
	after, err := DecodeClientCursor(cursor)
	if err != nil {
		return nil, "", err
	}

	r.mu.RLock()
	out := make([]Client, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, c)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	// The cursor names a row, not an offset: the page starts at the first id
	// strictly greater than the one the cursor carried, so a client added between
	// two requests lands on a later page instead of shifting this one.
	if after != "" {
		out = out[sort.Search(len(out), func(i int) bool { return out[i].ID > after }):]
	}
	if len(out) > limit {
		out = out[:limit]
		return out, EncodeClientCursor(out[len(out)-1].ID), nil
	}
	return out, "", nil
}

// SetStatus implements ClientAdmin.
func (r *MemoryClientRegistry) SetStatus(_ context.Context, id string, status ClientStatus) error {
	if status != ClientActive && status != ClientSuspended {
		return fmt.Errorf("oauth: invalid client status %q", status)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return ErrClientNotFound
	}
	c.Status = status
	r.byID[id] = c
	return nil
}

// RotateSecret implements ClientAdmin.
func (r *MemoryClientRegistry) RotateSecret(_ context.Context, id string, secretHash []byte) error {
	// The shape RestoreClient enforces. A value it would refuse used to be stored
	// as-is, so the client authenticated fine until the process restarted, when
	// RestoreClient refused the row and the client became unknown.
	if !validSecretHash(secretHash) {
		return fmt.Errorf("oauth: a rotation needs a %s secret hash, got %d bytes",
			secretHashAlgorithm, len(secretHash))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return ErrClientNotFound
	}
	if c.Type != ClientConfidential {
		return ErrNoSecretToRotate
	}
	c.secretHash = append([]byte(nil), secretHash...)
	r.byID[id] = c
	return nil
}

// Delete implements ClientAdmin. The tokens go first: if the revocation fails
// the registration survives, so a retry still has the client to act on and the
// deployment never reports a client as gone while its credentials live.
//
// A registry that was never wired with a token engine (see SetTokenRevoker) has
// nothing to revoke and removes only the registration.
func (r *MemoryClientRegistry) Delete(ctx context.Context, id string) error {
	if rev := r.tokenRevoker(); rev != nil {
		if _, err := rev.RevokeTokens(ctx, TokenFilter{ClientID: id}); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
	return nil
}
