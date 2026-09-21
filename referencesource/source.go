// Package referencesource is the first standalone Re0Auth data source: a
// Phigros backend whose native login is TapTap or a standard OAuth provider
// (Google, GitHub, ...), built on the public Upstream Kit.
//
// It exists to prove the Kit's central claim. A backend does not need native
// OAuth 2.0 to become a compliant source, because the Kit *supplies* the OAuth
// 2.0 authorization server face. The backend's own login lives behind the
// Login/Authenticator seam -- the Kit's Consent hook -- and is invisible to
// Re0Auth.
//
// The source owns exactly two things Re0Auth must never see: its session and its
// vault. Every Login only has to produce a Principal; the source stores the
// credential and sets the session.
package referencesource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/upstreamkit"
	"github.com/Re0Auth/r0semi/vault"
)

// SessionKey is where a source session remembers the logged-in subject.
const SessionKey = "subject"

// Config describes the source to Re0Auth.
type Config struct {
	// Discovery is what Re0Auth sees: game, name, scopes, resources, token class.
	Discovery upstreamkit.Config
	// Provider namespaces this source's credentials in the vault, e.g. "phigros".
	Provider string
	// Downstream is the client registration Re0Auth uses.
	Downstream Client
	// Session tunes the source's own login session.
	Session SessionConfig
}

// SessionConfig tunes the source's login session cookie.
type SessionConfig struct {
	// CookieName defaults to "refsrc_session".
	CookieName string
	// Lifetime defaults to 12h.
	Lifetime time.Duration
	// Secure marks the cookie Secure. Defaults to false so a reference source
	// can run over plain HTTP; production sets it true.
	Secure bool
}

// Client is a downstream client the source trusts.
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

// Deps are the source's own, private parts. Re0Auth never learns about them.
type Deps struct {
	// Auth establishes the end user for the static/demo case. When Logins are
	// configured it may be nil: the source then reads its own session.
	Auth Authenticator
	// Logins are the source's own login surfaces (TapTap QR, Google/GitHub…).
	// They share one session, owned by the source.
	Logins []Login
	// Vault stores native credentials privately, keyed by the source's own
	// account id.
	Vault vault.Service
	// Reader serves normalized resources using that credential.
	Reader Reader
	// Logger receives audit events. Defaults to an in-memory logger.
	Logger audit.Logger
	// Now injects a clock. Defaults to time.Now.
	Now func() time.Time
	// Sessions is the session manager shared by every Login. Created if nil.
	Sessions *scs.SessionManager
}

// Establish records a successful login: it stores the principal's credential in
// the source's vault and puts the subject into the source's session. A Login
// calls it exactly once per successful authentication.
type Establish func(ctx context.Context, principal Principal) error

// Login is one way for a visitor to authenticate at the source. It mounts its
// own routes and, on success, calls establish. It must never fabricate an
// identity: an unauthenticated visitor is an error, not a default subject.
type Login interface {
	Mount(mux *http.ServeMux, establish Establish)
}

// Reader serves normalized resources using a subject's native credential. The
// credential is valid only for the duration of the call: the vault zeroizes it
// when Read returns.
type Reader interface {
	Read(ctx context.Context, subject, resource string, credential []byte) (any, error)
}

// StaticReader is a fixed-payload Reader for tests and demos.
type StaticReader map[string]any

// Read implements Reader.
func (r StaticReader) Read(_ context.Context, _, resource string, _ []byte) (any, error) {
	value, ok := r[resource]
	if !ok {
		return nil, fmt.Errorf("referencesource: no payload for resource %q", resource)
	}
	return value, nil
}

// Source is a mountable, compliant data source.
type Source struct {
	discovery upstreamkit.Discovery
	provider  string
	kit       *upstreamkit.Server
	vault     vault.Service
	auth      Authenticator
	reader    Reader
	logins    []Login
	sessions  *scs.SessionManager
}

// New builds the source: it derives the scope catalog from the discovery
// document, stands up an OAuth 2.0 authorization server with Re0Auth
// registered as a client, mounts the Upstream Kit, and wires the source's own
// login surfaces onto one session.
func New(cfg Config, deps Deps) (*Source, error) {
	switch {
	case deps.Vault == nil:
		return nil, errors.New("referencesource: Deps.Vault is required")
	case deps.Reader == nil:
		return nil, errors.New("referencesource: Deps.Reader is required")
	case cfg.Provider == "":
		return nil, errors.New("referencesource: Config.Provider is required")
	case cfg.Downstream.ID == "":
		return nil, errors.New("referencesource: Config.Downstream.ID is required")
	case deps.Auth == nil && len(deps.Logins) == 0:
		return nil, errors.New("referencesource: Deps.Auth or Deps.Logins is required")
	}
	if deps.Logger == nil {
		deps.Logger = audit.NewMemoryLogger()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	sessions := deps.Sessions
	if sessions == nil {
		sessions = newSessions(cfg.Session)
	}

	discovery, err := upstreamkit.NewDiscovery(cfg.Discovery)
	if err != nil {
		return nil, err
	}
	registry, err := scopeRegistry(discovery)
	if err != nil {
		return nil, err
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient(
		cfg.Downstream.ID, cfg.Downstream.ID, oauth.ClientConfidential,
		cfg.Downstream.Secret, cfg.Downstream.RedirectURIs, scopesOf(discovery),
	)
	if err != nil {
		return nil, err
	}
	if err := clients.Create(context.Background(), client); err != nil {
		return nil, err
	}

	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), deps.Logger, oauth.Config{
		Issuer: discovery.OAuth.Issuer,
		Scopes: registry,
		Now:    deps.Now,
	})
	if err != nil {
		return nil, err
	}

	auth := deps.Auth
	if len(deps.Logins) > 0 {
		// Logins win: adding a login surface must not silently keep the demo
		// authenticator.
		auth = sessionAuth{sessions: sessions}
	}
	s := &Source{
		discovery: discovery,
		provider:  cfg.Provider,
		vault:     deps.Vault,
		auth:      auth,
		reader:    deps.Reader,
		logins:    deps.Logins,
		sessions:  sessions,
	}
	resources := make(map[string]upstreamkit.ResourceHandler, len(discovery.Resources))
	for _, res := range discovery.Resources {
		resources[res.Name] = s.resourceHandler(res.Name)
	}
	kit, err := upstreamkit.New(cfg.Discovery, upstreamkit.Hooks{
		OAuth:     as,
		Scope:     registry,
		Consent:   s.consent,
		Account:   s.account,
		Resources: resources,
	})
	if err != nil {
		return nil, err
	}
	s.kit = kit
	return s, nil
}

// Handler serves the source's whole surface: the login routes, then discovery,
// OAuth 2.0, account and resources. All of it is wrapped in one session
// LoadAndSave so the Kit's Consent hook can read the session. It shares no code
// path, no database and no credential store with Re0Auth.
func (s *Source) Handler() http.Handler {
	if len(s.logins) == 0 {
		return s.kit.Handler()
	}
	root := http.NewServeMux()
	root.HandleFunc("GET /login", s.handleLoginStatus)
	root.HandleFunc("POST /login/sign_out", s.handleSignOut)
	for _, login := range s.logins {
		login.Mount(root, s.establish)
	}
	root.Handle("/", s.kit.Handler())
	return s.sessions.LoadAndSave(root)
}

// handleLoginStatus reports who, if anyone, is logged in at the source.
func (s *Source) handleLoginStatus(w http.ResponseWriter, r *http.Request) {
	subject := s.sessions.GetString(r.Context(), SessionKey)
	state := "anonymous"
	if subject != "" {
		state = "confirmed"
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": state, "subject": subject})
}

func (s *Source) handleSignOut(w http.ResponseWriter, r *http.Request) {
	_ = s.sessions.Destroy(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// Discovery is the source's discovery document, with OAuth endpoints resolved.
func (s *Source) Discovery() upstreamkit.Discovery { return s.discovery }

// Sessions exposes the shared session manager.
func (s *Source) Sessions() *scs.SessionManager { return s.sessions }

// establish implements Establish. The credential goes into the source's vault
// under the source's own account id, and the subject into the source's session.
func (s *Source) establish(ctx context.Context, principal Principal) error {
	if principal.Subject == "" {
		return errors.New("referencesource: a login produced no subject")
	}
	if principal.Credential != nil {
		identity := vault.Identity{Subject: principal.Subject, Provider: s.provider}
		if err := s.vault.Enroll(ctx, identity, principal.Credential, principal.Meta); err != nil {
			return err
		}
	}
	s.sessions.Put(ctx, SessionKey, principal.Subject)
	return nil
}

// consent is the Kit's Consent hook. It reads the source's session, which the
// logins established, and tells the Kit which subject authorized. Re0Auth only
// ever sees the subject.
func (s *Source) consent(ctx context.Context, _ upstreamkit.ConsentRequest) (upstreamkit.ConsentDecision, error) {
	principal, err := s.auth.Authenticate(ctx)
	if err != nil {
		// The Kit turns this into access_denied; no identity is ever fabricated.
		return upstreamkit.ConsentDecision{}, err
	}
	// A static authenticator may hand the credential here; a real login already
	// stored it, so a nil credential means "already stored".
	if principal.Credential != nil {
		identity := vault.Identity{Subject: principal.Subject, Provider: s.provider}
		if err := s.vault.Enroll(ctx, identity, principal.Credential, principal.Meta); err != nil {
			return upstreamkit.ConsentDecision{}, err
		}
	}
	return upstreamkit.ConsentDecision{Subject: principal.Subject}, nil
}

func (s *Source) account(_ context.Context, subject string) (upstreamkit.AccountInfo, error) {
	return upstreamkit.AccountInfo{Subject: subject}, nil
}

// resourceHandler reads one normalized resource inside the vault's plaintext
// window: the credential is decrypted for the duration of the call and zeroized
// when it returns.
func (s *Source) resourceHandler(name string) upstreamkit.ResourceHandler {
	return func(ctx context.Context, subject string) (any, error) {
		var out any
		err := s.vault.Use(ctx, vault.Identity{Subject: subject, Provider: s.provider}, func(credential []byte) error {
			value, err := s.reader.Read(ctx, subject, name, credential)
			if err != nil {
				return err
			}
			out = value
			return nil
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	}
}

// sessionAuth is the Authenticator used when logins are configured: it reads the
// subject the source session established.
type sessionAuth struct{ sessions *scs.SessionManager }

func (a sessionAuth) Authenticate(ctx context.Context) (Principal, error) {
	subject := a.sessions.GetString(ctx, SessionKey)
	if subject == "" {
		return Principal{}, errors.New("referencesource: no session at the source")
	}
	return Principal{Subject: subject}, nil
}

func newSessions(cfg SessionConfig) *scs.SessionManager {
	if cfg.CookieName == "" {
		cfg.CookieName = "refsrc_session"
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = 12 * time.Hour
	}
	sessions := scs.New()
	sessions.Cookie.Name = cfg.CookieName
	sessions.Cookie.HttpOnly = true
	sessions.Cookie.SameSite = http.SameSiteLaxMode
	sessions.Cookie.Secure = cfg.Secure
	sessions.Lifetime = cfg.Lifetime
	return sessions
}

func scopesOf(d upstreamkit.Discovery) []oauth.Scope {
	out := make([]oauth.Scope, 0, len(d.ScopesSupported))
	for _, s := range d.ScopesSupported {
		out = append(out, oauth.Scope(s))
	}
	return out
}

func scopeRegistry(d upstreamkit.Discovery) (*oauth.Registry, error) {
	descriptors := make([]oauth.Descriptor, 0, len(d.ScopesSupported))
	for _, scope := range d.ScopesSupported {
		descriptors = append(descriptors, oauth.Descriptor{
			Scope: oauth.Scope(scope),
			Title: scope,
			Risk:  oauth.RiskLow,
		})
	}
	return oauth.NewRegistry(descriptors...)
}
