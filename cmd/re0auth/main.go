// Command re0auth is the composition root: it reads configuration from a TOML
// file plus the environment, wires every component, and serves the two HTTP
// planes.
//
// It exists so the storage adapters have a real caller. Ports that are still
// in-process are announced loudly at startup, because "which parts are durable"
// must never be a guess.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
	"github.com/Re0Auth/r0semi/internal/webui"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

var (
	configFlag = flag.String("config", "", "path to the TOML config file (default: RE0AUTH_CONFIG, then config/re0auth.toml)")
	rotateKeys = flag.Bool("rotate-keys", false,
		"re-wrap every stored credential's DEK under the current KEK, then exit")
)

const (
	// federationMaxConcurrent bounds how many requests the data plane may have in
	// flight to upstream sources at once. It is the bulkhead: past it, callers
	// wait for a slot rather than piling up goroutines, each holding a buffered
	// body, when a source turns slow.
	federationMaxConcurrent = 256

	// opJanitorInterval is how often the in-memory OP store is swept of expired
	// records. It is well under the shortest record lifetime, so the maps stay
	// close to the size the live records justify.
	opJanitorInterval = 5 * time.Minute
)

// storage bundles the persistence ports so the composition root does not thread
// five return values through every call.
type storage struct {
	accounts account.Store
	clients  admin.Clients
	// credentials is the vault's repository: the one place a decrypted secret
	// never reaches.
	credentials vault.Repo
	bindings    federation.BindingStore
	bindFlows   federation.BindFlowStore
	sessions    scs.Store
	// sessionRevoker drops every browser session for the Kill Switch. Nil in
	// memory mode, where sessions cannot be enumerated.
	sessionRevoker admin.SessionRevoker
	// sessionIndex maps a session token to its account, so the Kill Switch can
	// clear one account's sessions. Nil in memory mode.
	sessionIndex auth.SessionIndex
	// audit is the durable audit-log sink; nil would mean "nobody is auditing",
	// which must never be a silent state.
	audit audit.Logger
	// db is the Postgres handle when durable; nil in memory mode. The OpenID
	// Provider store is built on it in the composition root.
	db *postgres.DB
	// sweep removes expired auxiliary rows and reports how many. Nil when there
	// is nothing to sweep.
	sweep   func(context.Context) (int64, error)
	durable bool
	close   func()
}

// buildLimiter returns the per-address limiter, or nil when the deployment
// turned it off.
//
// It is configurable because "one client address" means very different things in
// different places: every user behind one NAT, a LAN of trusted machines, and a
// test run on loopback are all one address to this code. A deployment sitting
// behind its own limiter sets zero and says so, rather than having a cap it never
// chose.
func buildLimiter(cfg settings) *ratelimit.Limiter {
	if cfg.RateLimit <= 0 {
		return nil
	}
	return ratelimit.New(cfg.RateLimit, cfg.RateLimitBurst)
}

// die reports why the process cannot start, and exits non-zero.
//
// It replaces log.Fatalf so the reason is a structured field rather than a
// sentence, and so the stage is machine-readable: "which part refused to start"
// is the first question anyone asks.
func die(stage string, err error) {
	slog.Error("cannot start", "stage", stage, "err", err)
	os.Exit(1)
}

func main() {
	flag.Parse()

	// Before anything that logs. A bad level or format is a configuration error
	// like any other: refuse to start rather than run with a setting the operator
	// did not choose. This is the one message that cannot go through slog, because
	// slog is what failed to configure.
	if err := config.SetupLogging("RE0AUTH"); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "re0auth:", err)
		os.Exit(1)
	}

	configPath, explicit := config.Path(*configFlag, "RE0AUTH_CONFIG", defaultConfigPath)
	switch {
	case configPath != "":
		slog.Info("configuration file", "path", configPath)
	case explicit:
		slog.Error("cannot start", "stage", "config", "reason", "config file does not exist", "path", *configFlag)
		os.Exit(1)
	default:
		slog.Info("no configuration file; configuring from the environment only")
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		die("config", err)
	}
	ctx := context.Background()

	store, err := openStorage(ctx, cfg)
	if err != nil {
		die("storage", err)
	}
	defer store.close()
	reportDurability(store)

	logger := store.audit
	if store.durable {
		slog.Info("audit log", "driver", "postgres")
	} else {
		slog.Warn("audit log is in-memory; records do not survive a restart")
	}
	if store.sweep != nil {
		go sweepLoop(ctx, store.sweep, 15*time.Minute)
	}

	vaultService, err := openVault(cfg, store.credentials, logger)
	if err != nil {
		die("vault", err)
	}
	if len(cfg.RetiredKEKs) > 0 {
		// Said loudly, because a retired key is a key that can still open something.
		slog.Warn("retired KEKs are configured and can still unwrap credentials; "+
			"run with -rotate-keys to re-wrap them, then remove them from the config",
			"retired", len(cfg.RetiredKEKs))
	}
	if *rotateKeys {
		rotateAndReport(ctx, vaultService)
		return
	}

	if err := seedClient(ctx, store.clients, cfg); err != nil {
		die("seed client", err)
	}

	idpRegistry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: cfg.Issuer,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
		Credentials:  cfg.idpCredentials,
	})
	if err != nil {
		die("idp", err)
	}
	if len(cfg.idpCredentials) == 0 {
		slog.Warn("no identity provider is configured; nobody can sign in")
	}

	sessions := auth.NewManager(auth.Options{Secure: cfg.CookieSecure, Store: store.sessions, Index: store.sessionIndex})
	authHandler, err := auth.NewHandler(sessions, idpRegistry, store.accounts)
	if err != nil {
		die("auth", err)
	}

	// The handle must outlive the upstream binding round trip; see
	// authorizationRequestTTL. The OP store owns it now, in both storage modes.
	registry, err := federation.NewRegistry(cfg.sources...)
	if err != nil {
		die("sources", err)
	}
	// One pooled, bounded client for every outbound call the data plane makes.
	// The standard library's default transport keeps only two idle connections per
	// host, which for a proxy fronting a handful of sources means redialing on
	// nearly every request. Doer and HTTPClient point at the same client, so the
	// resource fetches and the OAuth token exchange share one connection pool.
	federationClient := httpclient.NewOutboundClient(httpclient.OutboundConfig{
		Timeout:       20 * time.Second,
		MaxConcurrent: federationMaxConcurrent,
	})
	federationService, err := federation.NewService(federation.Config{
		Registry:   registry,
		Bindings:   store.bindings,
		Flows:      store.bindFlows,
		Vault:      vaultService,
		Doer:       federationClient,
		HTTPClient: federationClient,
		BaseURL:    cfg.Issuer,
	})
	if err != nil {
		die("federation", err)
	}

	apiConfig := httpapi.Config{
		Issuer:     cfg.Issuer,
		Sessions:   sessions,
		Accounts:   store.accounts,
		Auth:       authHandler,
		Federation: federationService,
		Frontend:   webui.FS(),
		Limiter:    buildLimiter(cfg),
		// One switch for "this issuer is https": Secure cookies and HSTS.
		Secure: cfg.CookieSecure,
	}
	// Every deployment runs the OpenID Provider (ADR-0001 P4b). The only thing a
	// DATABASE_URL changes is where the OP keeps its state: Postgres or memory.
	oidcHandler, oidcStore, err := openOIDC(ctx, cfg, store, sessions, logger)
	if err != nil {
		die("oidc", err)
	}
	apiConfig.OIDC = oidcHandler
	apiConfig.TokenIntrospector = oidcHandler
	apiConfig.GrantStore = oidcStore
	apiConfig.DeviceStore = oidcStore
	apiConfig.Authorization = oidcHandler
	// The OP owns the tokens, so it is also what revokes them.
	tokenRevoker := oauth.TokenAdmin(oidcStore)
	if store.durable {
		slog.Info("authorization engine", "engine", "openid-provider", "store", "postgres")
	} else {
		slog.Info("authorization engine", "engine", "openid-provider", "store", "memory")
	}

	// The operator plane. It is mounted only when a deployment names at least one
	// admin account; `httpapi.New` rejects a service with an empty allowlist, and
	// this skips it entirely rather than mounting a door with no lock.
	if len(cfg.adminSubjects) > 0 {
		adminSvc, err := admin.New(admin.Config{
			Clients:  store.clients,
			Tokens:   tokenRevoker,
			Sessions: store.sessionRevoker,
			Bindings: bindingRevoker{fed: federationService},
			Audit:    logger,
		})
		if err != nil {
			die("admin", err)
		}
		admins := make([]account.UserID, 0, len(cfg.adminSubjects))
		for _, s := range cfg.adminSubjects {
			admins = append(admins, account.UserID(s))
		}
		apiConfig.Admin = adminSvc
		apiConfig.Admins = admins
		slog.Info("operator plane enabled", "admins", len(admins))
	}
	api, err := httpapi.New(apiConfig)
	if err != nil {
		die("http", err)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// The standard library's server writes its own diagnostics. Routing them
		// through the same handler keeps a connection or TLS error from being the
		// one line in the log that looks different.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
	slog.Info("listening", "addr", cfg.Addr, "issuer", cfg.Issuer)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		die("serve", err)
	}
}

// openStorage picks the backends. A DSN turns on Postgres and applies
// migrations; without one everything lives in memory.
func openStorage(ctx context.Context, cfg settings) (storage, error) {
	var store storage
	if cfg.DatabaseURL == "" {
		store = storage{
			accounts:    account.NewMemoryStore(),
			clients:     oauth.NewMemoryClientRegistry(),
			credentials: vault.NewMemoryRepo(),
			bindings:    federation.NewMemoryBindingStore(),
			bindFlows:   federation.NewMemoryBindFlowStore(),
			audit:       audit.NewMemoryLogger(),
			// A nil session store makes auth.NewManager fall back to its
			// in-memory one.
			sessions: nil,
			durable:  false,
			close:    func() {},
		}
		return store, nil
	}

	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return storage{}, err
	}
	slog.Info("storage ready", "driver", "postgres", "migrated", true)
	sessions := db.Sessions()
	return storage{
		db:          db,
		accounts:    db.Accounts(),
		clients:     db.Clients(),
		credentials: db.Vault(),
		bindings:    db.Bindings(),
		bindFlows:   db.BindFlows(),
		sessions:    sessions,
		// The concrete store, not the scs.Store interface: only it can drop
		// every session at once, which is the Kill Switch's session half.
		sessionRevoker: sessions,
		// The same object, for the auth layer to record which account a session
		// belongs to.
		sessionIndex: sessions,
		audit:        db.Audit(),
		sweep: func(ctx context.Context) (int64, error) {
			return sessions.SweepExpired(ctx)
		},
		durable: true,
		close:   db.Close,
	}, nil
}

// persistentPorts names every storage port that survives a restart, so the
// startup line says which ones rather than only how many.
const persistentPorts = "accounts, clients, " +
	"vault credentials, bindings, bind flows, sessions, " +
	"OP authorization requests, OP tokens, OP device authorizations"

// reportDurability states plainly what survives a restart. Silence here would
// read as "everything is durable", which is the one thing this project must not
// imply.
func reportDurability(store storage) {
	if !store.durable {
		slog.Warn("storage is in-memory: a restart loses sessions, bindings and pending requests",
			"because", "no DATABASE_URL")
		return
	}
	slog.Info("storage ready", "driver", "postgres", "persistent_ports", persistentPorts)
}

// opJanitorLoop sweeps expired records from the in-memory OP store on a ticker.
// It returns when ctx is done, so it stops with the process rather than
// outliving it. It is the memory-store counterpart of sweepLoop: the store
// exposes a pure SweepExpired, and the loop that calls it lives here, where the
// logging policy does.
func opJanitorLoop(ctx context.Context, sweep interface{ SweepExpired() int }, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if removed := sweep.SweepExpired(); removed > 0 {
				slog.Info("swept expired OP records", "removed", removed)
				continue
			}
			slog.Debug("OP sweep found nothing to remove")
		}
	}
}

// sweepLoop periodically removes expired sessions. Find already deletes the ones
// it is asked about; this covers the ones nobody comes back to.
func sweepLoop(ctx context.Context, sweep func(context.Context) (int64, error), every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := sweep(ctx)
			if err != nil {
				slog.Warn("session sweep failed", "err", err)
				continue
			}
			if removed > 0 {
				slog.Info("swept expired rows", "removed", removed)
				continue
			}
			// Nothing to remove is the normal case, so it is only worth a line to
			// somebody asking whether the loop is alive at all — which is what the
			// debug level is for.
			slog.Debug("sweep found nothing to remove")
		}
	}
}

func openVault(cfg settings, credentials vault.Repo, logger audit.Logger) (vault.Service, error) {
	// The KEK is an external trust boundary, which is why the wrapper is injected
	// rather than derived: replacing this with a KMS-backed KeyWrapper is a
	// deployment decision, not a code change. What that would and would not buy is
	// in docs/threat-model.md §6.0.
	wrapper, err := vault.NewLocalKeyWrapper(cfg.KEKID, cfg.KEK)
	if err != nil {
		return nil, err
	}
	if len(cfg.RetiredKEKs) == 0 {
		return vault.NewService(credentials, wrapper, logger)
	}

	// Retired keys can only unwrap. Without them a rotation could not read what it
	// is re-wrapping, which is the whole reason they are configurable at all.
	retired := make([]vault.KeyWrapper, 0, len(cfg.RetiredKEKs))
	for _, r := range cfg.RetiredKEKs {
		w, err := vault.NewLocalKeyWrapper(r.ID, r.KEK)
		if err != nil {
			return nil, err
		}
		retired = append(retired, w)
	}
	return vault.NewService(credentials, wrapper, logger, vault.WithRetiredKeys(retired...))
}

// rotateAndReport re-wraps the vault under the current KEK.
//
// It is a startup action rather than a running one, for the same reason migrations
// are: it needs the old key configured alongside the new one, and it decides what
// "current" means, so it should not race a server that is already serving.
func rotateAndReport(ctx context.Context, v vault.Service) {
	rotation, err := v.Rotate(ctx)
	if err != nil {
		die("rotate keys", err)
	}
	slog.Info("key rotation complete",
		"scanned", rotation.Scanned,
		"rewrapped", rotation.Rewrapped,
		"already_current", rotation.AlreadyCurrent)
	if rotation.Scanned == 0 {
		slog.Warn("there was nothing to rotate; is the configured storage the one holding credentials?")
	}
}

// oidcBackend is the OP store surface the composition root needs. Both
// storage adapters satisfy it, so the rest of main does not care which one ran.
type oidcBackend interface {
	op.Storage
	op.DeviceAuthorizationStorage
	CompleteLogin(ctx context.Context, id, subject string, scopes []string) error
	Grants(ctx context.Context, subject string) ([]oauth.Grant, error)
	RevokeGrant(ctx context.Context, subject, clientID string) error
	RevokeTokens(ctx context.Context, f oauth.TokenFilter) (int, error)
	DescribeDeviceAuthorization(ctx context.Context, userCode string) (oauth.DeviceAuthorization, error)
	DecideDeviceAuthorization(ctx context.Context, userCode, subject string, approve bool, scopes, explicit []oauth.Scope) error
}

// openOIDC builds the OpenID Provider store and HTTP handler. The store is
// Postgres when a database is configured and in-memory otherwise (ADR-0001 P4b);
// the handler and every policy around it are identical either way.
func openOIDC(ctx context.Context, cfg settings, store storage, sessions *auth.Manager, logger audit.Logger) (*oidchttp.Handler, oidcBackend, error) {
	tokenKey, err := oidcTokenKey()
	if err != nil {
		return nil, nil, err
	}
	retiredTokens, err := oidcRetiredTokenKeys()
	if err != nil {
		return nil, nil, err
	}
	key, err := oidcSigningKey()
	if err != nil {
		return nil, nil, err
	}
	retiredSigning, err := oidcRetiredSigningKeys()
	if err != nil {
		return nil, nil, err
	}
	registry := oauth.DefaultRegistry()
	scopes := make([]string, 0, len(registry.Descriptors()))
	for _, d := range registry.Descriptors() {
		scopes = append(scopes, d.Scope.String())
	}
	signer := oidcstore.NewSigner("re0auth", key).WithRetired(retiredSigning...)
	login := func(ctx context.Context, id string) string {
		// Bind the request to the browser that started it, so a relayed id cannot
		// be approved elsewhere. GetClientByClientID hands us the request context,
		// which is where the session lives.
		sessions.Bind(ctx, "authz", id)
		return webui.BasePath + "/consent?id=" + url.QueryEscape(id)
	}

	var oidcStore oidcBackend
	if store.db != nil {
		oidcStore, err = store.db.OIDC(store.clients, postgres.OIDCOptions{
			Registry:   registry,
			Signer:     signer,
			Audit:      logger,
			Login:      login,
			RequestTTL: authorizationRequestTTL,
		})
	} else {
		mem, err := memory.NewOIDCStore(memory.OIDCOptions{
			Clients:    store.clients,
			Registry:   registry,
			Signer:     signer,
			Audit:      logger,
			Login:      login,
			RequestTTL: authorizationRequestTTL,
		})
		if err != nil {
			return nil, nil, err
		}
		// The memory store never expires a record on its own — a lookup refuses an
		// expired one, but nothing removes it. Without this loop the token and
		// pending-request maps grow for the life of the process, and every call
		// that scans them under the store's single lock (grants, revocation) then
		// gets slower as they do.
		go opJanitorLoop(ctx, mem, opJanitorInterval)
		oidcStore = mem
	}
	if err != nil {
		return nil, nil, err
	}
	handler, err := oidchttp.New(oidchttp.Config{
		Issuer:           cfg.Issuer,
		Storage:          oidcStore,
		CryptoKey:        tokenKey,
		CryptoKeyID:      "re0auth",
		Scopes:           scopes,
		AllowInsecure:    !cfg.CookieSecure,
		Clients:          store.clients,
		Registry:         registry,
		Consent:          oidcStore,
		RetiredTokenKeys: retiredTokens,
	})
	if err != nil {
		return nil, nil, err
	}
	return handler, oidcStore, nil
}

// oidcTokenKey reads the 32-byte bearer-token encryption key.
//
// It is required, not defaulted. Minting an ephemeral key when the operator
// forgot one would turn a restart into a fleet-wide logout (every opaque access
// token becomes unreadable), which is exactly the kind of silent degradation
// this project refuses. Fail closed, like the KEK and the issuer.
func oidcTokenKey() ([32]byte, error) {
	var key [32]byte
	v := strings.TrimSpace(os.Getenv("RE0AUTH_OIDC_TOKEN_KEY"))
	if v == "" {
		return key, errors.New("RE0AUTH_OIDC_TOKEN_KEY is required (32 bytes, base64)")
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != 32 {
		return key, errors.New("RE0AUTH_OIDC_TOKEN_KEY must be base64 of exactly 32 bytes")
	}
	copy(key[:], b)
	return key, nil
}

// oidcRetiredTokenKeys parses "id:base64,id:base64" old token keys. They decrypt
// only, so a rotation can overlap without invalidating live access tokens.
func oidcRetiredTokenKeys() ([]oidchttp.RetiredTokenKey, error) {
	v := strings.TrimSpace(os.Getenv("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS"))
	if v == "" {
		return nil, nil
	}
	var out []oidchttp.RetiredTokenKey
	for _, part := range strings.Split(v, ",") {
		id, encoded, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok || id == "" {
			return nil, fmt.Errorf("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS entry %q must be id:base64", part)
		}
		b, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("RE0AUTH_OIDC_RETIRED_TOKEN_KEYS entry %q must be 32 bytes base64", id)
		}
		var key [32]byte
		copy(key[:], b)
		out = append(out, oidchttp.RetiredTokenKey{ID: id, Key: key})
	}
	return out, nil
}

// oidcSigningKey reads the RS256 key (base64 PKCS#8 DER). Required: an ephemeral
// key would invalidate every id_token across a restart, so it fails closed.
func oidcSigningKey() (*rsa.PrivateKey, error) {
	v := strings.TrimSpace(os.Getenv("RE0AUTH_OIDC_SIGNING_KEY"))
	if v == "" {
		return nil, errors.New("RE0AUTH_OIDC_SIGNING_KEY is required (PKCS#8 DER, base64)")
	}
	der, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("RE0AUTH_OIDC_SIGNING_KEY: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("RE0AUTH_OIDC_SIGNING_KEY: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("RE0AUTH_OIDC_SIGNING_KEY must be an RSA private key")
	}
	return key, nil
}

// oidcRetiredSigningKeys parses "kid:base64, kid:base64" old public keys
// (PKIX DER). They are published in the JWKS so id_tokens signed with them still
// verify during a rotation.
func oidcRetiredSigningKeys() ([]oidcstore.RetiredSigningKey, error) {
	v := strings.TrimSpace(os.Getenv("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS"))
	if v == "" {
		return nil, nil
	}
	var out []oidcstore.RetiredSigningKey
	for _, part := range strings.Split(v, ",") {
		id, encoded, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok || id == "" {
			return nil, fmt.Errorf("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS entry %q must be kid:base64", part)
		}
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS entry %q: %w", id, err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS entry %q: %w", id, err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("RE0AUTH_OIDC_RETIRED_SIGNING_KEYS entry %q must be an RSA public key", id)
		}
		out = append(out, oidcstore.RetiredSigningKey{ID: id, Public: rsaPub})
	}
	return out, nil
}

// bindingRevoker adapts the federation service to the operator plane's binding
// port. The mapping is trivial; it exists so neither package has to import the
// other's types.
type bindingRevoker struct{ fed federation.Service }

func (b bindingRevoker) RevokeAllBindings(ctx context.Context) (admin.BindingOutcome, error) {
	summary, err := b.fed.RevokeAllBindings(ctx)
	return bindingOutcome(summary), err
}

func (b bindingRevoker) RevokeSubjectBindings(ctx context.Context, subject string) (admin.BindingOutcome, error) {
	summary, err := b.fed.RevokeUserBindings(ctx, account.UserID(subject))
	return bindingOutcome(summary), err
}

func bindingOutcome(s federation.BindingRevocationSummary) admin.BindingOutcome {
	return admin.BindingOutcome{
		Total:       s.Total,
		Revoked:     s.Revoked,
		Cascade:     s.Cascade,
		Unsupported: s.Unsupported,
		Unavailable: s.Unavailable,
		Orphaned:    s.Orphaned,
		Failed:      s.Failed,
	}
}

// seedClient registers the first-party downstream client if it is not already
// present. Re-running the process must not fail, so an existing registration is
// left untouched rather than overwritten.
func seedClient(ctx context.Context, clients oauth.ClientRegistry, cfg settings) error {
	_, err := clients.Get(ctx, cfg.clientID)
	switch {
	case err == nil:
		slog.Info("downstream client already registered", "client_id", cfg.clientID)
		return nil
	case !errors.Is(err, oauth.ErrClientNotFound):
		return err
	}

	typ := oauth.ClientPublic
	if cfg.clientSecret != "" {
		typ = oauth.ClientConfidential
	}
	scopes := make([]oauth.Scope, 0, len(cfg.clientScopes))
	for _, s := range cfg.clientScopes {
		scopes = append(scopes, oauth.Scope(s))
	}
	client, err := oauth.NewClient(cfg.clientID, cfg.clientName, typ, cfg.clientSecret, cfg.clientRedirects, scopes)
	if err != nil {
		return err
	}
	if err := clients.Create(ctx, client); err != nil {
		return err
	}
	slog.Info("registered downstream client", "client_id", client.ID, "type", client.Type)
	return nil
}
