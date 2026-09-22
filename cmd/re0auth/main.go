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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/internal/config"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
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

// storage bundles the persistence ports so the composition root does not thread
// five return values through every call.
type storage struct {
	accounts account.Store
	tokens   oauth.Store
	devices  oauth.DeviceStore
	clients  oauth.ClientRegistry
	// credentials is the vault's repository: the one place a decrypted secret
	// never reaches.
	credentials vault.Repo
	bindings    federation.BindingStore
	bindFlows   federation.BindFlowStore
	sessions    scs.Store
	authzStore  authz.Store
	// audit is the durable audit-log sink; nil would mean "nobody is auditing",
	// which must never be a silent state.
	audit audit.Logger
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

	as, err := oauth.NewService(store.clients, store.tokens, logger, oauth.Config{
		Issuer:  cfg.Issuer,
		Scopes:  oauth.DefaultRegistry(),
		Devices: store.devices,
		// RFC 8628 hands this URI to the user's browser, so it must be the
		// frontend's page, not the JSON endpoint that backs it.
		VerificationPath: webui.BasePath + "/device",
	})
	if err != nil {
		die("authorization server", err)
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

	sessions := auth.NewManager(auth.Options{Secure: cfg.CookieSecure, Store: store.sessions})
	authHandler, err := auth.NewHandler(sessions, idpRegistry, store.accounts)
	if err != nil {
		die("auth", err)
	}

	// The handle must outlive the upstream binding round trip; see
	// authorizationRequestTTL.
	authzService, err := authz.NewService(as, store.authzStore, authz.Config{TTL: authorizationRequestTTL})
	if err != nil {
		die("authz", err)
	}

	registry, err := federation.NewRegistry(cfg.sources...)
	if err != nil {
		die("sources", err)
	}
	federationService, err := federation.NewService(federation.Config{
		Registry: registry,
		Bindings: store.bindings,
		Flows:    store.bindFlows,
		Vault:    vaultService,
		Doer:     &http.Client{Timeout: 20 * time.Second},
		BaseURL:  cfg.Issuer,
	})
	if err != nil {
		die("federation", err)
	}

	api, err := httpapi.New(httpapi.Config{
		Issuer:     cfg.Issuer,
		AS:         as,
		Sessions:   sessions,
		Accounts:   store.accounts,
		Auth:       authHandler,
		Authz:      authzService,
		Federation: federationService,
		Frontend:   webui.FS(),
		Limiter:    buildLimiter(cfg),
		// One switch for "this issuer is https": Secure cookies and HSTS.
		Secure: cfg.CookieSecure,
	})
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
			tokens:      oauth.NewMemoryStore(),
			devices:     oauth.NewMemoryDeviceStore(),
			clients:     oauth.NewMemoryClientRegistry(),
			credentials: vault.NewMemoryRepo(),
			bindings:    federation.NewMemoryBindingStore(),
			bindFlows:   federation.NewMemoryBindFlowStore(),
			authzStore:  authz.NewMemoryStore(),
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
	authzRequests := db.Authz()
	return storage{
		accounts:    db.Accounts(),
		tokens:      db.Tokens(),
		devices:     db.Devices(),
		clients:     db.Clients(),
		credentials: db.Vault(),
		bindings:    db.Bindings(),
		bindFlows:   db.BindFlows(),
		sessions:    sessions,
		authzStore:  authzRequests,
		audit:       db.Audit(),
		// Both are swept, and the first error is surfaced: one failing must not
		// hide the other.
		sweep: func(ctx context.Context) (int64, error) {
			removedSessions, errSessions := sessions.SweepExpired(ctx)
			removedRequests, errRequests := authzRequests.SweepExpired(ctx)
			removed := removedSessions + removedRequests
			if errSessions != nil {
				return removed, errSessions
			}
			return removed, errRequests
		},
		durable: true,
		close:   db.Close,
	}, nil
}

// persistentPorts names every storage port that survives a restart, so the
// startup line says which ones rather than only how many.
const persistentPorts = "accounts, tokens, device authorizations, clients, " +
	"vault credentials, bindings, bind flows, sessions, authorization requests"

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
