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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/observability"
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
	showVersion = flag.Bool("version", false, "print the build version and exit")
)

// version identifies the build. The release target stamps it at link time
// (`-ldflags -X main.version=…`); a binary compiled by hand answers "dev", which
// is the honest answer to "which build is this?" when nobody stamped it.
var version = "dev"

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

	// HTTP server timeouts. ReadHeaderTimeout bounds a slow-header (Slowloris)
	// client; IdleTimeout bounds a kept-alive connection that has gone quiet. Read
	// and Write bound a whole exchange: the data plane proxies an upstream
	// response, so Write is generous enough to cover the outbound client's own
	// deadline rather than cut a legitimately slow read short.
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	// maxHeaderBytes is well under the standard library's 1 MiB default: every
	// header this service reads is small, and a smaller cap is a cheaper refusal
	// for a caller that would otherwise spend memory on one.
	maxHeaderBytes = 64 << 10

	// shutdownTimeout is how long a graceful shutdown waits for in-flight
	// requests to finish after a signal, before closing their connections anyway.
	// It bounds the drain so a stuck handler cannot hold a deploy open forever.
	shutdownTimeout = 30 * time.Second
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
	// legacy, when set, clears the retired hand-rolled engine's non-token tables
	// during account erasure. Nil in memory mode, where those tables do not exist.
	legacy lifecycle.LegacyPurger
	// db is the Postgres handle when durable; nil in memory mode. The OpenID
	// Provider store is built on it in the composition root.
	db *postgres.DB
	// sweep removes expired rows -- dated tokens, codes and pending requests, plus
	// sessions -- and reports how many. Nil when there is nothing to sweep.
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

	// -version has to work with no config and no logging configured, because the
	// question it answers ("which build is this?") is asked by someone who is
	// already looking at a deployment that will not start.
	if *showVersion {
		fmt.Println("re0auth", version)
		return
	}

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

	// A signal context. Cancelling it on SIGTERM (what an orchestrator sends on a
	// rolling deploy) or SIGINT begins a graceful drain instead of an abrupt exit,
	// and it is what the background loops are tied to, so they stop with the
	// process rather than outliving it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Once a shutdown has begun, restore default signal handling: a second signal
	// must kill the process rather than be swallowed while the drain waits out a
	// handler that is not coming back. stop is idempotent, so the deferred call is
	// still safe.
	go func() {
		<-ctx.Done()
		stop()
	}()

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

	// The Prometheus instrumentation. It is always built: whether it is *exported*
	// depends on an internal address being configured, but recording is cheap and
	// a metric that only starts once someone remembers to enable it is missing
	// from exactly the incident it was meant to explain.
	metrics := observability.New()

	apiConfig := httpapi.Config{
		Issuer:     cfg.Issuer,
		Sessions:   sessions,
		Accounts:   store.accounts,
		Auth:       authHandler,
		Federation: federationService,
		Frontend:   webui.FS(),
		Limiter:    buildLimiter(cfg),
		// Concurrency cap, separate from the rate limiter: rate bounds arrivals,
		// this bounds work in progress.
		MaxInFlight: cfg.MaxInFlight,
		// Which peers may speak for the client through X-Forwarded-For. Empty
		// means none, so the peer address is the client.
		TrustedProxies: cfg.TrustedProxies,
		// One switch for "this issuer is https": Secure cookies and HSTS.
		Secure: cfg.CookieSecure,
		// Readiness is "can this instance reach what it needs to serve". With a
		// database that is the pool; without one there is nothing to reach, so the
		// probe stays nil and /readyz answers ready.
		Ready: readinessProbe(store),
		// The golden-signal instrumentation, labelled by plane. Always on; see
		// where it is built above.
		Metrics: metrics,
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
	// Tokens can live in two engines: the OP's tables, and — for a deployment
	// migrated from the retired hand-rolled engine — the token tables it left
	// behind. Both are revoked by the same step, so neither an erasure nor the
	// Kill Switch can report success while leaving a token alive in the other. The
	// legacy store advertises the capability; a deployment without one adds none.
	revokers := oauth.TokenAdmins{oidcStore}
	if legacyTokens, ok := store.legacy.(oauth.TokenAdmin); ok {
		revokers = append(revokers, legacyTokens)
	}
	tokenRevoker := oauth.TokenAdmin(revokers)
	if store.durable {
		slog.Info("authorization engine", "engine", "openid-provider", "store", "postgres")
	} else {
		slog.Info("authorization engine", "engine", "openid-provider", "store", "memory")
	}

	// The operator plane. It is mounted only when a deployment names at least one
	// admin account; `httpapi.New` rejects a service with an empty allowlist, and
	// this skips it entirely rather than mounting a door with no lock.
	// Operator step-up window. Set unconditionally: it is inert when the operator
	// plane is not mounted, and a value that only applies in some deployments is
	// easier to reason about than one wired in two places.
	apiConfig.AdminReauthWindow = cfg.AdminReauthWindow

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

	// The audit log's read side. Only the durable sink can answer: the in-memory
	// log is a bounded ring buffer with no record chain, so a "verify" over it
	// would report on a guarantee it does not have. Mounted when available rather
	// than gated on storage mode, so the difference stays a property of the sink.
	//
	// It also rides with the operator plane: reading the log means reading about
	// every account, so the endpoints are admin-only and the plane is not mounted
	// without an allowlist. A durable deployment with no admins is legitimate — it
	// simply has no read API — and it must still start, which is why this is gated
	// here rather than left for httpapi.New to reject.
	if reader := auditReadSide(cfg.adminSubjects, store.audit); reader != nil {
		apiConfig.Audit = reader
		slog.Info("audit read API enabled", "endpoints", "/v1/admin/audit, /v1/admin/audit/verify")
	}

	// Self-service account erasure. Always wired: PIPL/GDPR require a way to delete
	// one's own data, and a deployment that could not do it would be offering
	// sign-in it cannot undo.
	//
	// The wipers are the storage ports directly, not the vault Service or the
	// federation Service. The vault Service audits every operation it performs,
	// which is correct for credential use and wrong here: erasing the account's
	// pseudonym key would then depend on the very log it is trying to detach from.
	// Deleting rows at the repo layer bypasses that circularity while keeping the
	// same crypto-shredding effect — the wrapped DEK lives in the row.
	deleter, err := lifecycle.New(lifecycle.Config{
		Accounts: store.accounts,
		Tokens:   tokenRevoker,
		Vault:    store.credentials,
		Bindings: erasureBindings{fed: federationService},
		Sessions: store.sessionRevoker,
		OIDC:     oidcStore,
		Flows:    store.bindFlows,
		Legacy:   store.legacy,
		// The durable audit sink owns the subject pseudonyms, so it is what destroys
		// the key that makes a deleted account's history linkable. It is nil in
		// memory mode, where the log is a ring buffer that keeps no keys.
		Pseudonyms: pseudonymStore(store.audit),
		Audit:      logger,
	})
	if err != nil {
		die("lifecycle", err)
	}
	apiConfig.Deleter = deleter
	if store.sessionRevoker == nil {
		// The in-memory store cannot enumerate one account's sessions, so an
		// erasure there clears the token tables but cannot promise the browser
		// sessions are gone. Said at startup rather than discovered later.
		slog.Warn("account erasure cannot clear per-account sessions without a durable session store; " +
			"sessions for a deleted account are only dropped on expiry")
	}

	api, err := httpapi.New(apiConfig)
	if err != nil {
		die("http", err)
	}

	// Bind before announcing, so "listening" is only printed for an address that
	// was actually obtained — and so the log names the resolved address, which is
	// what a deployment with a port of 0 needs to read.
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		die("listen", err)
	}
	endpoints := []endpoint{{server: newServer(api.Handler()), listener: listener}}

	// The operational surface — metrics and the runtime profiling endpoints — is
	// a separate listener, off unless an address is configured. It is separate on
	// purpose: a profile dumps process internals, and that is not something the
	// public port should ever be able to answer.
	if cfg.InternalAddr != "" {
		internalListener, err := net.Listen("tcp", cfg.InternalAddr)
		if err != nil {
			die("internal listen", err)
		}
		endpoints = append(endpoints, endpoint{
			server:   newServer(metrics.InternalHandler()),
			listener: internalListener,
		})
		slog.Info("internal surface listening",
			"addr", internalListener.Addr().String(),
			"endpoints", "/metrics, /debug/pprof/")
	}

	slog.Info("listening", "addr", listener.Addr().String(), "issuer", cfg.Issuer, "version", version)
	if err := serveUntilSignal(ctx, shutdownTimeout, endpoints...); err != nil {
		// Not die(): the process started fine, so "cannot start" would be a lie.
		// Reaching here means serving stopped for a reason other than a clean
		// shutdown, or the drain ran out of time.
		slog.Error("server stopped with an error", "err", err)
		os.Exit(1)
	}
	slog.Info("stopped")
}

// endpoint is one listener together with the server that serves it. Shutdown has
// to drain every one of them, which is why they travel together rather than as
// parallel slices a caller has to keep in step.
type endpoint struct {
	server   *http.Server
	listener net.Listener
}

// newServer builds an HTTP server with the limits every listener here shares. The
// public and internal surfaces differ only in what they serve, not in how they
// are bounded.
func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h,
		// The standard library's server writes its own diagnostics. Routing them
		// through the same handler keeps a connection or TLS error from being the
		// one line in the log that looks different.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),

		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// serveUntilSignal serves every endpoint until ctx is cancelled — a shutdown
// signal — then drains in-flight requests within timeout before closing their
// connections.
//
// The drain is the point: on a rolling deploy the process is replaced while it is
// answering requests, and an abrupt exit drops them. Requests already in flight
// are given the chance to finish; the listeners stop accepting new ones first, so
// a load balancer sees the instance go away cleanly.
//
// It returns nil for a shutdown it performed itself, and the underlying error
// only when serving failed for some other reason.
func serveUntilSignal(ctx context.Context, timeout time.Duration, endpoints ...endpoint) error {
	serveErr := make(chan error, len(endpoints))
	for _, ep := range endpoints {
		go func(ep endpoint) { serveErr <- ep.server.Serve(ep.listener) }(ep)
	}

	select {
	case err := <-serveErr:
		// Serve reports ErrServerClosed after a Shutdown, which is not a failure.
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received; draining in-flight requests", "timeout", timeout)
		drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var err error
		for _, ep := range endpoints {
			if e := ep.server.Shutdown(drainCtx); e != nil {
				// The drain ran out of time (or failed for another reason): close
				// the connections rather than wait on handlers that are not coming
				// back.
				slog.Error("graceful shutdown did not finish; closing connections", "err", e)
				_ = ep.server.Close()
				err = e
			}
		}
		return err
	}
}

// readinessProbe returns the /readyz check for a storage configuration: the
// database pool when there is one, and nil — always ready — when there is not.
//
// Only the database is checked. It is the one dependency whose loss stops this
// instance from serving anything; a single upstream source being down degrades a
// game's data plane but does not make the instance unfit to route to.
func readinessProbe(store storage) httpapi.ReadinessProbe {
	if store.db == nil {
		return nil
	}
	return store.db.Ping
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

	// The pool is sized from configuration rather than left to the driver's
	// defaults, which are chosen for a general-purpose program. The lifetimes
	// that PoolOptions also carries are left at their defaults here; they are not
	// knobs a deployment has needed to turn.
	db, err := postgres.Open(ctx, cfg.DatabaseURL, postgres.PoolOptions{
		MaxConns:         cfg.Pool.MaxConns,
		MinConns:         cfg.Pool.MinConns,
		ConnectTimeout:   cfg.Pool.ConnectTimeout,
		StatementTimeout: cfg.Pool.StatementTimeout,
	})
	if err != nil {
		return storage{}, err
	}
	// Built before the rest so a bad chain key fails here, with the pool closed,
	// rather than leaving a half-built storage behind.
	auditLogger, err := db.Audit(cfg.AuditKey)
	if err != nil {
		db.Close()
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
		audit:        auditLogger,
		legacy:       db.Tokens(),
		sweep: func(ctx context.Context) (int64, error) {
			// The dated tables (codes, tokens, pending requests) and the sessions
			// are separate sweeps; sessions also collect their orphan index rows.
			expired, err := db.SweepExpired(ctx)
			if err != nil {
				return expired, err
			}
			sessionRows, err := sessions.SweepExpired(ctx)
			return expired + sessionRows, err
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

// sweepLoop periodically removes expired rows -- dated tokens, codes and pending
// requests, and sessions. A lookup already refuses an expired row; this covers
// the ones nobody comes back to, whose row would otherwise live on forever.
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
				slog.Warn("expiry sweep failed", "err", err)
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
	// SetAuthTime records the session's real authentication time on a pending
	// request, so the ID token does not report the consent decision as auth_time.
	SetAuthTime(ctx context.Context, id string, at time.Time) error
	Grants(ctx context.Context, subject string) ([]oauth.Grant, error)
	RevokeGrant(ctx context.Context, subject, clientID string) error
	RevokeTokens(ctx context.Context, f oauth.TokenFilter) (int, error)
	PurgeSubject(ctx context.Context, subject string) (int, error)
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
	if err := oidcstore.ValidateSigner(signer); err != nil {
		return nil, nil, err
	}
	// Declared before the login hook so the hook can record the session's real
	// authentication time on the pending request.
	var oidcStore oidcBackend
	login := func(ctx context.Context, id string) string {
		// Bind the request to the browser that started it, so a relayed id cannot
		// be approved elsewhere. GetClientByClientID hands us the request context,
		// which is where the session lives.
		sessions.Bind(ctx, "authz", id)
		if at, ok := sessions.AuthenticatedAt(ctx); ok {
			if err := oidcStore.SetAuthTime(ctx, id, at); err != nil {
				slog.Warn("could not record auth_time on the authorization request", "err", err)
			}
		}
		return webui.BasePath + "/consent?id=" + url.QueryEscape(id)
	}

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
		Issuer:      cfg.Issuer,
		Storage:     oidcStore,
		CryptoKey:   tokenKey,
		CryptoKeyID: "re0auth",
		Scopes:      scopes,
		// Resource servers allowed to see tokens issued to other clients. Empty
		// means a client may introspect only its own tokens.
		IntrospectionClients: cfg.IntrospectionClients,
		// Taken from the issuer's scheme, which is what the OP's question is
		// actually about: "may this issuer be plain http". It used to be derived
		// from cookie_secure — a different setting, about a different thing — and
		// the two could disagree with nothing looking at both: an https issuer
		// with cookie_secure = false made the OP accept an http issuer, which is
		// the one outcome that check exists to prevent. The OP now answers only to
		// the issuer URL it was given.
		AllowInsecure:    strings.HasPrefix(cfg.Issuer, "http://"),
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

// erasureBindings adapts the federation service to the lifecycle package's
// binding port. It is a second adapter rather than a reuse of bindingRevoker
// because that one answers in the operator plane's richer outcome, and the
// erasure path only reports a count. Keeping them separate means neither
// package's reporting needs shape the other's.
type erasureBindings struct{ fed federation.Service }

func (e erasureBindings) RevokeUserBindings(ctx context.Context, user account.UserID) (lifecycle.BindingOutcome, error) {
	summary, err := e.fed.RevokeUserBindings(ctx, user)
	return lifecycle.BindingOutcome{
		Total:   summary.Total,
		Revoked: summary.Revoked,
		Failed:  summary.Failed,
	}, err
}

// pseudonymStore narrows the audit sink to its erasure capability.
//
// The narrowing has to be dynamic because the two sinks differ in kind: the
// durable one pseudonymises subjects and holds the keys, while the in-memory one
// is a bounded ring buffer that keeps none and stores subjects as given. Asking
// for the capability rather than branching on storage mode keeps that difference
// where it belongs — in the sink — and returns nil, honestly, for the one that
// cannot do it.
func pseudonymStore(l audit.Logger) lifecycle.PseudonymDestroyer {
	if d, ok := l.(lifecycle.PseudonymDestroyer); ok {
		return d
	}
	return nil
}

// auditReadSide returns the sink's read capability, or nil when the deployment
// must not offer it.
//
// Two things gate it, and both are refusals rather than branches on storage mode:
// the sink must be able to answer (only the durable chain can — a "verify" over
// the in-memory ring buffer would report on a guarantee it does not have), and
// the deployment must name an operator. The log describes every account, so its
// read side is admin-only; the same allowlist that mounts the operator plane is
// what mounts this. A durable deployment with no admins is legitimate and simply
// gets no read API — httpapi.New would reject the alternative, taking the whole
// server down over an endpoint nobody is allowed to call.
func auditReadSide(admins []string, l audit.Logger) httpapi.AuditReader {
	if len(admins) == 0 {
		return nil
	}
	if r, ok := l.(httpapi.AuditReader); ok {
		return r
	}
	return nil
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
