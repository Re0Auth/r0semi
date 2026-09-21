// Command re0auth is the composition root: it reads configuration from the
// environment, wires every component, and serves the two HTTP planes.
//
// It exists so the storage adapters have a real caller. Ports that are still
// in-process are announced loudly at startup, because "which parts are durable"
// must never be a guess.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("re0auth: config: %v", err)
	}
	ctx := context.Background()
	logger := audit.NewMemoryLogger()

	accounts, tokens, devices, clients, closeStorage, err := openStorage(ctx, cfg)
	if err != nil {
		log.Fatalf("re0auth: storage: %v", err)
	}
	defer closeStorage()

	vaultService, err := openVault(cfg, logger)
	if err != nil {
		log.Fatalf("re0auth: vault: %v", err)
	}
	log.Print("WARNING: the vault's credential store is still in-memory; upstream credentials do not survive a restart")

	if err := seedClient(ctx, clients, cfg); err != nil {
		log.Fatalf("re0auth: seed client: %v", err)
	}

	as, err := oauth.NewService(clients, tokens, logger, oauth.Config{
		Issuer:  cfg.Issuer,
		Scopes:  oauth.DefaultRegistry(),
		Devices: devices,
	})
	if err != nil {
		log.Fatalf("re0auth: authorization server: %v", err)
	}

	idpRegistry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: cfg.Issuer,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
		Credentials:  cfg.idpCredentials,
	})
	if err != nil {
		log.Fatalf("re0auth: idp: %v", err)
	}
	if len(cfg.idpCredentials) == 0 {
		log.Print("WARNING: no identity provider is configured; nobody can sign in")
	}

	sessions := auth.NewManager(auth.Options{Secure: cfg.CookieSecure})
	authHandler, err := auth.NewHandler(sessions, idpRegistry, accounts)
	if err != nil {
		log.Fatalf("re0auth: auth: %v", err)
	}

	// Still in-process: the authorization-interaction store is the next port.
	authzService, err := authz.NewService(as, authz.NewMemoryStore(), authz.Config{})
	if err != nil {
		log.Fatalf("re0auth: authz: %v", err)
	}
	log.Print("WARNING: pending authorization requests are in-memory")

	registry, err := federation.NewRegistry(cfg.sources...)
	if err != nil {
		log.Fatalf("re0auth: sources: %v", err)
	}
	federationService, err := federation.NewService(federation.Config{
		Registry: registry,
		Bindings: federation.NewMemoryBindingStore(),
		Vault:    vaultService,
		Doer:     &http.Client{Timeout: 20 * time.Second},
		BaseURL:  cfg.Issuer,
	})
	if err != nil {
		log.Fatalf("re0auth: federation: %v", err)
	}
	log.Print("WARNING: bindings and bind flows are in-memory")

	api, err := httpapi.New(httpapi.Config{
		Issuer:     cfg.Issuer,
		AS:         as,
		Sessions:   sessions,
		Accounts:   accounts,
		Auth:       authHandler,
		Authz:      authzService,
		Federation: federationService,
		// A coarse per-address cap. Per-client limits are a later refinement.
		Limiter: ratelimit.New(50, 100),
	})
	if err != nil {
		log.Fatalf("re0auth: http: %v", err)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("re0auth listening on %s (issuer %s)", cfg.Addr, cfg.Issuer)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("re0auth: serve: %v", err)
	}
}

// openStorage picks the account and OAuth backends. Setting DATABASE_URL turns on
// Postgres and applies migrations; leaving it unset keeps everything in memory.
func openStorage(ctx context.Context, cfg config) (
	account.Store, oauth.Store, oauth.DeviceStore, oauth.ClientRegistry, func(), error,
) {
	if cfg.DatabaseURL == "" {
		log.Print("WARNING: DATABASE_URL is not set; using in-memory stores (nothing survives a restart)")
		return account.NewMemoryStore(), oauth.NewMemoryStore(), oauth.NewMemoryDeviceStore(),
			oauth.NewMemoryClientRegistry(), func() {}, nil
	}
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	log.Print("storage: postgres (schema migrated)")
	return db.Accounts(), db.Tokens(), db.Devices(), db.Clients(), db.Close, nil
}

func openVault(cfg config, logger audit.Logger) (vault.Service, error) {
	kek, err := decodeKEK(cfg.KEK)
	if err != nil {
		return nil, err
	}
	// A KMS/HSM wrapper replaces this in production; the KEK is an external
	// trust boundary, which is why the wrapper is injected rather than derived.
	wrapper, err := vault.NewLocalKeyWrapper("env", kek)
	if err != nil {
		return nil, err
	}
	return vault.NewService(vault.NewMemoryRepo(), wrapper, logger)
}

// seedClient registers the first-party downstream client if it is not already
// present. Re-running the process must not fail, so an existing registration is
// left untouched rather than overwritten.
func seedClient(ctx context.Context, clients oauth.ClientRegistry, cfg config) error {
	_, err := clients.Get(ctx, cfg.clientID)
	switch {
	case err == nil:
		log.Printf("client %q is already registered", cfg.clientID)
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
	log.Printf("registered downstream client %q (%s)", client.ID, client.Type)
	return nil
}
