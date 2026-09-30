// Package postgres holds the Postgres-backed implementations of the storage
// ports (account.Store, oauth.Store, oauth.DeviceStore, oauth.ClientRegistry).
//
// They live here rather than next to their interfaces on purpose: the public
// libraries (oauth, vault) must not depend on a database driver.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver goose runs on
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockKey serializes migrations across instances. Any constant works;
// this one is arbitrary but stable.
const migrationLockKey int64 = 0x7230636d6967

// migrationLockPeriod and migrationLockAttempts bound how long a starting
// instance waits for another instance's migration before giving up: goose's
// session locker probes pg_try_advisory_lock every 5 seconds, this many times,
// so five minutes. Waiting for a peer is legitimate and can outlast any request;
// waiting forever is a startup that never answers, which is what the blocking
// pg_advisory_lock this used to issue did.
const (
	migrationLockPeriod   = 5
	migrationLockAttempts = 60
)

// DB owns the connection pool and hands out the port implementations.
type DB struct {
	pool *pgxpool.Pool
	// dsn is kept so goose can open its own database/sql handle for migrations.
	dsn string
	// connectTimeout bounds establishing the migration connection, which is
	// deliberately not taken from the pool. See Migrate.
	connectTimeout time.Duration
	// now is the clock every store handed out here writes its deadlines with — and
	// judges them with, so a value is never compared against a different clock
	// than the one that produced it. It is injectable (WithClock) because that
	// policy is otherwise unassertable: a test cannot skew the database's clock,
	// but it can skew this one and watch a deadline it wrote still be honoured.
	now func() time.Time
	// auditObserver times one chained audit write; see WithAuditObserver.
	auditObserver func(time.Duration)
	// closersMu guards closers, the audit append writers this handle handed out.
	// Close stops them before the pool goes away, so a row that was already
	// accepted for writing is still written.
	closersMu sync.Mutex
	closers   []func()
}

// Option customises a DB at construction.
type Option func(*DB)

// WithClock replaces the store clock. Default: time.Now.
//
// Callers that do not set it get the process clock, which is the honest default:
// the alternative — judging Go-written deadlines with the database's now() — is
// exactly the two-clock mix this exists to remove. See OIDCStore.now.
func WithClock(now func() time.Time) Option {
	return func(db *DB) {
		if now != nil {
			db.now = now
		}
	}
}

// WithAuditObserver receives the duration of every chained audit write, the wait
// for the chain-head lock included.
//
// The chain serialises every writer on one row by design, and the audit write sits
// on the data plane's critical path (a vault use is audited before the secret is
// handed over). Whether that is affordable is a question only measurement answers,
// so the store reports the number and the composition root decides what to do with
// it — the metrics package, in production.
func WithAuditObserver(observe func(time.Duration)) Option {
	return func(db *DB) {
		if observe != nil {
			db.auditObserver = observe
		}
	}
}

// PoolOptions bounds the connection pool and the statements that run on it.
//
// They are options rather than constants because the right numbers are a
// deployment fact, not a code fact: pgxpool keeps its semaphore per process, so
// "how many connections may this instance hold" has to be answered together with
// "how many instances are there", and the answer must leave room under Postgres's
// max_connections for migrations and for a human with psql. A pool that is too
// large does not fail loudly; it makes the database refuse a connection to
// something that needs one.
type PoolOptions struct {
	// MaxConns caps connections held by this process.
	MaxConns int32
	// MinConns is how many connections are kept warm. Zero lets the pool shrink
	// to nothing, so the request after an idle period pays a full connect.
	MinConns int32
	// ConnectTimeout bounds establishing a single connection. It is what turns an
	// unreachable host into a startup failure instead of a hang.
	ConnectTimeout time.Duration
	// StatementTimeout is applied as the session's statement_timeout, so no query
	// outlives the request that issued it. A non-positive value leaves the
	// server's setting alone (which is the default: no timeout).
	StatementTimeout time.Duration
	// MaxConnLifetime retires a connection after this long, so a DNS change or a
	// failover is picked up without a restart.
	MaxConnLifetime time.Duration
	// MaxConnIdleTime releases a connection that has gone unused, returning its
	// backend to the server.
	MaxConnIdleTime time.Duration
	// HealthCheckPeriod is how often an idle connection is checked, so one that
	// died in the interim is not handed to a caller.
	HealthCheckPeriod time.Duration
}

// DefaultPoolOptions is the configuration a deployment gets when it tunes
// nothing. Every value is overridable; see cmd/re0auth/config.go for the keys.
func DefaultPoolOptions() PoolOptions {
	return PoolOptions{
		MaxConns:          16,
		MinConns:          2,
		ConnectTimeout:    5 * time.Second,
		StatementTimeout:  30 * time.Second,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
	}
}

// normalized replaces a value that cannot mean anything with its default, so the
// zero PoolOptions is a usable configuration rather than a silently unbounded
// one.
//
// Two fields are passed through untouched, because for them zero is a choice
// rather than an omission: MinConns = 0 is "keep no connection warm", and a
// non-positive StatementTimeout is "leave the server's setting alone". Both have
// non-zero defaults, so a caller who wants the house values names them
// (DefaultPoolOptions) instead of leaving the fields out.
func (o PoolOptions) normalized() PoolOptions {
	d := DefaultPoolOptions()
	if o.MaxConns <= 0 {
		o.MaxConns = d.MaxConns
	}
	if o.MinConns < 0 {
		o.MinConns = 0
	}
	if o.MinConns > o.MaxConns {
		o.MinConns = o.MaxConns
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = d.ConnectTimeout
	}
	if o.MaxConnLifetime <= 0 {
		o.MaxConnLifetime = d.MaxConnLifetime
	}
	if o.MaxConnIdleTime <= 0 {
		o.MaxConnIdleTime = d.MaxConnIdleTime
	}
	if o.HealthCheckPeriod <= 0 {
		o.HealthCheckPeriod = d.HealthCheckPeriod
	}
	return o
}

// Open connects, verifies the connection, and applies pending migrations. It is
// the only constructor: there is no supported way to use the stores against an
// unmigrated database.
//
// opts is parsed rather than passed to pgxpool.New, because the defaults pgx
// would otherwise apply are for a general-purpose program, not for one whose
// every query is on a request's critical path. See PoolOptions for what each
// bound buys.
//
// options customise the handle itself rather than the pool; today that means the
// store clock (WithClock), which tests use to pin the single-clock policy.
func Open(ctx context.Context, dsn string, opts PoolOptions, options ...Option) (*DB, error) {
	opts = opts.normalized()
	cfg, err := poolConfig(dsn, opts)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	// The initial reachability check is bounded by the same connect budget, so a
	// host that accepts nothing answers at startup rather than holding the
	// process open. The pool itself is lazy; without this, "connected" would only
	// be discovered on the first request.
	pingCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	db := &DB{pool: pool, dsn: dsn, connectTimeout: opts.ConnectTimeout, now: time.Now}
	for _, opt := range options {
		if opt != nil {
			opt(db)
		}
	}
	if err := db.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

// poolConfig turns a DSN and the pool options into the driver's configuration.
//
// It is a separate function so that "did these bounds actually reach the driver"
// can be asserted without a database. Every one of these settings is invisible
// when it is wrong — a missing statement timeout looks exactly like a query that
// happened to be fast — so the mapping is pinned by a test rather than by
// reading it.
//
// opts is expected already normalized; a zero value here would leave MaxConns at
// the driver's default rather than this package's.
func poolConfig(dsn string, opts PoolOptions) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", redactDSNParseError(err))
	}
	cfg.MaxConns = opts.MaxConns
	cfg.MinConns = opts.MinConns
	cfg.MaxConnLifetime = opts.MaxConnLifetime
	cfg.MaxConnIdleTime = opts.MaxConnIdleTime
	cfg.HealthCheckPeriod = opts.HealthCheckPeriod
	cfg.ConnConfig.ConnectTimeout = opts.ConnectTimeout
	if opts.StatementTimeout > 0 {
		// Sent in the startup packet, so it is a property of every connection the
		// pool opens rather than something each caller has to remember to set. A
		// statement that outlives its request holds a backend, and possibly a lock,
		// while the caller has already given up — which is how one slow query
		// becomes an outage.
		if cfg.ConnConfig.RuntimeParams == nil {
			cfg.ConnConfig.RuntimeParams = make(map[string]string, 1)
		}
		cfg.ConnConfig.RuntimeParams["statement_timeout"] =
			strconv.FormatInt(opts.StatementTimeout.Milliseconds(), 10)
	}
	return cfg, nil
}

// redactDSNParseError removes the connection string from the driver's parse error.
//
// pgconn quotes the input it could not parse and redacts it only in the positions
// its own heuristics recognise ("necessarily best effort", pgconn/errors.go). A
// userinfo with no '@', or a keyword/value pair missing its '=', comes back
// verbatim — password included — and postgres.Open hands that to the caller, which
// logs it at stage=storage (Z19V-1). Replacing the exact string the driver
// reported keeps the reason ("invalid port") and drops the input: the replacement
// is scoped to the error text, so a DSN that parses is untouched.
func redactDSNParseError(err error) error {
	var pe *pgconn.ParseConfigError
	if !errors.As(err, &pe) || pe.ConnString == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), pe.ConnString, "<redacted>"))
}

// Close releases the pool. Append writers handed out by Audit are stopped first,
// and stopped synchronously: a queued audit row is a caller waiting for its write
// to be confirmed, so closing the pool underneath it would turn a graceful stop
// into a failed record.
func (db *DB) Close() {
	db.closersMu.Lock()
	closers := db.closers
	db.closers = nil
	db.closersMu.Unlock()
	for _, close := range closers {
		close()
	}
	db.pool.Close()
}

// Ping reports whether the database is reachable. It is the readiness probe: a
// pool that cannot acquire a connection means this instance cannot serve, and an
// orchestrator should stop routing to it until it can.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// PoolStats returns the pool's live statistics. The metrics package exports them
// under re0auth_db_pool_*; *pgxpool.Stat satisfies its PoolStats interface
// structurally, so the composition root wires the two together and neither
// package has to name the other's type.
func (db *DB) PoolStats() *pgxpool.Stat { return db.pool.Stat() }

// Accounts returns the account store.
func (db *DB) Accounts() *Accounts { return &Accounts{pool: db.pool} }

// Tokens returns the authorization-code and token store.
func (db *DB) Tokens() *Tokens { return &Tokens{pool: db.pool, now: db.now} }

// Devices returns the device-authorization store.
func (db *DB) Devices() *Devices { return &Devices{pool: db.pool} }

// Vault returns the credential-record repository. Decryption lives in the vault
// package; this only stores opaque crypto material.
func (db *DB) Vault() *Vault { return &Vault{pool: db.pool} }

// Bindings returns the source-binding store. It holds metadata only.
func (db *DB) Bindings() *Bindings { return &Bindings{pool: db.pool} }

// BindFlows returns the pending bind-flow store.
func (db *DB) BindFlows() *BindFlows { return &BindFlows{pool: db.pool} }

// Sessions returns the HTTP session store.
func (db *DB) Sessions() *Sessions { return &Sessions{pool: db.pool, now: db.now} }

// Clients returns the downstream-client registry.
func (db *DB) Clients() *Clients { return &Clients{pool: db.pool} }

// Audit returns the durable audit-log sink. The key authenticates the record
// chain; it is required, and must be 32 bytes, because a chain signed with no key
// would look like tamper-evidence and not be.
func (db *DB) Audit(key []byte) (*AuditLogger, error) {
	logger, err := newAuditLogger(db.pool, key)
	if err != nil {
		return nil, err
	}
	logger.observe = db.auditObserver
	db.closersMu.Lock()
	db.closers = append(db.closers, logger.Close)
	db.closersMu.Unlock()
	return logger, nil
}

// withMigrationLock runs fn against a goose provider under goose's Postgres
// session locker, so two instances acting at once cannot race.
//
// The lock is goose's rather than the hand-written blocking
// `pg_advisory_lock` this used to issue: goose probes with
// `pg_try_advisory_lock` in a bounded retry loop (migrationLockAttempts ×
// migrationLockPeriod) and releases the session-level lock when the connection
// ends, so a peer that never finishes becomes a startup failure instead of a
// startup that hangs forever.
//
// It is held around fn rather than handed to the provider through
// goose.WithSessionLocker, because fn also adopts a pre-goose
// `schema_migrations` table: that read-modify-write has to sit under the same
// lock as the migration that follows it, and provider.Up/Down would cover only
// the latter.
//
// The lock lives on a connection of its own rather than one borrowed from the
// pool, for two reasons:
//
//   - waiting for another instance to finish migrating is legitimate and can
//     take longer than any request should, so it must not inherit the pool's
//     serving-side statement_timeout;
//   - pgxpool does not reset session state when a connection is released, so a
//     serving connection must not be used to hold a migration lock. goose runs
//     its migrations on the handle's other connections, and the lock connection
//     is closed when the migration finishes.
//
// goose itself runs on a database/sql handle (the pgx stdlib driver), because
// that is the seam it exposes. Both directions of migration share this setup, so
// up and down cannot drift apart.
func withMigrationLock(ctx context.Context, dsn string, connectTimeout time.Duration,
	fn func(context.Context, *sql.DB, *goose.Provider) error) error {
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("postgres: migrate: open database/sql handle: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockID(migrationLockKey),
		lock.WithLockTimeout(migrationLockPeriod, migrationLockAttempts),
	)
	if err != nil {
		return fmt.Errorf("postgres: migrate: locker: %w", err)
	}

	// Bound acquiring the lock's connection by the same connect budget as any
	// other startup dial, so an unreachable host fails rather than holds.
	connCtx := ctx
	cancel := func() {}
	if connectTimeout > 0 {
		connCtx, cancel = context.WithTimeout(ctx, connectTimeout)
	}
	conn, err := sqlDB.Conn(connCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("postgres: migrate: connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := locker.SessionLock(ctx, conn); err != nil {
		return fmt.Errorf("postgres: migrate: lock: %w", err)
	}
	defer func() {
		// Detached: unlocking must happen even if ctx was cancelled. If it still
		// fails, closing the connection releases the session-level lock.
		_ = locker.SessionUnlock(context.WithoutCancel(ctx), conn)
	}()

	dir, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: migrate: migrations dir: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, dir)
	if err != nil {
		return fmt.Errorf("postgres: migrate: provider: %w", err)
	}
	return fn(ctx, sqlDB, provider)
}

// Migrate applies every pending goose migration. It also adopts a pre-goose
// `schema_migrations` table when it finds one: its rows are copied into goose's
// version table (preserving the applied_at timestamps), then it is dropped. A
// database that has never run a migration simply gets a fresh goose_db_version.
func (db *DB) Migrate(ctx context.Context) error {
	return withMigrationLock(ctx, db.dsn, db.connectTimeout,
		func(ctx context.Context, sqlDB *sql.DB, provider *goose.Provider) error {
			if err := adoptLegacyMigrations(ctx, sqlDB, provider); err != nil {
				return err
			}
			if _, err := provider.Up(ctx); err != nil {
				return fmt.Errorf("postgres: migrate: up: %w", err)
			}
			return nil
		})
}

// MigrateDown rolls back the most recently applied migration. It is a package
// function rather than a *DB method because the caller that needs it must NOT have
// opened the pool first: Open migrates up, so a rollback issued after it would be
// undone by the very act of opening the database.
//
// Down migrations exist for the operator who has to undo one step, not as the
// rollback story. The story is restore-from-backup (see docs/migration-decision.md,
// ADR-0008): a down that drops a column loses the data in it, and a deploy that
// went wrong is usually better served by the last-known-good dump.
func MigrateDown(ctx context.Context, dsn string, opts PoolOptions) error {
	return withMigrationLock(ctx, dsn, opts.normalized().ConnectTimeout,
		func(ctx context.Context, sqlDB *sql.DB, provider *goose.Provider) error {
			if err := refuseAuditChainRollback(ctx, sqlDB, provider); err != nil {
				return err
			}
			if _, err := provider.Down(ctx); err != nil {
				return fmt.Errorf("postgres: migrate: down: %w", err)
			}
			return nil
		})
}

// These are the versions whose Down sections are no-ops because rolling them
// back destroys tamper-evidence rather than undoing a schema change. They are
// named constants so refuseAuditChainRollback and its guard test cannot drift
// from one another on the numbers.
const (
	migrationAuditChain      = 13
	migrationAuditPseudonyms = 14
)

// refuseAuditChainRollback stops `-migrate-down` from running 0013's or 0014's
// step while the audit chain holds chained rows.
//
// Both Down sections are empty, so this guard is not what prevents the damage;
// it is what turns a silent, unrecoverable loss into a refusal an operator can
// act on. 0013 used to drop prev_hash/row_hash/signature and re-seed the chain
// head to genesis in Up, which made every historical row read back as Legacy
// while Verify still returned OK=true — a destroyed audit chain that reports
// healthy. 0014 used to drop audit_subject_keys, the only copy of every
// per-subject pseudonym key. Neither is reversible by re-applying Up, so the
// rollback story is restore-from-backup (ADR-0008 §5).
//
// The refusal only fires for versions 13 and 14 and only when a row with a
// non-NULL row_hash exists: on a fresh or never-chained database there is
// nothing to protect, so the rollback proceeds and `-migrate-down` keeps
// working there. The provider drives the version, not the migration file
// contents, so a future migration stacked on 13 gets its own decision.
func refuseAuditChainRollback(ctx context.Context, sqlDB *sql.DB, provider *goose.Provider) error {
	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return fmt.Errorf("postgres: migrate: down: read version: %w", err)
	}
	if version != migrationAuditChain && version != migrationAuditPseudonyms {
		return nil
	}
	var chained bool
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM audit_events WHERE row_hash IS NOT NULL)`).Scan(&chained); err != nil {
		return fmt.Errorf("postgres: migrate: down: audit chain probe: %w", err)
	}
	if chained {
		return fmt.Errorf("postgres: migrate: down: refusing to roll back migration %d: the audit chain holds chained rows and its rollback is not reversible (ADR-0008); restore the last-known-good backup instead", version)
	}
	return nil
}

// adoptLegacyMigrations copies a pre-goose `schema_migrations` table into
// goose's version table, then removes it. It is idempotent: re-running it after
// a partial adoption inserts nothing that is already present and still drops
// the legacy table.
func adoptLegacyMigrations(ctx context.Context, sqlDB *sql.DB, provider *goose.Provider) error {
	var legacy bool
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&legacy); err != nil {
		return fmt.Errorf("postgres: migrate: detect legacy table: %w", err)
	}
	if !legacy {
		return nil
	}

	// Let goose create its version table (and its zero row) before inserting.
	if _, err := provider.GetDBVersion(ctx); err != nil {
		return fmt.Errorf("postgres: migrate: init version table: %w", err)
	}

	rows, err := sqlDB.QueryContext(ctx, `SELECT version, applied_at FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("postgres: migrate: read legacy rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type legacyRow struct {
		filename  string
		appliedAt time.Time
	}
	var legacyRows []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.filename, &r.appliedAt); err != nil {
			return fmt.Errorf("postgres: migrate: scan legacy row: %w", err)
		}
		legacyRows = append(legacyRows, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: migrate: iterate legacy rows: %w", err)
	}

	for _, r := range legacyRows {
		version, err := goose.NumericComponent(r.filename)
		if err != nil {
			return fmt.Errorf("postgres: migrate: legacy version %q: %w", r.filename, err)
		}
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO goose_db_version (version_id, is_applied, tstamp)
			SELECT $1, true, $2
			WHERE NOT EXISTS (SELECT 1 FROM goose_db_version WHERE version_id = $1)`,
			version, r.appliedAt); err != nil {
			return fmt.Errorf("postgres: migrate: adopt %q: %w", r.filename, err)
		}
	}

	if _, err := sqlDB.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
		return fmt.Errorf("postgres: migrate: drop legacy table: %w", err)
	}
	return nil
}

// isUniqueViolation reports a Postgres unique-constraint error (SQLSTATE 23505),
// which is how the stores enforce the account invariants without a read-then-write
// race.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// noRows reports pgx's "no rows" sentinel.
func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
