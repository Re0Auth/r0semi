package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/vault"
)

// Vault implements vault.Repo on Postgres.
//
// It stores exactly what it is given and nothing derived: the row is opaque
// crypto material plus the identity and the non-secret metadata. Decryption
// happens in the vault, never here, and is impossible without the KEK.
type Vault struct{ pool *pgxpool.Pool }

const vaultCols = `subject, provider, version, wrapped_dek, kek_id, nonce, ciphertext, meta, created_at, updated_at`

// vaultRow is one vault_credentials row, named so scanning matches by column
// rather than by position.
type vaultRow struct {
	Subject    string            `db:"subject"`
	Provider   string            `db:"provider"`
	Version    int16             `db:"version"`
	WrappedDEK []byte            `db:"wrapped_dek"`
	KEKID      string            `db:"kek_id"`
	Nonce      []byte            `db:"nonce"`
	Ciphertext []byte            `db:"ciphertext"`
	Meta       map[string]string `db:"meta"`
	CreatedAt  time.Time         `db:"created_at"`
	UpdatedAt  time.Time         `db:"updated_at"`
}

// record converts the stored row. The only version this code writes is vault's
// recordVersion (1), which is a byte; the int16 column is headroom, so narrowing
// it back to the byte the format uses cannot truncate a value this code produces
// (G115).
func (r vaultRow) record() vault.Record {
	return vault.Record{
		Identity:   vault.Identity{Subject: r.Subject, Provider: r.Provider},
		Version:    byte(r.Version), //nolint:gosec // G115: the column holds vault's recordVersion byte
		WrappedDEK: r.WrappedDEK,
		KEKID:      r.KEKID,
		Nonce:      r.Nonce,
		Ciphertext: r.Ciphertext,
		Meta:       r.Meta,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
}

// List implements vault.Repo.
//
// One scan of the table, ordered so the same rotation run twice agrees with
// itself. It exists for key rotation; nothing on the read path enumerates
// credentials, and the set of identities is itself personal data. Rotation prefers
// ListPage, which is the same order without the whole vault in memory.
func (s *Vault) List(ctx context.Context) ([]vault.Record, error) {
	return s.queryRecords(ctx, `SELECT `+vaultCols+` FROM vault_credentials ORDER BY subject, provider`)
}

// ListPage implements vault.RecordPager: the same order as List, one page at a
// time, keyed on the primary key. Rotation walks the vault with it rather than
// holding every credential in memory.
func (s *Vault) ListPage(ctx context.Context, afterSubject, afterProvider string, limit int) ([]vault.Record, error) {
	if limit <= 0 {
		limit = 1
	}
	if afterSubject == "" && afterProvider == "" {
		return s.queryRecords(ctx,
			`SELECT `+vaultCols+` FROM vault_credentials ORDER BY subject, provider LIMIT $1`, limit)
	}
	return s.queryRecords(ctx,
		`SELECT `+vaultCols+` FROM vault_credentials
		  WHERE (subject, provider) > ($1, $2)
		  ORDER BY subject, provider
		  LIMIT $3`, afterSubject, afterProvider, limit)
}

func (s *Vault) queryRecords(ctx context.Context, query string, args ...any) ([]vault.Record, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[vaultRow])
	if err != nil {
		return nil, err
	}

	out := make([]vault.Record, 0, len(scanned))
	for _, r := range scanned {
		out = append(out, r.record())
	}
	return out, nil
}

// Put implements vault.Repo. An existing record is replaced wholesale, so the
// repository never invents timestamps or merges metadata on its own.
func (s *Vault) Put(ctx context.Context, rec vault.Record) error {
	meta := rec.Meta
	if meta == nil {
		// jsonb accepts JSON null, but an object is what a reader expects.
		meta = map[string]string{}
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO vault_credentials (`+vaultCols+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (subject, provider) DO UPDATE SET
			version     = EXCLUDED.version,
			wrapped_dek = EXCLUDED.wrapped_dek,
			kek_id      = EXCLUDED.kek_id,
			nonce       = EXCLUDED.nonce,
			ciphertext  = EXCLUDED.ciphertext,
			meta        = EXCLUDED.meta,
			created_at  = EXCLUDED.created_at,
			updated_at  = EXCLUDED.updated_at`,
		rec.Identity.Subject, rec.Identity.Provider, int16(rec.Version),
		rec.WrappedDEK, rec.KEKID, rec.Nonce, rec.Ciphertext, meta,
		rec.CreatedAt, rec.UpdatedAt)
	return err
}

// RewrapIfUnchanged implements vault.Repo.
//
// One statement, and the comparison is part of it: `WHERE wrapped_dek = $3` makes
// this a compare-and-swap inside Postgres rather than a read followed by a write
// with a window between them. The columns a rotation must not touch — nonce,
// ciphertext, meta, created_at — are not in the SET list at all, so a credential
// enrolled by another process while a rotation page is being processed cannot be
// rolled back to the stale record the rotation read.
//
// Zero rows affected means the row changed under us (or is gone). That is a
// refusal, not an error: the caller reports the record as not re-wrapped, and a
// re-run resolves it.
func (s *Vault) RewrapIfUnchanged(ctx context.Context, id vault.Identity, expect []byte, next vault.Envelope) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE vault_credentials
		   SET wrapped_dek = $4, kek_id = $5, updated_at = $6
		 WHERE subject = $1 AND provider = $2 AND wrapped_dek = $3`,
		id.Subject, id.Provider, expect, next.WrappedDEK, next.KEKID, next.UpdatedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Get implements vault.Repo.
func (s *Vault) Get(ctx context.Context, id vault.Identity) (vault.Record, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+vaultCols+` FROM vault_credentials WHERE subject = $1 AND provider = $2`,
		id.Subject, id.Provider)
	if err != nil {
		return vault.Record{}, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[vaultRow])
	if noRows(err) {
		return vault.Record{}, vault.ErrNotFound
	}
	if err != nil {
		return vault.Record{}, err
	}
	return row.record(), nil
}

// Delete implements vault.Repo. Deleting an absent credential is not an error:
// crypto-shredding is idempotent in its goal.
func (s *Vault) Delete(ctx context.Context, id vault.Identity) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM vault_credentials WHERE subject = $1 AND provider = $2`,
		id.Subject, id.Provider)
	return err
}

// DeleteSubject implements vault.Repo: every credential one subject holds, gone.
//
// One statement, because subject is the leading column of the primary key, so
// this is an index range rather than a scan. RETURNING 1 makes the count exact
// without a second round trip, and the count is worth having: it is the number
// reported back to the person who asked to be erased.
//
// It removes whole rows, which is what actually erases the account's data. The
// wrapped DEK goes with the row (so the ciphertext is unrecoverable), and so do
// the plaintext Identity and Meta columns — which a "null the DEK" approach would
// leave behind.
func (s *Vault) DeleteSubject(ctx context.Context, subject string) (int, error) {
	rows, err := s.pool.Query(ctx,
		`DELETE FROM vault_credentials WHERE subject = $1 RETURNING 1`, subject)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}
