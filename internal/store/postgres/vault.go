package postgres

import (
	"context"

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

// List implements vault.Repo.
//
// One scan of the table, ordered so the same rotation run twice agrees with
// itself. It exists for key rotation; nothing on the read path enumerates
// credentials, and the set of identities is itself personal data.
func (s *Vault) List(ctx context.Context) ([]vault.Record, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+vaultCols+` FROM vault_credentials ORDER BY subject, provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]vault.Record, 0, 8)
	for rows.Next() {
		var (
			rec     vault.Record
			version int16
		)
		if err := rows.Scan(&rec.Identity.Subject, &rec.Identity.Provider, &version, &rec.WrappedDEK,
			&rec.KEKID, &rec.Nonce, &rec.Ciphertext, &rec.Meta, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		rec.Version = byte(version)
		out = append(out, rec)
	}
	return out, rows.Err()
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

// Get implements vault.Repo.
func (s *Vault) Get(ctx context.Context, id vault.Identity) (vault.Record, error) {
	var (
		rec     vault.Record
		version int16
	)
	err := s.pool.QueryRow(ctx,
		`SELECT `+vaultCols+` FROM vault_credentials WHERE subject = $1 AND provider = $2`,
		id.Subject, id.Provider).
		Scan(&rec.Identity.Subject, &rec.Identity.Provider, &version, &rec.WrappedDEK,
			&rec.KEKID, &rec.Nonce, &rec.Ciphertext, &rec.Meta, &rec.CreatedAt, &rec.UpdatedAt)
	if noRows(err) {
		return vault.Record{}, vault.ErrNotFound
	}
	if err != nil {
		return vault.Record{}, err
	}
	rec.Version = byte(version)
	return rec, nil
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
