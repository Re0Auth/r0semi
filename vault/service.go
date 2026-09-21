package vault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// Service is the credential-vault capability.
//
// It is deliberately the only way to reach a plaintext secret: Use hands the
// plaintext to a callback and zeroizes it afterwards (invariant I2), so
// "acquire scope" is a language-level guarantee rather than a convention.
type Service interface {
	// Enroll stores, or replaces, the secret for id.
	Enroll(ctx context.Context, id Identity, secret []byte, meta map[string]string) error

	// Use decrypts the secret for id and passes it to fn. The plaintext is
	// zeroized when fn returns, whatever fn returns.
	Use(ctx context.Context, id Identity, fn func(secret []byte) error) error

	// Revoke crypto-shreds the credential for id.
	Revoke(ctx context.Context, id Identity) error

	// Exists reports whether a credential is stored for id.
	Exists(ctx context.Context, id Identity) (bool, error)
}

type service struct {
	repo  Repo
	kek   KeyWrapper
	audit audit.Logger
}

// NewService wires a vault service. All arguments are required.
func NewService(repo Repo, kek KeyWrapper, logger audit.Logger) (Service, error) {
	if repo == nil {
		return nil, errors.New("vault: Repo is required")
	}
	if kek == nil {
		return nil, errors.New("vault: KeyWrapper is required")
	}
	if logger == nil {
		return nil, errors.New("vault: audit.Logger is required")
	}
	return &service{repo: repo, kek: kek, audit: logger}, nil
}

func (s *service) Enroll(ctx context.Context, id Identity, secret []byte, meta map[string]string) error {
	if err := id.validate(); err != nil {
		return err
	}
	aad := bindingAAD(recordVersion, id.Subject, id.Provider)

	dek := make([]byte, dekSize)
	if err := fillRandom(dek); err != nil {
		return err
	}
	defer zeroize(dek)

	wrapped, err := s.kek.Wrap(ctx, dek, aad)
	if err != nil {
		return fmt.Errorf("vault: wrap DEK: %w", err)
	}
	nonce, ct, err := sealSecret(dek, secret, aad)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if err := s.repo.Put(ctx, Record{
		Identity:   id,
		Version:    recordVersion,
		WrappedDEK: wrapped,
		KEKID:      s.kek.KeyID(),
		Nonce:      nonce,
		Ciphertext: ct,
		Meta:       cloneMeta(meta),
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		return fmt.Errorf("vault: persist credential: %w", err)
	}
	return s.record(ctx, audit.Event{
		Action:   "vault.enroll",
		Subject:  id.Subject,
		Provider: id.Provider,
		Outcome:  audit.OutcomeOK,
	})
}

func (s *service) Use(ctx context.Context, id Identity, fn func(secret []byte) error) error {
	if err := id.validate(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("vault: Use requires a callback")
	}

	rec, err := s.repo.Get(ctx, id)
	if err != nil {
		_ = s.record(ctx, audit.Event{
			Action:   "vault.use",
			Subject:  id.Subject,
			Provider: id.Provider,
			Outcome:  audit.OutcomeDenied,
		})
		return err
	}

	aad := bindingAAD(rec.Version, id.Subject, id.Provider)
	dek, err := s.kek.Unwrap(ctx, rec.WrappedDEK, aad)
	if err != nil {
		_ = s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		return fmt.Errorf("vault: unwrap DEK: %w", err)
	}
	defer zeroize(dek)

	plain, err := openSecret(dek, rec.Nonce, rec.Ciphertext, aad)
	if err != nil {
		_ = s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		return err
	}
	defer zeroize(plain)

	// I3: the access record is persisted before the secret is used. If the
	// audit log is unavailable we fail closed rather than proceed unaudited.
	if err := s.record(ctx, audit.Event{
		Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeOK,
	}); err != nil {
		return err
	}

	return fn(plain)
}

func (s *service) Revoke(ctx context.Context, id Identity) error {
	if err := id.validate(); err != nil {
		return err
	}
	// Removing the wrapped DEK crypto-shreds the credential: the ciphertext,
	// even if it lingers, is no longer decryptable.
	if err := s.repo.Delete(ctx, id); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("vault: delete credential: %w", err)
	}
	return s.record(ctx, audit.Event{
		Action: "vault.revoke", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeOK,
	})
}

func (s *service) Exists(ctx context.Context, id Identity) (bool, error) {
	if err := id.validate(); err != nil {
		return false, err
	}
	if _, err := s.repo.Get(ctx, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *service) record(ctx context.Context, e audit.Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if err := s.audit.Record(ctx, e); err != nil {
		return fmt.Errorf("vault: audit: %w", err)
	}
	return nil
}
