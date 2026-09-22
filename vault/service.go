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

	// Rotate re-wraps every record whose DEK is not wrapped by the current key,
	// so a retired KEK can be discarded. It is an operational action, not a read
	// path: it visits every credential.
	Rotate(ctx context.Context) (Rotation, error)
}

type service struct {
	repo Repo
	// current wraps new DEKs, and is the target of a rotation.
	current KeyWrapper
	// keys indexes every wrapper that may unwrap, by the id that appears in a
	// record. A record is unwrapped by the key that wrapped it, which is the only
	// thing that makes rotation possible: without the old key, a record written
	// before the rotation cannot be re-wrapped, and is simply unreadable.
	keys  map[string]KeyWrapper
	audit audit.Logger
}

// Option tunes a Service.
type Option func(*service) error

// WithRetiredKeys declares additional KEKs that may still have wrapped records.
//
// They can only unwrap; new records always use the current key. This is what a
// rotation needs in order to run at all, and it is also what keeps a deployment
// serving while a rotation is in progress. Once `Rotate` reports nothing left to
// re-wrap, they can be removed from the configuration and discarded.
//
// Each retired key must carry the id it had **while it was current**, because
// that id is what the records remember.
func WithRetiredKeys(keys ...KeyWrapper) Option {
	return func(s *service) error {
		for _, k := range keys {
			if k == nil {
				return errors.New("vault: a retired KeyWrapper must not be nil")
			}
			id := k.KeyID()
			if id == s.current.KeyID() {
				return fmt.Errorf("vault: retired key %q has the same id as the current key; "+
					"a KEK id must change when the key material does", id)
			}
			if _, dup := s.keys[id]; dup {
				return fmt.Errorf("vault: retired key %q is declared twice", id)
			}
			s.keys[id] = k
		}
		return nil
	}
}

// Rotation reports what a key rotation examined and changed.
type Rotation struct {
	// Scanned is how many records were visited.
	Scanned int
	// Rewrapped is how many had their DEK re-wrapped under the current key.
	Rewrapped int
	// AlreadyCurrent is how many were on the current key and verified as readable
	// by it.
	AlreadyCurrent int
}

// NewService wires a vault service. The first three arguments are required.
func NewService(repo Repo, kek KeyWrapper, logger audit.Logger, opts ...Option) (Service, error) {
	if repo == nil {
		return nil, errors.New("vault: Repo is required")
	}
	if kek == nil {
		return nil, errors.New("vault: KeyWrapper is required")
	}
	if logger == nil {
		return nil, errors.New("vault: audit.Logger is required")
	}
	if kek.KeyID() == "" {
		// The id is the lookup key for unwrapping, so an empty one would make every
		// record unwrappable by nothing.
		return nil, errors.New("vault: KeyWrapper.KeyID must not be empty")
	}

	s := &service{
		repo:    repo,
		current: kek,
		audit:   logger,
		keys:    map[string]KeyWrapper{kek.KeyID(): kek},
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
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
	defer Scrub(dek)

	wrapped, err := s.current.Wrap(ctx, dek, aad)
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
		KEKID:      s.current.KeyID(),
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
	key, ok := s.keys[rec.KEKID]
	if !ok {
		// Saying which key is missing is the difference between "a rotation was left
		// half-configured" and "the ciphertext is corrupt".
		_ = s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		return fmt.Errorf("vault: %s was wrapped by key %q, which is not configured; "+
			"declare it as a retired key if this deployment rotated away from it", id, rec.KEKID)
	}
	dek, err := key.Unwrap(ctx, rec.WrappedDEK, aad)
	if err != nil {
		_ = s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		return fmt.Errorf("vault: unwrap DEK: %w", err)
	}
	defer Scrub(dek)

	plain, err := openSecret(dek, rec.Nonce, rec.Ciphertext, aad)
	if err != nil {
		_ = s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		return err
	}
	defer Scrub(plain)

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
