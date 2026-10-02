package vault

import (
	"context"
	"crypto/subtle"
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

// Metrics observes credential-vault operations. It is optional: a nil interface
// records nothing.
//
// vault is a public library and must not import this service's observability
// package, so a deployment injects its own implementation with WithMetrics. The
// vocabulary travels in the strings:
//
//   - operation: "use", "enroll" or "revoke";
//   - result: "ok", "not_found", "repo_error", "key_unavailable",
//     "decrypt_error" or "audit_error";
//   - d: wall-clock duration of the whole operation — for Use, that includes the
//     audit write and the caller's callback, so it is the latency a caller sees.
type Metrics interface {
	ObserveVaultOperation(operation, result string, d time.Duration)
}

// The vault's label vocabulary. They are unexported because the only consumer is
// this package; a Metrics implementation receives them as opaque strings.
const (
	metricOpUse    = "use"
	metricOpEnroll = "enroll"
	metricOpRevoke = "revoke"

	metricOK             = "ok"
	metricNotFound       = "not_found"
	metricRepoError      = "repo_error"
	metricKeyUnavailable = "key_unavailable"
	metricDecryptError   = "decrypt_error"
	metricAuditError     = "audit_error"
	metricError          = "error"
)

type service struct {
	repo Repo
	// current wraps new DEKs, and is the target of a rotation.
	current KeyWrapper
	// keys indexes every wrapper that may unwrap, by the id that appears in a
	// record. A record is unwrapped by the key that wrapped it, which is the only
	// thing that makes rotation possible: without the old key, a record written
	// before the rotation cannot be re-wrapped, and is simply unreadable.
	keys    map[string]KeyWrapper
	audit   audit.Logger
	metrics Metrics
}

// Option tunes a Service.
type Option func(*service) error

// WithMetrics attaches an observer for vault operations. It is optional: without
// it, operations run unobserved.
func WithMetrics(m Metrics) Option {
	return func(s *service) error {
		s.metrics = m
		return nil
	}
}

// observe records one completed operation. A nil observer is a no-op, so the
// call sites below need no branch.
func (s *service) observe(operation, result string, start time.Time) {
	if s.metrics == nil {
		return
	}
	s.metrics.ObserveVaultOperation(operation, result, time.Since(start))
}

// WithRetiredKeys declares additional KEKs that may still have wrapped records.
//
// They can only unwrap; new records always use the current key. This is what a
// rotation needs in order to run at all, and it is also what keeps a deployment
// serving while a rotation is in progress. Once `Rotate` reports nothing left to
// re-wrap, they can be removed from the configuration and discarded.
//
// Each retired key must carry the id it had **while it was current**, because
// that id is what the records remember. Two wrappers that expose a
// KeyFingerprint must also hold distinct material from the current key and from
// each other: a "rotation" that only changes the id relabels every record without
// changing what protects it, and the deployment is refused at startup so it
// cannot be mistaken for a completed rotation.
func WithRetiredKeys(keys ...KeyWrapper) Option {
	return func(s *service) error {
		added := make([]KeyWrapper, 0, len(keys))
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
			if sameKeyMaterial(k, s.current) {
				return fmt.Errorf("vault: retired key %q holds the same material as the current key %q; "+
					"reusing material under a new id is not a rotation, "+
					"because the envelopes it relabels stay openable by the retired bytes",
					id, s.current.KeyID())
			}
			for _, prev := range added {
				if sameKeyMaterial(k, prev) {
					return fmt.Errorf("vault: retired key %q holds the same material as retired key %q; "+
						"two retired keys that share material are one key under two ids",
						id, prev.KeyID())
				}
			}
			s.keys[id] = k
			added = append(added, k)
		}
		return nil
	}
}

// sameKeyMaterial reports whether two wrappers hold the same key material.
//
// It is deliberately conservative: unless BOTH wrappers implement
// KeyFingerprint there is nothing this package can compare, and it answers false.
// A KMS/HSM wrapper keeps its material out of the process by design and must not
// be forced to expose a digest of it, so the check can only ever be a local one.
func sameKeyMaterial(a, b KeyWrapper) bool {
	af, aok := a.(KeyFingerprint)
	bf, bok := b.(KeyFingerprint)
	if !aok || !bok {
		return false
	}
	afp, bfp := af.Fingerprint(), bf.Fingerprint()
	return subtle.ConstantTimeCompare(afp[:], bfp[:]) == 1
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
	// Skipped is how many records were NOT re-wrapped because the row was no longer
	// the one that was read — a credential enrolled or re-wrapped by another process
	// in between, or deleted (an erasure). A non-zero value means the run cannot be
	// called complete: whatever the other process wrote may still be on a retired
	// key, so the retired key must stay configured and the rotation must be run
	// again until Skipped and Rewrapped are both zero.
	//
	// Scanned == Rewrapped + AlreadyCurrent + Skipped always holds.
	Skipped int
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
	start := time.Now()
	if err := id.validate(); err != nil {
		return err
	}
	aad := bindingAAD(recordVersion, id.Subject, id.Provider)

	dek := make([]byte, dekSize)
	if err := fillRandom(dek); err != nil {
		s.observe(metricOpEnroll, metricError, start)
		return err
	}
	defer Scrub(dek)

	wrapped, err := s.current.Wrap(ctx, dek, aad)
	if err != nil {
		s.observe(metricOpEnroll, metricError, start)
		return fmt.Errorf("vault: wrap DEK: %w", err)
	}
	nonce, ct, err := sealSecret(dek, secret, aad)
	if err != nil {
		s.observe(metricOpEnroll, metricError, start)
		return err
	}

	now := time.Now().UTC()
	// Fail closed: the enrollment is audited before it is persisted, mirroring
	// Use's ordering (I3). An unavailable audit log must leave no record behind,
	// rather than reporting an error for a write that already happened and would
	// linger unaudited.
	if err := s.record(ctx, audit.Event{
		Action:   "vault.enroll",
		Subject:  id.Subject,
		Provider: id.Provider,
		Outcome:  audit.OutcomeOK,
	}); err != nil {
		s.observe(metricOpEnroll, metricAuditError, start)
		return err
	}
	// A re-enrollment replaces the secret, not the credential's birth: Put writes
	// the whole row, so CreatedAt has to be carried over from the row being
	// replaced or the time the account first held this credential is lost (S07-9).
	// A read that fails leaves this write's own timestamp, and the Put below
	// reports the repository failure itself.
	createdAt := now
	if prev, err := s.repo.Get(ctx, id); err == nil {
		createdAt = prev.CreatedAt
	}
	if err := s.repo.Put(ctx, Record{
		Identity:   id,
		Version:    recordVersion,
		WrappedDEK: wrapped,
		KEKID:      s.current.KeyID(),
		Nonce:      nonce,
		Ciphertext: ct,
		Meta:       cloneMeta(meta),
		CreatedAt:  createdAt,
		UpdatedAt:  now,
	}); err != nil {
		s.observe(metricOpEnroll, metricRepoError, start)
		return fmt.Errorf("vault: persist credential: %w", err)
	}
	s.observe(metricOpEnroll, metricOK, start)
	return nil
}

func (s *service) Use(ctx context.Context, id Identity, fn func(secret []byte) error) error {
	start := time.Now()
	if err := id.validate(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("vault: Use requires a callback")
	}

	rec, err := s.repo.Get(ctx, id)
	if err != nil {
		aerr := s.record(ctx, audit.Event{
			Action:   "vault.use",
			Subject:  id.Subject,
			Provider: id.Provider,
			Outcome:  audit.OutcomeDenied,
		})
		// A missing record and a failing repository are different incidents: the
		// first is a caller asking for a credential that was never there, the
		// second is the storage layer itself.
		result := metricRepoError
		if errors.Is(err, ErrNotFound) {
			result = metricNotFound
		}
		s.observe(metricOpUse, result, start)
		// The audit failure is joined, not dropped: this sink is fail-closed on the
		// success path, so an unavailable log must be visible here too. Join keeps
		// errors.Is(err, ErrNotFound) true for callers (Z19-3).
		return errors.Join(err, aerr)
	}

	// The AAD is built from the record's own identity, as Rotate builds it
	// (rotate.go). Deriving it from the requested id made the read path and the
	// rotation disagree about which row they were addressing (S07-4).
	aad := bindingAAD(rec.Version, rec.Identity.Subject, rec.Identity.Provider)
	key, ok := s.keys[rec.KEKID]
	if !ok {
		aerr := s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		s.observe(metricOpUse, metricKeyUnavailable, start)
		// Saying which key is missing is the difference between "a rotation was left
		// half-configured" and "the ciphertext is corrupt"; saying which subject it
		// belongs to is not needed, and it would reach the process log (G-21).
		return errors.Join(fmt.Errorf("vault: %s was wrapped by key %q, which is not configured; "+
			"declare it as a retired key if this deployment rotated away from it",
			identityRef(rec.Identity), rec.KEKID), aerr)
	}
	dek, err := key.Unwrap(ctx, rec.WrappedDEK, aad)
	if err != nil {
		aerr := s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		s.observe(metricOpUse, metricDecryptError, start)
		return errors.Join(fmt.Errorf("vault: unwrap DEK: %w", err), aerr)
	}
	defer Scrub(dek)

	plain, err := openSecret(dek, rec.Nonce, rec.Ciphertext, aad)
	if err != nil {
		aerr := s.record(ctx, audit.Event{
			Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeError,
		})
		s.observe(metricOpUse, metricDecryptError, start)
		return errors.Join(err, aerr)
	}
	defer Scrub(plain)

	// I3: the access record is persisted before the secret is used. If the
	// audit log is unavailable we fail closed rather than proceed unaudited.
	if err := s.record(ctx, audit.Event{
		Action: "vault.use", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeOK,
	}); err != nil {
		s.observe(metricOpUse, metricAuditError, start)
		return err
	}

	// The callback's own error is the caller's outcome, not the vault's: the
	// credential was opened and handed over, which is what this signal means.
	result := fn(plain)
	s.observe(metricOpUse, metricOK, start)
	return result
}

func (s *service) Revoke(ctx context.Context, id Identity) error {
	start := time.Now()
	if err := id.validate(); err != nil {
		return err
	}
	// Removing the wrapped DEK crypto-shreds the credential: the ciphertext,
	// even if it lingers, is no longer decryptable.
	if err := s.repo.Delete(ctx, id); err != nil && !errors.Is(err, ErrNotFound) {
		s.observe(metricOpRevoke, metricRepoError, start)
		return fmt.Errorf("vault: delete credential: %w", err)
	}
	if err := s.record(ctx, audit.Event{
		Action: "vault.revoke", Subject: id.Subject, Provider: id.Provider, Outcome: audit.OutcomeOK,
	}); err != nil {
		s.observe(metricOpRevoke, metricAuditError, start)
		return err
	}
	s.observe(metricOpRevoke, metricOK, start)
	return nil
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
