package vault

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// Rotate re-wraps every record's DEK under the current key.
//
// # What it changes, and what it cannot
//
// The DEK stays the same, so the payload ciphertext is never touched and no
// plaintext is produced. Only the envelope around the DEK is rewritten. That is
// what makes rotation cheap, and safe to run again.
//
// It resolves exactly one of the three ways a key can be exposed:
//
//   - **The database leaked, the key did not.** Nothing was readable, and nothing
//     needs doing: the envelope already handled it.
//   - **The key leaked, the database did not.** This is the case rotation exists
//     for. Nothing was readable either, and rotation is what lets the leaked key
//     be retired so that records written from now on are not protected by
//     something an attacker already holds.
//   - **Both leaked.** The credentials are compromised. Rotation stops the leak
//     from applying to anything written afterwards, and **nothing local can undo
//     the exposure** — re-encrypting the same secret changes its stored bytes,
//     not what the attacker has. Recovering means enrolling new credentials at
//     the source, which is why §6.0 of the threat model says so rather than
//     offering a command that looks like a fix.
func (s *service) Rotate(ctx context.Context) (Rotation, error) {
	records, err := s.repo.List(ctx)
	if err != nil {
		return Rotation{}, fmt.Errorf("vault: rotate: list: %w", err)
	}

	current := s.current.KeyID()
	var out Rotation
	for _, rec := range records {
		out.Scanned++
		aad := bindingAAD(rec.Version, rec.Identity.Subject, rec.Identity.Provider)

		if rec.KEKID == current {
			// Verify rather than assume. A deployment that changed the key material
			// but kept the id would otherwise look fully rotated while every
			// credential had become unreadable, and the first sign of it would be a
			// user unable to reach their own data.
			dek, err := s.current.Unwrap(ctx, rec.WrappedDEK, aad)
			if err != nil {
				return out, fmt.Errorf(
					"vault: rotate: %s is tagged %q but the current key cannot unwrap it: "+
						"the key material changed without changing kek_id: %w",
					rec.Identity, current, err)
			}
			Scrub(dek)
			out.AlreadyCurrent++
			continue
		}

		old, ok := s.keys[rec.KEKID]
		if !ok {
			return out, fmt.Errorf(
				"vault: rotate: %s was wrapped by key %q, which is not configured; "+
					"declare it as a retired key and run again", rec.Identity, rec.KEKID)
		}
		dek, err := old.Unwrap(ctx, rec.WrappedDEK, aad)
		if err != nil {
			return out, fmt.Errorf("vault: rotate: unwrap %s: %w", rec.Identity, err)
		}
		wrapped, err := s.current.Wrap(ctx, dek, aad)
		Scrub(dek)
		if err != nil {
			return out, fmt.Errorf("vault: rotate: re-wrap %s: %w", rec.Identity, err)
		}

		rec.WrappedDEK = wrapped
		rec.KEKID = current
		rec.UpdatedAt = time.Now().UTC()
		if err := s.repo.Put(ctx, rec); err != nil {
			return out, fmt.Errorf("vault: rotate: persist %s: %w", rec.Identity, err)
		}
		out.Rewrapped++
	}

	// One event for the operation rather than one per record: the counts are the
	// part anyone reads, and a rotation over a large vault should not flood the log
	// it is meant to be auditable in.
	_ = s.record(ctx, audit.Event{
		Action:  "vault.rotate_keys",
		Outcome: audit.OutcomeOK,
		Detail: map[string]string{
			"to_key":    current,
			"scanned":   strconv.Itoa(out.Scanned),
			"rewrapped": strconv.Itoa(out.Rewrapped),
		},
	})
	return out, nil
}
