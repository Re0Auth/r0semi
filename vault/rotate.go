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
	var out Rotation

	// A repo that can page is walked a page at a time: rotation visits every
	// credential in the deployment, and holding all of them at once does not scale
	// with the number of accounts. The cursor is the last record read, and rotation
	// never changes a record's identity, so paging is stable under the writes it
	// makes.
	if pager, ok := s.repo.(RecordPager); ok {
		var afterSubject, afterProvider string
		for {
			page, err := pager.ListPage(ctx, afterSubject, afterProvider, rotatePageSize)
			if err != nil {
				return out, fmt.Errorf("vault: rotate: list: %w", err)
			}
			if len(page) == 0 {
				break
			}
			if err := s.rotateRecords(ctx, page, &out); err != nil {
				return out, err
			}
			if len(page) < rotatePageSize {
				break
			}
			last := page[len(page)-1]
			afterSubject, afterProvider = last.Identity.Subject, last.Identity.Provider
		}
	} else {
		records, err := s.repo.List(ctx)
		if err != nil {
			return out, fmt.Errorf("vault: rotate: list: %w", err)
		}
		if err := s.rotateRecords(ctx, records, &out); err != nil {
			return out, err
		}
	}

	// One event for the operation rather than one per record: the counts are the
	// part anyone reads, and a rotation over a large vault should not flood the log
	// it is meant to be auditable in.
	//
	// The outcome is not unconditionally "ok": a run that left records unre-wrapped
	// must not read as a completed rotation in the audit trail, because that trail
	// is what an operator consults before deleting the retired key.
	//
	// A sink that cannot take the event fails the whole run, as it does for
	// Enroll/Use/Revoke: an operator who automates "exit 0 => remove the retired
	// key" must not be handed an exit 0 whose only evidence was never written. The
	// rotation is idempotent, so re-running it is safe (G-19).
	outcome := audit.OutcomeOK
	if out.Skipped > 0 {
		outcome = audit.OutcomeError
	}
	if err := s.record(ctx, audit.Event{
		Action:  "vault.rotate_keys",
		Outcome: outcome,
		Detail: map[string]string{
			"to_key":    s.current.KeyID(),
			"scanned":   strconv.Itoa(out.Scanned),
			"rewrapped": strconv.Itoa(out.Rewrapped),
			"skipped":   strconv.Itoa(out.Skipped),
		},
	}); err != nil {
		return out, err
	}
	return out, nil
}

// rotatePageSize is how many records one page of a rotation holds.
const rotatePageSize = 200

// rotateRecords re-wraps the DEK of every record that is not on the current key,
// accumulating what it examined into out.
func (s *service) rotateRecords(ctx context.Context, records []Record, out *Rotation) error {
	current := s.current.KeyID()
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
				return fmt.Errorf(
					"vault: rotate: %s is tagged %q but the current key cannot unwrap it: "+
						"the key material changed without changing kek_id: %w",
					identityRef(rec.Identity), current, err)
			}
			Scrub(dek)
			out.AlreadyCurrent++
			continue
		}

		old, ok := s.keys[rec.KEKID]
		if !ok {
			return fmt.Errorf(
				"vault: rotate: %s was wrapped by key %q, which is not configured; "+
					"declare it as a retired key and run again", identityRef(rec.Identity), rec.KEKID)
		}
		dek, err := old.Unwrap(ctx, rec.WrappedDEK, aad)
		if err != nil {
			return fmt.Errorf("vault: rotate: unwrap %s: %w", identityRef(rec.Identity), err)
		}
		wrapped, err := s.current.Wrap(ctx, dek, aad)
		Scrub(dek)
		if err != nil {
			return fmt.Errorf("vault: rotate: re-wrap %s: %w", identityRef(rec.Identity), err)
		}

		// The envelope ONLY, and only if the row is still the one that was read.
		//
		// Writing the whole record back is what made this a lost update: the record
		// carries the payload ciphertext, the metadata and the timestamps as they
		// were when the page was read, so a credential enrolled in the meantime was
		// restored to its earlier contents — the user's newer secret gone, the
		// rotation reporting success. `expect` is the wrapped DEK just unwrapped, so
		// a concurrent enrol or a concurrent re-wrap both make the write refuse.
		applied, err := s.repo.RewrapIfUnchanged(ctx, rec.Identity, rec.WrappedDEK, Envelope{
			KEKID:      current,
			WrappedDEK: wrapped,
			UpdatedAt:  time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("vault: rotate: persist %s: %w", identityRef(rec.Identity), err)
		}
		if !applied {
			// The row changed (or is gone) since the page was read. It was NOT
			// re-wrapped by this run, so the run must not report itself complete: a
			// credential written by a process still on the retired key stays on that
			// key, and removing it is what makes such a record permanently
			// unreadable. See Rotation.Skipped.
			out.Skipped++
			continue
		}
		out.Rewrapped++
	}
	return nil
}
