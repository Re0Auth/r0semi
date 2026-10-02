package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Identity names one stored credential.
//
// Subject is the r0semi-internal user identifier. Provider is an opaque
// identifier for the credential's origin -- an auth provider such as "taptap",
// or a game that maintains its own credentials. The vault never interprets
// Provider, which is what keeps it game-agnostic and extensible: adding a game
// means registering a new provider value, not changing the vault.
//
// PRIVACY: Identity is personal data. It appears in the clear both in this
// record and in whichever store holds it, so a store compromise reveals the
// (Subject, Provider) pairs a user holds -- e.g. which games they play. It is
// not a secret and is not encrypted; treat it as PII at rest.
type Identity struct {
	Subject  string
	Provider string
}

// String renders the identity as "provider:subject". It is convenient in a test
// message and deliberately NOT used in this package's error text: an error from
// here reaches the -rotate-keys die path (cmd/re0auth) and the unbind/cascade warn
// paths, and a raw usr_… in a retained process log outlives the erasure's
// pseudonym key. Use identityRef for anything a caller prints or logs (G-21).
func (i Identity) String() string { return i.Provider + ":" + i.Subject }

// identityRef renders an identity for an error message without writing the subject.
// What an operator needs in order to locate a row is its provider and the kek_id
// that could not open it; the subject is personal data the message does not need.
func identityRef(id Identity) string {
	return fmt.Sprintf("provider %q (subject %d bytes)", id.Provider, len(id.Subject))
}

// ErrInvalidIdentity reports an empty or over-long subject or provider.
var ErrInvalidIdentity = errors.New("vault: invalid identity")

// maxIdentityFieldLen bounds one identity field. A stored subject is
// generated ("usr_" plus 16 hex characters) and a provider is a configured name,
// so this bound is far above any real identity. It is not what keeps bindingAAD
// collision-free: that encoding length-prefixes each field with a uvarint, which
// cannot truncate a Go-length field (S07-11). The bound is store hygiene — it
// refuses an identity whose shape no caller could have meant.
const maxIdentityFieldLen = 1024

func (i Identity) validate() error {
	if i.Subject == "" {
		return ErrInvalidIdentity
	}
	if i.Provider == "" {
		return ErrInvalidIdentity
	}
	if len(i.Subject) > maxIdentityFieldLen || len(i.Provider) > maxIdentityFieldLen {
		return ErrInvalidIdentity
	}
	return nil
}

// Record is the at-rest form of one credential. It contains no plaintext: the
// secret is only recoverable by unwrapping WrappedDEK through the KeyWrapper
// and decrypting Ciphertext with the resulting DEK.
//
// Two parts are deliberately NOT encrypted, because they are needed without the
// KEK: Identity (the lookup key) and Meta. See their individual docs for the
// privacy consequence.
//
// Deleting the wrapped DEK therefore crypto-shreds the credential even if
// Ciphertext lingers.
type Record struct {
	Identity   Identity
	Version    byte
	WrappedDEK []byte
	KEKID      string
	Nonce      []byte
	Ciphertext []byte
	// Meta is non-secret metadata about the credential (for example the upstream
	// openid/unionid and the LeanCloud objectId). It is stored in the clear, so
	// it must never hold a secret -- and it is PII at rest: a store compromise
	// reveals those identifiers, though not the credential itself.
	Meta      map[string]string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ErrNotFound reports a missing credential.
var ErrNotFound = errors.New("vault: credential not found")

// Envelope is the part of a record a key rotation replaces: the wrapped DEK, the
// id of the key that wrapped it, and when. Everything else in a Record belongs to
// the identity or the payload, and a rotation must not touch any of it — which is
// the point of naming this much rather than passing a whole Record.
type Envelope struct {
	KEKID      string
	WrappedDEK []byte
	UpdatedAt  time.Time
}

// Repo persists credential records. It stores opaque crypto material and needs
// no knowledge of the vault's envelope format.
type Repo interface {
	Put(ctx context.Context, rec Record) error
	Get(ctx context.Context, id Identity) (Record, error)
	Delete(ctx context.Context, id Identity) error
	// RewrapIfUnchanged replaces ONLY the envelope of id, and only when the stored
	// wrapped DEK still equals expect. It reports whether it applied.
	//
	// It is on the interface rather than assembled by the caller from Get+Put
	// because the window between those two is where a credential is lost: a
	// rotation that writes back the whole record it read restores that record's old
	// ciphertext, metadata and timestamps, so a credential enrolled by another
	// process in the meantime is silently rolled back while the rotation reports
	// success. Only the store can make "read, compare, write" one atomic step.
	//
	// expect is the wrapped DEK the caller read. It works as a compare-and-swap
	// token because it is specific to the row's crypto material: a concurrent enrol
	// (new DEK, new ciphertext) and a concurrent re-wrap (new envelope) both change
	// it. A row that is no longer there reports false: there is nothing left to
	// re-wrap, and that is not an error.
	RewrapIfUnchanged(ctx context.Context, id Identity, expect []byte, next Envelope) (bool, error)
	// List returns every record, ordered by identity.
	//
	// It exists for one caller: key rotation, which has to visit everything. No
	// read path enumerates credentials, and adding one would be a bigger change to
	// the privacy story than it looks — the set of records is itself the "who holds
	// credentials for what" question that Identity is already documented as leaking.
	List(ctx context.Context) ([]Record, error)
	// DeleteSubject removes every credential belonging to one subject and reports
	// how many there were. It is the account-erasure path.
	//
	// It deletes whole rows rather than nulling WrappedDEK, and that distinction
	// matters: Identity and Meta are stored in the clear, so blanking only the
	// wrapped key would leave the account's PII behind while making the credential
	// undecryptable — an erasure that reports success and is not one.
	DeleteSubject(ctx context.Context, subject string) (int, error)
}

// RecordPager is implemented by a Repo that can enumerate records a page at a
// time, in ascending (subject, provider) order.
//
// Rotate visits every credential, and loading the whole vault into memory to do it
// does not scale with the number of accounts. A repo that can page is asked for
// pages; one that cannot keeps using List — which is why this is a separate
// interface rather than another method on Repo, whose implementations include
// third-party ones.
//
// An empty cursor is the start of the list.
type RecordPager interface {
	ListPage(ctx context.Context, afterSubject, afterProvider string, limit int) ([]Record, error)
}

// MemoryRepo is a non-durable Repo for development and tests.
type MemoryRepo struct {
	mu      sync.RWMutex
	records map[Identity]Record
	// ids indexes the records' keys in identityLess order, so a listing or a page
	// never has to materialise and re-sort the whole map. Every mutation keeps it in
	// sync: Put inserts a new key with a binary search, Delete and DeleteSubject
	// remove keys, and RewrapIfUnchanged rewrites only the payload (the key does not
	// move).
	ids []Identity
	// rowsCopied counts the rows List and ListPage have cloned out. It exists so a
	// probe can show that paging copies each row once rather than materialising the
	// whole table per page; nothing in the read path depends on it.
	rowsCopied atomic.Int64
}

// NewMemoryRepo returns an empty in-memory credential store.
func NewMemoryRepo() *MemoryRepo {
	return &MemoryRepo{records: make(map[Identity]Record)}
}

// indexOf returns the position of id in the ordered index and whether it is
// present. When absent, the position is where it must be inserted.
func (r *MemoryRepo) indexOf(id Identity) (int, bool) {
	i := sort.Search(len(r.ids), func(i int) bool { return !identityLess(r.ids[i], id) })
	if i < len(r.ids) && r.ids[i] == id {
		return i, true
	}
	return i, false
}

// insertIndex records id in the ordered index. The caller must have already
// established that id is absent.
func (r *MemoryRepo) insertIndex(id Identity) {
	i, _ := r.indexOf(id)
	r.ids = append(r.ids, Identity{})
	copy(r.ids[i+1:], r.ids[i:])
	r.ids[i] = id
}

// removeIndex drops id from the ordered index if it is there.
func (r *MemoryRepo) removeIndex(id Identity) {
	if i, ok := r.indexOf(id); ok {
		r.ids = append(r.ids[:i], r.ids[i+1:]...)
	}
}

// Put implements Repo. Existing records are replaced.
func (r *MemoryRepo) Put(_ context.Context, rec Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.records[rec.Identity]; !ok {
		r.insertIndex(rec.Identity)
	}
	r.records[rec.Identity] = cloneRecord(rec)
	return nil
}

// RewrapIfUnchanged implements Repo. The comparison and the write happen under one
// lock, which is what makes it a compare-and-swap rather than a narrower race.
func (r *MemoryRepo) RewrapIfUnchanged(_ context.Context, id Identity, expect []byte, next Envelope) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[id]
	if !ok {
		return false, nil
	}
	if !bytes.Equal(rec.WrappedDEK, expect) {
		return false, nil
	}
	rec.WrappedDEK = append([]byte(nil), next.WrappedDEK...)
	rec.KEKID = next.KEKID
	rec.UpdatedAt = next.UpdatedAt
	r.records[id] = rec
	return true, nil
}

// Get implements Repo.
func (r *MemoryRepo) Get(_ context.Context, id Identity) (Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(rec), nil
}

// Delete implements Repo.
func (r *MemoryRepo) Delete(_ context.Context, id Identity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.records[id]; !ok {
		return ErrNotFound
	}
	delete(r.records, id)
	r.removeIndex(id)
	return nil
}

// List implements Repo, ordered by (subject, provider) so two runs agree — and so
// the order matches the Postgres adapter's `ORDER BY subject, provider` and the
// cursor ListPage compares against. Identity.String() renders it the other way
// round (provider:subject), and ordering by that was a real bug: the pager's
// cursor then disagreed with the listing's order, so a rotation walked some
// records twice and others not at all.
func (r *MemoryRepo) List(_ context.Context) ([]Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Record, 0, len(r.ids))
	for _, id := range r.ids {
		out = append(out, cloneRecord(r.records[id]))
	}
	r.rowsCopied.Add(int64(len(out)))
	return out, nil
}

// identityLess orders identities the way every listing and cursor does.
func identityLess(a, b Identity) bool {
	if a.Subject != b.Subject {
		return a.Subject < b.Subject
	}
	return a.Provider < b.Provider
}

// ListPage implements RecordPager: the records after the cursor, in the same order
// List returns them.
//
// The ordered index makes this a bounded read rather than a full scan: the cursor
// is located by binary search, so a page copies only its own rows and never sorts
// the table.
func (r *MemoryRepo) ListPage(_ context.Context, afterSubject, afterProvider string, limit int) ([]Record, error) {
	if limit <= 0 {
		limit = 1
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	// recordAfter is monotone over the sorted index (a contiguous run of trues), so
	// its first true position is exactly the cursor's successor.
	pos := sort.Search(len(r.ids), func(i int) bool {
		return recordAfter(r.ids[i], afterSubject, afterProvider)
	})
	end := pos + limit
	if end > len(r.ids) {
		end = len(r.ids)
	}

	out := make([]Record, 0, end-pos)
	for _, id := range r.ids[pos:end] {
		out = append(out, cloneRecord(r.records[id]))
	}
	r.rowsCopied.Add(int64(len(out)))
	return out, nil
}

// recordAfter reports whether id sorts after the (subject, provider) cursor. An
// empty cursor is the start of the list, which is safe because a stored identity
// always has both fields set.
func recordAfter(id Identity, subject, provider string) bool {
	if subject == "" && provider == "" {
		return true
	}
	if id.Subject != subject {
		return id.Subject > subject
	}
	return id.Provider > provider
}

// DeleteSubject implements Repo.
func (r *MemoryRepo) DeleteSubject(_ context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, ErrInvalidIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// One subject's records are a contiguous run in (subject, provider) order, so
	// the run is found by binary search and removed as a block.
	lo := sort.Search(len(r.ids), func(i int) bool { return r.ids[i].Subject >= subject })
	hi := lo
	for hi < len(r.ids) && r.ids[hi].Subject == subject {
		delete(r.records, r.ids[hi])
		hi++
	}
	if hi > lo {
		r.ids = append(r.ids[:lo], r.ids[hi:]...)
	}
	return hi - lo, nil
}

func cloneRecord(rec Record) Record {
	rec.WrappedDEK = cloneBytes(rec.WrappedDEK)
	rec.Nonce = cloneBytes(rec.Nonce)
	rec.Ciphertext = cloneBytes(rec.Ciphertext)
	rec.Meta = cloneMeta(rec.Meta)
	return rec
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneMeta(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
