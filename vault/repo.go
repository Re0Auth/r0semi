package vault

import (
	"context"
	"errors"
	"sort"
	"sync"
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

func (i Identity) String() string { return i.Provider + ":" + i.Subject }

// ErrInvalidIdentity reports an empty subject or provider.
var ErrInvalidIdentity = errors.New("vault: invalid identity")

func (i Identity) validate() error {
	if i.Subject == "" {
		return ErrInvalidIdentity
	}
	if i.Provider == "" {
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

// Repo persists credential records. It stores opaque crypto material and needs
// no knowledge of the vault's envelope format.
type Repo interface {
	Put(ctx context.Context, rec Record) error
	Get(ctx context.Context, id Identity) (Record, error)
	Delete(ctx context.Context, id Identity) error
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

// MemoryRepo is a non-durable Repo for development and tests.
type MemoryRepo struct {
	mu      sync.RWMutex
	records map[Identity]Record
}

// NewMemoryRepo returns an empty in-memory credential store.
func NewMemoryRepo() *MemoryRepo {
	return &MemoryRepo{records: make(map[Identity]Record)}
}

// Put implements Repo. Existing records are replaced.
func (r *MemoryRepo) Put(_ context.Context, rec Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[rec.Identity] = cloneRecord(rec)
	return nil
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
	return nil
}

// List implements Repo, ordered by identity so two runs agree.
func (r *MemoryRepo) List(_ context.Context) ([]Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]Identity, 0, len(r.records))
	for id := range r.records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })

	out := make([]Record, 0, len(ids))
	for _, id := range ids {
		out = append(out, cloneRecord(r.records[id]))
	}
	return out, nil
}

// DeleteSubject implements Repo.
func (r *MemoryRepo) DeleteSubject(_ context.Context, subject string) (int, error) {
	if subject == "" {
		return 0, ErrInvalidIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id := range r.records {
		if id.Subject == subject {
			delete(r.records, id)
			n++
		}
	}
	return n, nil
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
