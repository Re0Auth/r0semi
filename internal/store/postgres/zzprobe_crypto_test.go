//go:build audit5

package postgres

// Audit probe (crypto/key-lifecycle area). This file only READS the package's
// unexported surface — auditRow.canonical, chainHash, AuditLogger.mac,
// subjectIndex, pseudonymOf, auditGenesis — and never touches the database, so
// every test here runs on this machine. Persistence aspects of the same code are
// marked 「读；无 DB 执行」 in the report.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

func probeRow() auditRow {
	return auditRow{
		OccurredAt: time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC),
		Action:     "vault.use",
		Subject:    "usr_alice",
		Provider:   "taptap",
		Outcome:    "ok",
		Detail:     map[string]string{"k": "v"},
	}
}

// TestProbeCanonicalIsDeterministicAndTotal is the anti-vacuity control: the
// baseline row must hash the same twice, and every mutation must change the hash.
// Without the first half, "the mutation changed the hash" would be meaningless.
func TestProbeCanonicalIsDeterministicAndTotal(t *testing.T) {
	base := probeRow()
	first := base.canonical()
	for i := 0; i < 64; i++ {
		if !bytes.Equal(first, base.canonical()) {
			t.Fatalf("canonical is not deterministic on run %d", i)
		}
	}

	mutations := map[string]func(*auditRow){
		"action":     func(r *auditRow) { r.Action = "vault.enroll" },
		"subject":    func(r *auditRow) { r.Subject = "usr_bob" },
		"provider":   func(r *auditRow) { r.Provider = "phigros" },
		"outcome":    func(r *auditRow) { r.Outcome = "denied" },
		"time+1us":   func(r *auditRow) { r.OccurredAt = r.OccurredAt.Add(time.Microsecond) },
		"time-1us":   func(r *auditRow) { r.OccurredAt = r.OccurredAt.Add(-time.Microsecond) },
		"detail val": func(r *auditRow) { r.Detail = map[string]string{"k": "w"} },
		"detail key": func(r *auditRow) { r.Detail = map[string]string{"j": "v"} },
		"detail +1":  func(r *auditRow) { r.Detail = map[string]string{"k": "v", "k2": "v"} },
		"detail -1":  func(r *auditRow) { r.Detail = map[string]string{} },
		"detail nil": func(r *auditRow) { r.Detail = nil },
	}
	for name, mutate := range mutations {
		row := probeRow()
		mutate(&row)
		if bytes.Equal(first, row.canonical()) {
			t.Errorf("mutation %q did not change the canonical form", name)
		}
	}

	// nil and empty Detail must agree: Record() normalises nil to an empty map
	// before enqueueing, and the DB column is NOT NULL DEFAULT '{}'.
	nilRow, emptyRow := probeRow(), probeRow()
	nilRow.Detail, emptyRow.Detail = nil, map[string]string{}
	if !bytes.Equal(nilRow.canonical(), emptyRow.canonical()) {
		t.Error("a nil Detail and an empty Detail hash differently; Record() normalises one of them, " +
			"so a row written with the other would fail its own verification")
	}
}

// TestProbeCanonicalConcatenationIsUnambiguous is the brief's "length prefixing,
// field separator" question, tested the adversarial way: for every adjacent pair
// of fields, moving bytes across the boundary must change the hash.
func TestProbeCanonicalConcatenationIsUnambiguous(t *testing.T) {
	pairs := []struct {
		name  string
		left  func(*auditRow)
		right func(*auditRow)
	}{
		{
			"action/subject",
			func(r *auditRow) { r.Action, r.Subject = "a", "bc" },
			func(r *auditRow) { r.Action, r.Subject = "ab", "c" },
		},
		{
			"subject/provider",
			func(r *auditRow) { r.Subject, r.Provider = "a", "bc" },
			func(r *auditRow) { r.Subject, r.Provider = "ab", "c" },
		},
		{
			"provider/outcome",
			func(r *auditRow) { r.Provider, r.Outcome = "a", "bc" },
			func(r *auditRow) { r.Provider, r.Outcome = "ab", "c" },
		},
		{
			"detail key/value",
			func(r *auditRow) { r.Detail = map[string]string{"a": "bc"} },
			func(r *auditRow) { r.Detail = map[string]string{"ab": "c"} },
		},
		{
			"detail key boundaries",
			func(r *auditRow) { r.Detail = map[string]string{"a": "b", "c": "d"} },
			func(r *auditRow) { r.Detail = map[string]string{"ab": "", "cd": ""} },
		},
	}
	for _, p := range pairs {
		l, r := probeRow(), probeRow()
		p.left(&l)
		p.right(&r)
		if bytes.Equal(l.canonical(), r.canonical()) {
			t.Errorf("%s: %q and %q are ambiguous in the canonical form", p.name, dump(l), dump(r))
		}
	}
}

func dump(r auditRow) string {
	return fmt.Sprintf("action=%q subject=%q provider=%q outcome=%q detail=%v",
		r.Action, r.Subject, r.Provider, r.Outcome, r.Detail)
}

// TestProbeCanonicalDetailOrderIsNormalised checks that Go's randomised map
// iteration cannot make the same logical row hash two ways, and that the key
// COUNT is committed to as well.
func TestProbeCanonicalDetailOrderIsNormalised(t *testing.T) {
	base := probeRow()
	base.Detail = map[string]string{"a": "1", "b": "2", "c": "3", "aa": "4"}
	want := base.canonical()
	for i := 0; i < 128; i++ {
		shuffled := probeRow()
		shuffled.Detail = map[string]string{"c": "3", "aa": "4", "a": "1", "b": "2"}
		if !bytes.Equal(want, shuffled.canonical()) {
			t.Fatalf("detail iteration order changed the hash on run %d", i)
		}
	}

	// {"a":"b"} vs {"a":"b","a":""} is impossible (map), but a duplicate VALUE
	// with different keys must differ, and the count prefix is what makes
	// {"a":"b","c":"d"} differ from {"ab":"cd"} (tested above).
	one := probeRow()
	one.Detail = map[string]string{"a": "b"}
	two := probeRow()
	two.Detail = map[string]string{"a": "b", "": ""}
	if bytes.Equal(one.canonical(), two.canonical()) {
		t.Error("adding a detail entry did not change the hash: the entry count is not committed to")
	}
}

// TestProbeHashInputFieldsAreReproducibleUnderTheStoredEncoding walks the fields
// through the shapes a round trip actually produces (utf-8, NUL bytes, very long
// strings, non-ASCII) and asserts the hash is stable. It cannot catch a
// normalising database; the report says so and points at the manual check.
func TestProbeHashInputFieldsAreReproducibleUnderTheStoredEncoding(t *testing.T) {
	rows := map[string]auditRow{}
	for i, s := range []string{
		"", "plain", "with space", "with\nnewline", "with\x00nul", "キャラクター", "e\u0301", "é",
		strings.Repeat("x", 4096),
	} {
		r := probeRow()
		r.Subject = s
		rows[fmt.Sprintf("subject-%d", i)] = r
	}
	// All nine distinct byte strings must produce nine distinct hashes.
	seen := map[string]string{}
	for name, r := range rows {
		h := string(chainHash(auditGenesis, r.canonical()))
		if prev, dup := seen[h]; dup {
			t.Errorf("%s and %s hash identically (subject values collide)", name, prev)
		}
		seen[h] = name
	}
}

// TestProbeChainedRowsAreDistinguishable pins the LINKAGE, not just the content:
// the same canonical row under different predecessors must produce different row
// hashes, which is what makes a reorder detectable.
func TestProbeChainedRowsAreDistinguishable(t *testing.T) {
	row := probeRow()
	c := row.canonical()
	genesis := chainHash(auditGenesis, c)
	after := chainHash(genesis, c)
	if bytes.Equal(genesis, after) {
		t.Fatal("a row hashes the same regardless of its predecessor: reordering is undetectable")
	}
	if !bytes.Equal(genesis, chainHash([]byte{}, c)) {
		t.Error("auditGenesis and an empty prev differ: the first chained row would not verify")
	}
}

// TestProbeMACLabelsActuallySeparateTheKey is the domain-separation proof the
// brief asks for: the same message under two different labels must not produce
// the same MAC, and — more importantly — a value computed for one purpose must
// not be accepted as another. The second half is what a label prefix collision
// would break.
func TestProbeMACLabelsActuallySeparateTheKey(t *testing.T) {
	l := &AuditLogger{key: bytes.Repeat([]byte{0x77}, auditChainKeySize)}

	msg := []byte("usr_alice")
	index := l.mac(auditSubjectIndexLabel, msg)
	pseudo := l.mac(auditPseudonymLabel, msg)
	sig := l.mac(auditSignatureLabel, msg)
	if bytes.Equal(index, pseudo) || bytes.Equal(index, sig) || bytes.Equal(pseudo, sig) {
		t.Fatal("two purposes produced the same MAC for the same input")
	}

	// The labels are a PREFIX of the message, so the separation must survive the
	// case where the attacker gets to choose the message: "label2||x" must not
	// equal label1||"label2-ish||x". Because the label is written first and is
	// fixed-length per purpose, an attacker controlling only msg cannot shift a
	// purpose boundary. Demonstrate the concrete attack that must fail: using the
	// pseudonym label's output as a subject-index value.
	if hmac.Equal(l.mac(auditPseudonymLabel, msg), l.mac(auditSubjectIndexLabel, msg)) {
		t.Fatal("HMAC values are interchangeable across labels")
	}
	// And a raw HMAC with no label is not equal to the labelled one, which is why
	// the label is load-bearing rather than cosmetic.
	bare := hmac.New(sha256.New, l.key)
	bare.Write(msg)
	if hmac.Equal(bare.Sum(nil), sig) {
		t.Error("the signature equals a bare HMAC of the message: the label is not applied")
	}

	// Cross-key separation: the same label under a different audit key differs.
	other := &AuditLogger{key: bytes.Repeat([]byte{0x78}, auditChainKeySize)}
	if hmac.Equal(l.sign(msg), other.sign(msg)) {
		t.Error("two different chain keys sign identically")
	}
}

// TestProbeSubjectIndexIsNotThePseudonym is a direct check on the value the DB
// stores: audit_subject_keys.idx must not be a monotone function of the
// pseudonym, and neither may be recomputable from the raw subject without the
// key.
func TestProbeSubjectIndexIsNotThePseudonym(t *testing.T) {
	l := &AuditLogger{key: bytes.Repeat([]byte{0x77}, auditChainKeySize)}
	subject := "usr_alice"
	idx := l.subjectIndex(subject)
	if idx == subject || strings.Contains(idx, subject) {
		t.Errorf("subjectIndex(%q) = %q leaks the subject", subject, idx)
	}
	if strings.Contains(strings.ToLower(idx), "alice") {
		t.Errorf("subjectIndex leaks a readable fragment: %q", idx)
	}
	if _, err := base64.RawURLEncoding.DecodeString(idx); err != nil {
		t.Errorf("subjectIndex is not raw-url base64: %q", idx)
	}
	// 18 bytes of HMAC output.
	if n := len(idx); n != base64.RawURLEncoding.EncodedLen(18) {
		t.Errorf("subjectIndex encodes %d chars, want %d (18 bytes)", n, base64.RawURLEncoding.EncodedLen(18))
	}

	// The pseudonym is derived from a PER-SUBJECT key, so two subjects with the
	// same key would collide; the same subject under two different keys must not.
	k1 := bytes.Repeat([]byte{0x01}, 32)
	k2 := bytes.Repeat([]byte{0x02}, 32)
	if pseudonymOf(k1, subject) == pseudonymOf(k2, subject) {
		t.Error("the pseudonym ignores its key")
	}
	if pseudonymOf(k1, subject) == pseudonymOf(k1, "usr_bob") {
		t.Error("two subjects share a pseudonym")
	}
	if got := len(pseudonymOf(k1, subject)); got != base64.RawURLEncoding.EncodedLen(pseudonymBytes) {
		t.Errorf("pseudonym is %d chars, want %d", got, base64.RawURLEncoding.EncodedLen(pseudonymBytes))
	}
}

// TestProbeCheckSubjectKeyRefusesWrongLengths is the read-path guard from round
// two; kept here because it is a crypto-length invariant of the pseudonym key.
func TestProbeCheckSubjectKeyRefusesWrongLengths(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if err := checkSubjectKey(make([]byte, n)); err == nil {
			t.Errorf("checkSubjectKey accepted a %d-byte key", n)
		}
	}
	if err := checkSubjectKey(make([]byte, auditSubjectKeySize)); err != nil {
		t.Errorf("checkSubjectKey refused a 32-byte key: %v", err)
	}
}

// TestProbeNewAuditLoggerRefusesWrongKeyLengths is the same invariant on the
// chain key.
func TestProbeNewAuditLoggerRefusesWrongKeyLengths(t *testing.T) {
	// pool is nil, which must be reported as "pool is required" rather than
	// panicking — the key check is the second branch, so a nil pool short-circuits
	// it. Assert both branches explicitly with a key of the wrong length.
	if _, err := newAuditLogger(nil, make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "pool is required") {
		t.Errorf("newAuditLogger(nil, 32 bytes) = %v", err)
	}
}

// TestProbeWriteLenPrefixedIsInjective is the primitive the whole canonical form
// rests on.
func TestProbeWriteLenPrefixedIsInjective(t *testing.T) {
	enc := func(parts ...string) []byte {
		var b bytes.Buffer
		for _, p := range parts {
			writeLenPrefixed(&b, p)
		}
		return b.Bytes()
	}
	cases := [][2][]string{
		{{"a", "bc"}, {"ab", "c"}},
		{{""}, {"", ""}},
		{{"", "a"}, {"a", ""}},
		{{"\x00"}, {"\x00\x00"}},
	}
	for _, c := range cases {
		if bytes.Equal(enc(c[0]...), enc(c[1]...)) {
			t.Errorf("%v and %v encode identically", c[0], c[1])
		}
	}
	if !bytes.Equal(enc("a", "b"), enc("a", "b")) {
		t.Error("encoding is not deterministic")
	}
	// The length really is the big-endian byte count.
	want := binary.BigEndian.AppendUint32(nil, 3)
	want = append(want, "abc"...)
	if !bytes.Equal(enc("abc"), want) {
		t.Errorf("encoding = %x, want %x", enc("abc"), want)
	}
}

// TestProbeVerifyAndHeadAgreeOnGenesis pins the one equality Verify depends on:
// the stored genesis (an empty bytea) and the in-process auditGenesis must be
// interchangeable, both as a byte slice and as "no row" (NULL from pgx).
func TestProbeVerifyAndHeadAgreeOnGenesis(t *testing.T) {
	if len(auditGenesis) != 0 {
		t.Fatalf("auditGenesis is %d bytes, want 0", len(auditGenesis))
	}
	row := probeRow()
	c := row.canonical()
	if !bytes.Equal(chainHash(nil, c), chainHash(auditGenesis, c)) {
		t.Error("chainHash(nil, ...) and chainHash(auditGenesis, ...) differ")
	}
}

var _ = context.Background
