package postgres

// p3_low_source_guard_test.go is the database-free half of the P3-low batch:
// S03-8, S03-10, S09-3, S09-5, S09-6, S09-7, S09-8, S09-9, S09-10, S11-7,
// Z10-1, Z10-2, Z10-9, G-14 and G-17.
//
// Every claim below is about which statement or predicate the adapter issues, so
// it is decided by reading the shipped source and the shipped migrations — the
// same shape refresh_family_guard_test.go and migration_lock_guard_test.go use.
// Where a behaviour is runtime-decidable without Postgres (the pseudonym cache's
// bound, TTL, trimming and cached miss) it is asserted directly in
// auditpseudo_test.go instead; where a live database is required (the device
// audit rows, the chain walk) the CI Postgres service runs the integration tests
// in oidc_test.go, postgres_test.go and auditchain_test.go.

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// sourceOf reads one adapter source file. It fails the test rather than skipping,
// because every guard below is vacuous if the file it reads is not the shipped one.
func sourceOf(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("cannot read the adapter source %s: %v", name, err)
	}
	if len(body) == 0 {
		t.Fatalf("%s is empty", name)
	}
	return string(body)
}

// receiverMethod returns the source of the method named name on any receiver, from
// its func line to the next top-level declaration.
func receiverMethod(t *testing.T, src, file, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func \([^)]*\) ` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("%s: method %s not found; the guard is reading the wrong text", file, name)
	}
	rest := src[loc[0]:]
	if next := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:]); next != nil {
		rest = rest[:next[0]+1]
	}
	return rest
}

// migrationOf reads one shipped migration out of the embedded FS, so the guards
// below cannot read a file the migration runner would not.
func migrationOf(t *testing.T, name string) string {
	t.Helper()
	body, err := fs.ReadFile(migrationsFS, "migrations/"+name)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(body)
}

// TestIdentitiesDoesNotProbeExistenceBeforeTheRead pins S03-8: the ordinary case
// (an account with identities) must be one round trip, not two. The
// account-existence probe may only run when the rows came back empty.
func TestIdentitiesDoesNotProbeExistenceBeforeTheRead(t *testing.T) {
	body := receiverMethod(t, sourceOf(t, "account.go"), "account.go", "Identities")

	read := strings.Index(body, "FROM accounts_identities WHERE user_id = $1")
	if read < 0 {
		t.Fatal("Identities no longer reads accounts_identities; the guard is reading the wrong method")
	}
	probe := strings.Index(body, "SELECT EXISTS (SELECT 1 FROM accounts_users")
	if probe < 0 {
		t.Fatal("Identities no longer probes accounts_users at all; the not-found answer would be lost")
	}
	if probe < read {
		t.Error("Identities still runs the EXISTS probe before the real SELECT: the common case pays two " +
			"round trips for one answer (S03-8)")
	}
	if !strings.Contains(body, "if len(out) > 0 {") {
		t.Error("Identities does not return the rows before consulting the existence probe, so the probe " +
			"still runs on every call (S03-8)")
	}
}

// TestUnlinkIdentityClassifiesTheDatabaseError pins S09-3: ownership may not be
// tested before err, or a connection error is answered as ErrNotFound.
func TestUnlinkIdentityClassifiesTheDatabaseError(t *testing.T) {
	body := receiverMethod(t, sourceOf(t, "account.go"), "account.go", "UnlinkIdentity")

	if strings.Contains(flatten(body), "if noRows(err) || account.UserID(owner) != user") {
		t.Error("UnlinkIdentity tests ownership before the error: any database error is reported as " +
			"ErrNotFound (S09-3)")
	}
	if !strings.Contains(flatten(body), "if noRows(err) { return account.ErrNotFound }") {
		t.Error("UnlinkIdentity no longer returns ErrNotFound for the pgx.ErrNoRows case specifically")
	}
}

// TestKillSwitchSessionDeletesAreTransactionalAndBounded pins S03-10 and S09-8:
// both session halves run in one transaction, and the all-sessions delete is
// issued in bounded batches rather than as one statement that a statement_timeout
// can cancel halfway.
func TestKillSwitchSessionDeletesAreTransactionalAndBounded(t *testing.T) {
	body := sourceOf(t, "sessions.go")

	for _, name := range []string{"RevokeAllSessions", "RevokeSubjectSessions"} {
		method := receiverMethod(t, body, "sessions.go", name)
		if !strings.Contains(method, ".Begin(") {
			t.Errorf("Sessions.%s issues its two deletes without a transaction: a partial application leaves "+
				"a session and its index row out of step (S03-10, S09-8)", name)
		}
		if !strings.Contains(method, "tx.Commit(") {
			t.Errorf("Sessions.%s no longer commits its transaction", name)
		}
	}
	if !strings.Contains(body, "ctid IN (SELECT ctid FROM ") {
		t.Error("the all-sessions delete is no longer batched: one unbounded DELETE can be cancelled by the " +
			"pool's statement_timeout, leaving the Kill Switch unapplied (S03-10)")
	}
	if !strings.Contains(body, "sessionSweepBatchSize") {
		t.Error("the revoke batches no longer share the sweep's bound")
	}
}

// TestLegacyMultiStatementDeletesAreTransactional pins the other half of S09-8 in
// oauth.go: DeleteRefresh and PurgeLegacySubject each issue two writes, and a
// partial application is not a state a retry can distinguish from success.
func TestLegacyMultiStatementDeletesAreTransactional(t *testing.T) {
	body := sourceOf(t, "oauth.go")
	for _, name := range []string{"DeleteRefresh", "PurgeLegacySubject"} {
		method := receiverMethod(t, body, "oauth.go", name)
		if !strings.Contains(method, ".Begin(") {
			t.Errorf("Tokens.%s issues two deletes without a transaction (S09-8)", name)
		}
	}
}

// TestVerifyComparesTheWalkedTailToTheChainHead pins S09-6 and Z10-9: the head is
// read as a witness and must be compared to the last chained row, or a deleted
// tail still verifies.
func TestVerifyComparesTheWalkedTailToTheChainHead(t *testing.T) {
	method := receiverMethod(t, sourceOf(t, "auditchain.go"), "auditchain.go", "Verify")

	if !strings.Contains(flatten(method), "!bytes.Equal(prev, head)") {
		t.Error("Verify reads the chain head but never compares it to the last chained row it walked: rows " +
			"deleted from the end of the chain leave the head pointing at a hash no row owns, and the walk " +
			"still answers ok (S09-6, Z10-9)")
	}
	if !strings.Contains(method, "rows were removed from the end of the chain") {
		t.Error("Verify's refusal does not name the tail truncation it detected")
	}
	if !strings.Contains(method, "head_hash, legacy_ceiling_id FROM audit_chain") {
		t.Error("Verify no longer reads the legacy ceiling with the head")
	}
	if !strings.Contains(method, "SET LOCAL TRANSACTION ISOLATION LEVEL REPEATABLE READ") {
		t.Error("Verify does not take one snapshot for the head and the row walk: under READ COMMITTED an " +
			"append committing between the two reads makes the head point past the walked tail, which the " +
			"comparison would report as a truncated chain")
	}
}

// TestVerifyBoundsLegacyRowsAtTheSealedCeiling pins Z10-2: a row with a NULL hash
// is only "legacy" if its id is at or below the ceiling migration 0030 recorded.
// A ceiling of 0 means nothing was ever sealed as pre-chain, so no NULL-hash row
// can be legacy — the id comparison alone accepted a forged row at id 0, where
// `id > 0` is false (see TestVerifyRejectsAnUnchainedRowWithNoSealedCeiling).
func TestVerifyBoundsLegacyRowsAtTheSealedCeiling(t *testing.T) {
	method := receiverMethod(t, sourceOf(t, "auditchain.go"), "auditchain.go", "Verify")
	if !strings.Contains(flatten(method), "if legacyCeiling == 0 || id > legacyCeiling {") {
		t.Error("Verify does not reject a NULL-hash row when no legacy ceiling was sealed, nor past one " +
			"that was: an unsigned row inserted after the seal — or at id 0 while the ceiling is still 0 — " +
			"is reported as a migration-era row (Z10-2)")
	}

	migration := migrationOf(t, "0030_audit_legacy_ceiling.sql")
	if !strings.Contains(migration, "ADD COLUMN IF NOT EXISTS legacy_ceiling_id bigint NOT NULL DEFAULT 0") {
		t.Error("0030 does not add audit_chain.legacy_ceiling_id in the idempotent form")
	}
	if !strings.Contains(migration, "max(id) FROM audit_events WHERE row_hash IS NULL") {
		t.Error("0030 does not compute the ceiling from the unchained rows present when it runs")
	}
	if !strings.Contains(migration, "-- +goose Down") ||
		!strings.Contains(migration, "DROP COLUMN IF EXISTS legacy_ceiling_id") {
		t.Error("0030's Down does not remove the column it added")
	}
}

// TestVerifyRejectsAnUnchainedRowWithNoSealedCeiling pins the residual Z10-2 case
// the ceiling comparison alone missed.
//
// legacy_ceiling_id is 0 both on a log that never had a pre-chain row and on a
// chain that has not started. A writer with DB write access can plant a row at
// id 0 with OVERRIDING SYSTEM VALUE; `id > legacyCeiling` is then `0 > 0`, false,
// and because no chained row has been walked yet the row was counted as legacy
// and the walk answered ok. Every genuine migration-era row has id >= 1 and was
// present when 0030 sealed the ceiling, so requiring a non-zero ceiling cannot
// misclassify one.
func TestVerifyRejectsAnUnchainedRowWithNoSealedCeiling(t *testing.T) {
	method := receiverMethod(t, sourceOf(t, "auditchain.go"), "auditchain.go", "Verify")
	if !strings.Contains(flatten(method), "if legacyCeiling == 0 || id > legacyCeiling {") {
		t.Error("Verify still accepts a NULL-hash row while legacy_ceiling_id is 0: the id-0 row a writer " +
			"can plant with OVERRIDING SYSTEM VALUE has `id > 0` false and is blessed as a migration-era " +
			"row (Z10-2)")
	}
	if !strings.Contains(flatten(method), "legacy ceiling") {
		t.Error("Verify's refusal does not name the legacy ceiling it detected")
	}
}

// TestCodeAndDeviceMissesAreNotStoreOutages pins S09-7 on the two paths the
// finding names: the authorization-code claim and the device-state read must
// classify pgx.ErrNoRows, and every other error must travel with its cause.
func TestCodeAndDeviceMissesAreNotStoreOutages(t *testing.T) {
	body := sourceOf(t, "oidc.go")

	code := oidcStoreMethod(t, body, "AuthRequestByCode")
	if !strings.Contains(flatten(code), "if noRows(err) { return nil, errors.New(\"postgres: authorization code is unknown or expired\") }") {
		t.Error("AuthRequestByCode does not return its protocol answer only for pgx.ErrNoRows: a database " +
			"outage is collapsed into invalid_grant (S09-7)")
	}
	if strings.Count(code, "claim authorization code: %w") != 1 {
		t.Error("AuthRequestByCode does not preserve the database cause of a failed code claim (S09-7)")
	}

	device := oidcStoreMethod(t, body, "deviceState")
	if !strings.Contains(device, "oauth.ErrDeviceNotFound") {
		t.Error("deviceState no longer maps a missing row to oauth.ErrDeviceNotFound")
	}
	if strings.Count(device, "device authorization: %w") != 2 {
		t.Error("deviceState does not wrap both the query error and the non-noRows collect error, so a store " +
			"outage is indistinguishable from an unknown device code (S09-7)")
	}

	for _, name := range []string{"DescribeDeviceAuthorization", "DecideDeviceAuthorization"} {
		method := oidcStoreMethod(t, body, name)
		if strings.Contains(method, "if err != nil || st.Done") {
			t.Errorf("%s collapses a store failure into ErrDeviceNotFound: the err branch must return the "+
				"store error and only the state checks map to not-found (S09-7)", name)
		}
		if !strings.Contains(method, "if err != nil {") {
			t.Errorf("%s no longer separates the store error from the state checks (S09-7)", name)
		}
	}
}

// TestOPTokenTimesComeFromTheStoreClock pins S09-10: issued_at is written by the
// store's clock like expires_at, not by the column default's now().
func TestOPTokenTimesComeFromTheStoreClock(t *testing.T) {
	body := sourceOf(t, "oidc.go")
	if strings.Contains(body, "INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, expires_at)") {
		t.Error("an oidc_access_tokens insert still omits issued_at, so the database's now() supplies a value " +
			"the rest of the store judges with its own clock (S09-10)")
	}
	if n := strings.Count(body, "INSERT INTO oidc_access_tokens (id_hash, client_id, subject, scopes, issued_at, expires_at)"); n != 2 {
		t.Errorf("found %d oidc_access_tokens inserts that name issued_at, want 2 (S09-10)", n)
	}
	if !strings.Contains(body, "(token_hash, id_hash, client_id, subject, scopes, amr, audience, auth_time, nonce, family_id, issued_at, expires_at)") {
		t.Error("the oidc_refresh_tokens insert still omits issued_at (S09-10)")
	}
}

// TestDeviceDecisionsAuditTheClient pins G-17: both device decisions must carry
// the client the code was issued to out of the write and into the record, the way
// the memory backend does.
func TestDeviceDecisionsAuditTheClient(t *testing.T) {
	body := sourceOf(t, "oidc.go")

	approve := oidcStoreMethod(t, body, "ApproveDevice")
	if !strings.Contains(approve, "RETURNING client_id") {
		t.Error("ApproveDevice does not return the client_id it just approved, so its audit row cannot name " +
			"the client (G-17)")
	}
	if strings.Contains(approve, `s.record(ctx, "oidc.device.approve", subject, ""`) {
		t.Error("ApproveDevice still records an empty client_id (G-17)")
	}

	deny := oidcStoreMethod(t, body, "DenyDevice")
	if !strings.Contains(deny, "RETURNING client_id") {
		t.Error("DenyDevice does not return the client_id it just denied (G-17)")
	}
	if strings.Contains(deny, `s.record(ctx, "oidc.device.deny", "", ""`) {
		t.Error("DenyDevice still records an empty client_id (G-17)")
	}
}

// TestRevokeTokensTouchesTheIndexedOidcDevicesTable pins G-14 from the migration
// side: OIDCStore.RevokeTokens runs a client-only filter over oidc_devices, so
// that table needs a leading client_id index. The in-package guard
// TestClientScopedRevokeIsIndexed proves the schema carries it; this proves the
// predicate is really there, so the guard cannot pass over a table nothing
// filters by client_id.
func TestRevokeTokensTouchesTheIndexedOidcDevicesTable(t *testing.T) {
	body := sourceOf(t, "oidc.go")
	revoke := oidcStoreMethod(t, body, "RevokeTokens")
	if !strings.Contains(revoke, `revokeMatching(ctx, tx, []string{"oidc_devices"}, f)`) {
		t.Error("RevokeTokens no longer deletes device authorizations through revokeMatching; if the predicate " +
			"moved, the G-14 index guard's premise changed")
	}
	migration := migrationOf(t, "0029_oidc_devices_client_idx.sql")
	if !strings.Contains(migration, "CREATE INDEX oidc_devices_client_idx ON oidc_devices (client_id);") {
		t.Error("0029 does not create a leading client_id index on oidc_devices (G-14)")
	}
	if !strings.Contains(migration, "DROP INDEX IF EXISTS oidc_devices_client_idx;") {
		t.Error("0029's Down does not drop the index it created")
	}
}

// TestPseudonymCacheIsAgedAndTrimmedNotReset pins S09-9, S11-7 and Z10-1 on the
// source side: the cache carries an expiry, caches the negative answer, and is
// trimmed rather than emptied at its bound.
func TestPseudonymCacheIsAgedAndTrimmedNotReset(t *testing.T) {
	body := sourceOf(t, "auditpseudo.go")

	if !strings.Contains(body, "expires: l.now().Add(pseudoCacheTTL)") {
		t.Error("cache entries carry no expiry: a replica that was not told about an erasure keeps resolving " +
			"the erased subject forever (Z10-1)")
	}
	if !strings.Contains(body, "l.remember(subject, nil)") {
		t.Error("a subject with no key row is not cached, so the negative lookup is repeated per call and its " +
			"timing differs from a warm key (S11-7)")
	}
	if strings.Contains(body, "l.cache = make(map[string]cachedSubjectKey") {
		t.Error("the cache is still dropped wholesale at its bound: every subject in the next burst becomes a " +
			"miss on the vault's fail-closed path (S09-9)")
	}
	if !strings.Contains(body, "func (l *AuditLogger) trimLocked()") ||
		!strings.Contains(flatten(body), "len(l.cache) / 4") {
		t.Error("the bound is no longer enforced by a partial trim (S09-9)")
	}
}

// TestConsumeRefreshExpiryIsStillTheServicesJob pins S09-4 as an open
// decision rather than a fix: the PG store claims an expired live value (no
// expires_at predicate), and oauth/tokens.go documents that expiry is judged by
// the service, which oauth/as.go does after the claim. Closing the gap means
// choosing between those two statements, and would also have to change the memory
// backend to keep the two implementations of one interface in step. This guard
// fails on EITHER change so the choice is made deliberately and the contract text
// is updated with it.
func TestConsumeRefreshExpiryIsStillTheServicesJob(t *testing.T) {
	consume := receiverMethod(t, sourceOf(t, "oauth.go"), "oauth.go", "ConsumeRefresh")
	if regexp.MustCompile(`DELETE FROM oauth_refresh_tokens\s+WHERE token_hash = \$1 AND expires_at`).MatchString(consume) {
		t.Fatal("ConsumeRefresh now filters by expires_at (S09-4 appears fixed): re-decide the contract — " +
			"oauth/tokens.go says expiry is judged by the service, and internal/store/memory must match or " +
			"the two backends of one interface disagree")
	}
	contract, err := os.ReadFile("../../../oauth/tokens.go")
	if err != nil {
		t.Skipf("cannot read the public contract text: %v", err)
	}
	if !strings.Contains(string(contract), "expiry is judged by the service, not the store") {
		t.Fatal("the Store contract no longer says expiry is judged by the service: update this guard and " +
			"S09-4's disposition together")
	}
}

// flatten collapses whitespace so a guard is not defeated by line wrapping.
func flatten(s string) string { return strings.Join(strings.Fields(s), " ") }
