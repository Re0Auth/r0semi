package oauth

import (
	"context"
	"sync"
	"testing"
	"time"
)

// S14-5: refresh-family revocation and rotation are not atomic.
//
// ConsumeRefresh is atomic by itself, but the step the service performs *after*
// the claim is not: on the reuse branch it calls RevokeRefreshFamily, on the
// rotation branch it calls issue (SaveAccess then SaveRefresh). A replay that
// lands between the winner's claim and the winner's mint therefore revokes a
// family the winner then re-populates — the family is reported revoked while a
// live generation of it is created afterwards, so the thief keeps a working
// refresh/access pair for the rest of the refresh TTL.
//
// The window is a handful of instructions wide and cannot be hit by chance, so
// this probe enters it deliberately rather than racing goroutines and hoping.
// blockingRefreshStore parks the winning rotation immediately after its
// ConsumeRefresh has retired the value; the probe then runs the replay and only
// releases the winner once the replay has had its chance to revoke. With the
// family serialized (the fix) the replay cannot revoke while the winner holds
// the family, so the release cannot precede it by construction; the bounded
// select below is a scheduling guard, not the interleaving.

// blockingRefreshStore is a *MemoryStore that parks the winning claim and
// announces the replay's family revocation.
//
// It embeds *MemoryStore, so it also keeps the optional RefreshFamilyResolver
// the service uses to name the family before it claims: the serialization under
// test is the service's, not a wrapper's.
type blockingRefreshStore struct {
	*MemoryStore

	consumeOnce sync.Once
	consumed    chan struct{} // closed once the winner's claim has retired the value
	release     chan struct{} // the probe closes it to let the winner mint

	revokeOnce sync.Once
	revoked    chan struct{} // closed when a family revocation has run
}

func (s *blockingRefreshStore) ConsumeRefresh(ctx context.Context, value string) (RefreshToken, error) {
	rt, err := s.MemoryStore.ConsumeRefresh(ctx, value)
	if err == nil {
		// Only the winning claim parks. A replay gets a typed reuse error and runs
		// to completion, which is exactly the interleaving under test.
		s.consumeOnce.Do(func() {
			close(s.consumed)
			<-s.release
		})
	}
	return rt, err
}

func (s *blockingRefreshStore) RevokeRefreshFamily(ctx context.Context, familyID string) (int, error) {
	n, err := s.MemoryStore.RevokeRefreshFamily(ctx, familyID)
	s.revokeOnce.Do(func() { close(s.revoked) })
	return n, err
}

func TestConcurrentReplayCannotLeaveANewGeneration(t *testing.T) {
	svc, clients, store, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	const (
		redirect = "https://app.example/cb"
		verifier = "atomic-verifier-atomic-verifier-atomic"
	)

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "usr_1",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	racing := &blockingRefreshStore{
		MemoryStore: store,
		consumed:    make(chan struct{}),
		release:     make(chan struct{}),
		revoked:     make(chan struct{}),
	}
	impl, ok := svc.(*service)
	if !ok {
		t.Fatalf("service is %T, want *service", svc)
	}
	impl.tokens = racing

	type outcome struct {
		tok TokenResponse
		err error
	}
	winner := make(chan outcome, 1)
	go func() {
		tok, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: first.RefreshToken})
		winner <- outcome{tok, err}
	}()

	// The winner has claimed the value and is parked before it can mint.
	<-racing.consumed

	replay := make(chan error, 1)
	go func() {
		_, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: first.RefreshToken})
		replay <- err
	}()

	// Release the winner only after the replay has revoked the family — or after
	// the bound. On the defective code the replay revokes immediately and the
	// winner then repopulates the family. With the family serialized the replay
	// cannot reach RevokeRefreshFamily while the winner holds the family, so this
	// branch is guaranteed to time out; the bound only decides how long the probe
	// waits to be sure of that.
	select {
	case <-racing.revoked:
	case <-time.After(2 * time.Second):
	}
	close(racing.release)

	win := <-winner
	if win.err != nil {
		t.Fatalf("the winning rotation failed: %v", win.err)
	}
	replayErr := <-replay
	if got := protocolCode(t, replayErr); got != "invalid_grant" {
		t.Fatalf("the replay answered %q, want invalid_grant", got)
	}

	// The invariant: once the replay has been detected, no generation of the
	// family may be usable. On the defective code the winner's mint landed after
	// the revocation, so both assertions fail.
	if info, err := svc.Introspect(ctx, win.tok.AccessToken); err != nil || info.Active {
		t.Fatalf("a generation minted after the family revocation is still active: active=%v err=%v", info.Active, err)
	}
	if _, err := racing.MemoryStore.ConsumeRefresh(ctx, win.tok.RefreshToken); err == nil {
		t.Fatal("the new generation's refresh token survived the detected replay's family revocation")
	}
}

// TestReplayOfAnOlderGenerationCannotOutrunANewerRotation is the case that makes
// the turnstile per *family* rather than per value.
//
// The same-value probe above would also be fixed by locking on the presented
// token, because both requests carry that token. Here they do not: the replay
// carries the first generation's spent value while the parked rotation carries
// the second generation's live value. Only a key both generations resolve to —
// the family — serializes them, so this pins that the key really is the family.
func TestReplayOfAnOlderGenerationCannotOutrunANewerRotation(t *testing.T) {
	svc, clients, store, _, _ := newTestAS(t)
	registerClient(t, clients, "app", ClientPublic, "", []Scope{ScopeAccountID})
	ctx := context.Background()
	const (
		redirect = "https://app.example/cb"
		verifier = "generational-verifier-generational-x"
	)

	auth, err := svc.Authorize(ctx, AuthorizationRequest{
		ClientID: "app", RedirectURI: redirect, Subject: "usr_1",
		Scopes:        []Scope{ScopeAccountID},
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Exchange(ctx, CodeExchangeRequest{
		ClientID: "app", Code: auth.Code, RedirectURI: redirect, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	// One ordinary rotation, so there is an older spent value and a newer live one
	// in the same family.
	second, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}

	racing := &blockingRefreshStore{
		MemoryStore: store,
		consumed:    make(chan struct{}),
		release:     make(chan struct{}),
		revoked:     make(chan struct{}),
	}
	impl, ok := svc.(*service)
	if !ok {
		t.Fatalf("service is %T, want *service", svc)
	}
	impl.tokens = racing

	type outcome struct {
		tok TokenResponse
		err error
	}
	// The newer generation rotates; it holds the family while parked.
	newer := make(chan outcome, 1)
	go func() {
		tok, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: second.RefreshToken})
		newer <- outcome{tok, err}
	}()
	<-racing.consumed

	// The older generation is replayed. It shares the family, not the value.
	older := make(chan error, 1)
	go func() {
		_, err := svc.Refresh(ctx, RefreshRequest{ClientID: "app", RefreshToken: first.RefreshToken})
		older <- err
	}()
	select {
	case <-racing.revoked:
	case <-time.After(2 * time.Second):
	}
	close(racing.release)

	win := <-newer
	if win.err != nil {
		t.Fatalf("the newer generation's rotation failed: %v", win.err)
	}
	if got := protocolCode(t, <-older); got != "invalid_grant" {
		t.Fatalf("the older generation's replay answered %q, want invalid_grant", got)
	}
	if info, err := svc.Introspect(ctx, win.tok.AccessToken); err != nil || info.Active {
		t.Fatalf("the rotation minted after the replay's revocation is still active: active=%v err=%v", info.Active, err)
	}
	if _, err := racing.MemoryStore.ConsumeRefresh(ctx, win.tok.RefreshToken); err == nil {
		t.Fatal("a generation minted into the family after the replay's revocation survived it")
	}
}
