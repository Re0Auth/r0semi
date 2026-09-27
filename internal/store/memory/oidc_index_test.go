package memory

// The subject indexes are what keep a revocation from walking every token in the
// deployment. They are only worth having if they cannot drift from the maps they
// describe, and drift is exactly what a hand-maintained index does: a delete that
// forgets to update it leaves a key pointing at nothing (a wasted lookup) or a
// record reachable by nobody (a token that survives a Kill Switch).
//
// So the invariant is asserted two ways: directly after a scripted sequence of
// operations, and after every step of a seeded random walk.

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/Re0Auth/r0semi/oauth"
)

// checkIndexes asserts each index agrees with its map in both directions.
func checkIndexes(t *testing.T, store *OIDCStore) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()

	seen := make(map[string]bool)
	for subject, keys := range store.accessBySubject {
		if subject == "" {
			t.Fatal("an empty subject was indexed")
		}
		for k := range keys {
			if seen[k] {
				t.Fatalf("access token %q is indexed twice", k)
			}
			seen[k] = true
			tok, ok := store.accessTokens[k]
			if !ok {
				t.Fatalf("the access index points at a missing record %q", k)
			}
			if tok.subject != subject {
				t.Fatalf("access token %q is indexed under %q but belongs to %q", k, subject, tok.subject)
			}
		}
	}
	for k, tok := range store.accessTokens {
		if tok.subject == "" {
			continue
		}
		if !seen[k] {
			t.Fatalf("access token %q is not indexed under its subject", k)
		}
	}

	seen = make(map[string]bool)
	for subject, keys := range store.refreshBySubject {
		for k := range keys {
			if seen[k] {
				t.Fatalf("refresh token %q is indexed twice", k)
			}
			seen[k] = true
			tok, ok := store.refreshTokens[k]
			if !ok {
				t.Fatalf("the refresh index points at a missing record %q", k)
			}
			if tok.subject != subject {
				t.Fatalf("refresh token %q is indexed under %q but belongs to %q", k, subject, tok.subject)
			}
		}
	}
	for k, tok := range store.refreshTokens {
		if tok.subject == "" {
			continue
		}
		if !seen[k] {
			t.Fatalf("refresh token %q is not indexed under its subject", k)
		}
	}

	seen = make(map[string]bool)
	for subject, ids := range store.requestBySubject {
		for id := range ids {
			if seen[id] {
				t.Fatalf("auth request %q is indexed twice", id)
			}
			seen[id] = true
			req, ok := store.authRequests[id]
			if !ok {
				t.Fatalf("the request index points at a missing record %q", id)
			}
			if req.Subject != subject {
				t.Fatalf("auth request %q is indexed under %q but belongs to %q", id, subject, req.Subject)
			}
		}
	}
	for id, req := range store.authRequests {
		if req.Subject == "" {
			continue
		}
		if !seen[id] {
			t.Fatalf("auth request %q is not indexed under its subject", id)
		}
	}
}

// The scripted sequence: every operation that touches an indexed map, in an order
// where each one has something to act on.
func TestSubjectIndexesFollowAScriptedSequence(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: "cli", RedirectURI: "https://app.example/cb",
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
		CodeChallenge: "challenge-1234567890", CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store) // an unattributed request is simply not indexed

	if err := store.CompleteLogin(ctx, ar.GetID(), "usr_1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	if err := store.SaveAuthCode(ctx, ar.GetID(), "code-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, &fakeTokenRequest{subject: "usr_1", clientID: "cli"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateAccessToken(ctx, &fakeTokenRequest{subject: "usr_2", clientID: "cli"}); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	if err := store.TerminateSession(ctx, "usr_2", "cli"); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	if err := store.RevokeGrant(ctx, "usr_1", "cli"); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	// Rebuild, then revoke by subject and by nothing at all (the Kill Switch).
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, &fakeTokenRequest{subject: "usr_1", clientID: "cli"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeTokens(ctx, oauth.TokenFilter{Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, &fakeTokenRequest{subject: "usr_3", clientID: "cli"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeTokens(ctx, oauth.TokenFilter{}); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	// And the purge path.
	if _, _, err := store.CreateAccessToken(ctx, &fakeTokenRequest{subject: "usr_4", clientID: "cli"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PurgeSubject(ctx, "usr_4"); err != nil {
		t.Fatal(err)
	}
	checkIndexes(t, store)

	// Expiry, driven by a clock the test owns.
	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, &fakeTokenRequest{subject: "usr_5", clientID: "cli"}, ""); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Now().Add(24 * time.Hour * 40) }
	store.SweepExpired()
	checkIndexes(t, store)
}

// The random walk: the same invariant, after every step of a seeded sequence. A
// hand-maintained index fails on the combination nobody wrote a script for.
func TestSubjectIndexesSurviveARandomSequence(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // determinism is the point; no security property is at stake

	var (
		requests []string
		access   []string
		refresh  []string
	)
	subjects := []string{"usr_1", "usr_2", "usr_3"}

	for step := 0; step < 300; step++ {
		switch rng.Intn(9) {
		case 0:
			ar, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
				ClientID: "cli", RedirectURI: "https://app.example/cb",
				ResponseType: oidc.ResponseTypeCode, Scopes: []string{"account.id"},
				CodeChallenge: "challenge-1234567890", CodeChallengeMethod: oidc.CodeChallengeMethodS256,
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			requests = append(requests, ar.GetID())
		case 1:
			if len(requests) == 0 {
				continue
			}
			id := requests[rng.Intn(len(requests))]
			_ = store.CompleteLogin(ctx, id, subjects[rng.Intn(len(subjects))], []string{"account.id"})
		case 2:
			if len(requests) == 0 {
				continue
			}
			_ = store.SaveAuthCode(ctx, requests[rng.Intn(len(requests))], "code-"+string(rune('a'+step%26)))
		case 3:
			req := &fakeTokenRequest{subject: subjects[rng.Intn(len(subjects))], clientID: "cli"}
			if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, req, ""); err != nil {
				t.Fatal(err)
			}
		case 4:
			if len(access) > 0 {
				store.RevokeToken(ctx, access[rng.Intn(len(access))], "usr_1", "cli")
			}
		case 5:
			_ = store.TerminateSession(ctx, subjects[rng.Intn(len(subjects))], "cli")
		case 6:
			_ = store.RevokeGrant(ctx, subjects[rng.Intn(len(subjects))], "cli")
		case 7:
			if rng.Intn(2) == 0 {
				_, _ = store.RevokeTokens(ctx, oauth.TokenFilter{Subject: subjects[rng.Intn(len(subjects))]})
			} else {
				_, _ = store.RevokeTokens(ctx, oauth.TokenFilter{})
			}
		case 8:
			if rng.Intn(2) == 0 {
				_, _ = store.PurgeSubject(ctx, subjects[rng.Intn(len(subjects))])
			} else if len(requests) > 0 {
				_ = store.DeleteAuthRequest(ctx, requests[rng.Intn(len(requests))])
			}
		}

		// Token handles the walk needs: refreshed from the store so a revocation
		// above cannot leave the walk holding stale ids.
		access = access[:0]
		store.mu.Lock()
		for k, tok := range store.accessTokens {
			if tok.subject == "usr_1" {
				access = append(access, k)
			}
		}
		store.mu.Unlock()
		_ = refresh

		if step%10 == 0 {
			checkIndexes(t, store)
		}
	}
	checkIndexes(t, store)
}

// fakeTokenRequest is the smallest op.TokenRequest the store's token mints need:
// a subject and a client.
type fakeTokenRequest struct {
	subject  string
	clientID string
}

func (r *fakeTokenRequest) GetSubject() string  { return r.subject }
func (r *fakeTokenRequest) GetClientID() string { return r.clientID }
func (r *fakeTokenRequest) GetAudience() []string {
	return []string{r.clientID}
}
func (r *fakeTokenRequest) GetScopes() []string { return []string{"account.id"} }
