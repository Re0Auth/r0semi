package account

import (
	"context"
	"errors"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
)

func ident(provider idp.Provider, subject string) idp.Identity {
	return idp.Identity{Provider: provider, Subject: subject, DisplayName: subject}
}

func TestCreateAndFind(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	user, linked, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1"))
	if err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || user.PrimaryIdentity != linked.ID || linked.User != user.ID {
		t.Fatalf("user = %+v identity = %+v", user, linked)
	}

	found, err := s.FindByIdentity(ctx, idp.GitHub, "gh-1")
	if err != nil || found != user.ID {
		t.Fatalf("find = %q, %v", found, err)
	}
	if _, err := s.FindByIdentity(ctx, idp.GitHub, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	list, err := s.Identities(ctx, user.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("identities = %v, %v", list, err)
	}
}

func TestCreateRejectsDuplicateIdentity(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if _, _, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1")); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("err = %v, want ErrIdentityTaken", err)
	}
}

func TestLinkIdentity(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	user, first, _ := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1"))

	second, err := s.LinkIdentity(ctx, user.ID, ident(idp.Google, "go-1"))
	if err != nil {
		t.Fatal(err)
	}
	if second.User != user.ID || second.ID == first.ID {
		t.Fatalf("second = %+v", second)
	}

	// Re-linking the same identity to the same user is idempotent.
	again, err := s.LinkIdentity(ctx, user.ID, ident(idp.Google, "go-1"))
	if err != nil || again.ID != second.ID {
		t.Fatalf("idempotent link = %+v, %v", again, err)
	}
	if list, _ := s.Identities(ctx, user.ID); len(list) != 2 {
		t.Fatalf("identities = %d, want 2", len(list))
	}
}

// I-3: an identity already owned by another user is never linked.
func TestLinkRejectsIdentityOwnedByAnotherUser(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	alice, _, _ := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-alice"))
	if _, _, err := s.CreateWithIdentity(ctx, ident(idp.Google, "go-bob")); err != nil {
		t.Fatal(err)
	}

	if _, err := s.LinkIdentity(ctx, alice.ID, ident(idp.Google, "go-bob")); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("err = %v, want ErrIdentityTaken", err)
	}
}

// I-2: the last identity cannot be unlinked.
func TestUnlinkRejectsLastIdentity(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	user, only, _ := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1"))

	if err := s.UnlinkIdentity(ctx, user.ID, only.ID); !errors.Is(err, ErrLastIdentity) {
		t.Fatalf("err = %v, want ErrLastIdentity", err)
	}
	if list, _ := s.Identities(ctx, user.ID); len(list) != 1 {
		t.Fatalf("identity was removed despite the guard")
	}
}

func TestUnlinkReassignsPrimary(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	user, first, _ := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1"))
	second, _ := s.LinkIdentity(ctx, user.ID, ident(idp.Google, "go-1"))

	if err := s.UnlinkIdentity(ctx, user.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryIdentity != second.ID {
		t.Fatalf("primary = %q, want %q", got.PrimaryIdentity, second.ID)
	}
	if _, err := s.FindByIdentity(ctx, idp.GitHub, "gh-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlinked identity still resolvable: %v", err)
	}
}

func TestUnlinkUnknownIdentity(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	user, _, _ := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1"))
	if err := s.UnlinkIdentity(ctx, user.ID, "idn_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestTouchLogin(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	user, first, _ := s.CreateWithIdentity(ctx, ident(idp.GitHub, "gh-1"))

	if err := s.TouchLogin(ctx, idp.GitHub, "gh-1"); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Identities(ctx, user.ID)
	if !list[0].LastLoginAt.After(first.LastLoginAt) && !list[0].LastLoginAt.Equal(first.LastLoginAt) {
		t.Fatalf("LastLoginAt was not updated: %v", list[0].LastLoginAt)
	}
	if err := s.TouchLogin(ctx, idp.GitHub, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
