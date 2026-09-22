package oauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testClient(t *testing.T, id string) Client {
	t.Helper()
	c, err := NewClient(id, "Test "+id, ClientPublic, "", []string{"https://app.example/callback"}, []Scope{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A suspended client must be indistinguishable from an unregistered one at the
// protocol entrance, while remaining visible to the operator.
func TestSuspendedClientIsUnknownToProtocolAndVisibleToAdmin(t *testing.T) {
	ctx := context.Background()
	reg := NewMemoryClientRegistry()
	if err := reg.Create(ctx, testClient(t, "cli_a")); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Get(ctx, "cli_a"); err != nil {
		t.Fatalf("active client should resolve: %v", err)
	}

	if err := reg.SetStatus(ctx, "cli_a", ClientSuspended); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Get(ctx, "cli_a"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("suspended client Get = %v, want ErrClientNotFound", err)
	}

	all, err := reg.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Status != ClientSuspended {
		t.Fatalf("admin list = %+v, want the suspended client", all)
	}
}

func TestClientAdminRejectsUnknownAndBadStatus(t *testing.T) {
	ctx := context.Background()
	reg := NewMemoryClientRegistry()
	if err := reg.SetStatus(ctx, "cli_missing", ClientSuspended); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("SetStatus on unknown = %v, want ErrClientNotFound", err)
	}
	if err := reg.Create(ctx, testClient(t, "cli_a")); err != nil {
		t.Fatal(err)
	}
	if err := reg.SetStatus(ctx, "cli_a", "bogus"); err == nil {
		t.Fatal("invalid status accepted")
	}
}

func TestRestoreClientWithStatusRejectsBadStatus(t *testing.T) {
	_, err := RestoreClientWithStatus("cli_a", "A", ClientPublic, "bogus", nil, []string{"https://a/cb"}, nil, time.Time{})
	if err == nil {
		t.Fatal("invalid status accepted by RestoreClientWithStatus")
	}
}
