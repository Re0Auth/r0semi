package federation

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// refusingTransport fails every round trip, standing in for a source — or the
// network to it — that is unreachable.
type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func refusingRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: "https://source.example",
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		TokenEndpoint: "https://source.example/token",
		Resources:     []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// A transient transport failure while refreshing is not a dead grant: the binding
// must survive, or a network blip would force every user to bind again. This
// pins the difference between "the source is unreachable" (transient) and "the
// source rejected the refresh" (the grant is gone).
func TestRefreshTransportFailureIsTransientAndKeepsTheBinding(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBindingStore()
	v := newVault(t)
	b := backend{store: store, vault: v}
	b.bind(t, "usr_1", sourceName, "stale", "rt-1", time.Now().Add(-time.Hour))

	client := &http.Client{Transport: refusingTransport{}}
	svc := mustService(t, Config{
		Registry:   refusingRegistry(t),
		Doer:       client,
		HTTPClient: client,
		BaseURL:    "https://re0auth.test",
	}, backend{store: store, vault: v})

	if _, err := svc.Fetch(ctx, FetchRequest{User: "usr_1", Game: game, Resource: "profile"}); err == nil {
		t.Fatal("a fetch against an unreachable source returned no error")
	}
	if _, gerr := store.Get(ctx, "usr_1", game, sourceName); gerr != nil {
		t.Fatalf("a transient refresh failure removed the binding: %v", gerr)
	}
}
