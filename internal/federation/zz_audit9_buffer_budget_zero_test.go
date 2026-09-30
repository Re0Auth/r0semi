package federation

import (
	"net/http"
	"testing"
)

// AUDIT9 / S08-8 — an explicitly configured MaxBufferedBytes = 0 is coerced to
// the 64 MiB house default.
//
// cmd/re0auth carries the operator's value through as a chosen 0 (config.go:556-571
// only substitutes for the -1 sentinel), but NewService treats 0 as "unset"
// (service.go:382-383) and replaces it with defaultMaxBufferedBytes. So the value
// is neither applied nor refused: the operator's setting looks applied and is not,
// and the two layers disagree about what 0 means (newBufferBudget would treat a 0
// limit as fail-closed).
//
// Guard: pins the coercion. It fails once 0 is honoured (limit == 0) or refused at
// construction, which is the recommended fix.
func TestAudit9ZeroBufferBudgetIsCoercedToTheDefault(t *testing.T) {
	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: "https://upstream.example",
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{
		Registry: reg, Bindings: NewMemoryBindingStore(), Vault: newVault(t),
		Doer: http.DefaultClient, HTTPClient: http.DefaultClient,
		BaseURL: "https://re0auth.test",
		// The operator asked for a zero-byte budget, which is a fail-closed value.
		MaxBufferedBytes: 0,
	})
	if err != nil {
		t.Fatalf("NewService with MaxBufferedBytes = 0: %v", err)
	}
	s, ok := svc.(*service)
	if !ok {
		t.Fatalf("service type = %T", svc)
	}
	if s.buffers.limit != defaultMaxBufferedBytes {
		t.Fatalf("buffer limit = %d, want the %d-byte default (the configured 0 was "+
			"silently coerced)", s.buffers.limit, defaultMaxBufferedBytes)
	}
	if s.buffers.limit == 0 {
		t.Fatal("the configured 0 was honoured; S08-8 appears fixed, update this guard")
	}
}
