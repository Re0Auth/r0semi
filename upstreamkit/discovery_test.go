package upstreamkit

import "testing"

func TestNewDiscovery(t *testing.T) {
	disc, err := NewDiscovery(Config{
		Game: "phigros", Source: "ref", DisplayName: "Reference", Issuer: "https://api.example/",
		TokenClass: TokenRevocable,
		Resources: []Resource{
			{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if disc.ProtocolVersion != 1 || disc.OAuth.TokenEndpoint != "https://api.example/oauth/token" {
		t.Fatalf("discovery = %+v", disc)
	}
	if len(disc.ScopesSupported) != 3 { // account.read + two resources
		t.Fatalf("scopes = %v", disc.ScopesSupported)
	}
	if err := disc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestNewDiscoveryRejectsBadConfig(t *testing.T) {
	base := Config{Game: "phigros", Source: "ref", DisplayName: "Ref", Issuer: "https://api.example", TokenClass: TokenRevocable}

	bad := base
	bad.Game = ""
	if _, err := NewDiscovery(bad); err == nil {
		t.Error("accepted an empty game")
	}

	bad = base
	bad.Issuer = "not-a-url"
	if _, err := NewDiscovery(bad); err == nil {
		t.Error("accepted an invalid issuer")
	}

	bad = base
	bad.TokenClass = "master"
	if _, err := NewDiscovery(bad); err == nil {
		t.Error("accepted an invalid token_class")
	}

	bad = base
	bad.Resources = []Resource{{Name: "scores", Schema: "scores/1", Scope: "phigros.score.read"}}
	if _, err := NewDiscovery(bad); err == nil {
		t.Error("accepted a non-canonical schema id")
	}

	bad = base
	bad.Resources = []Resource{{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.scores"}}
	if _, err := NewDiscovery(bad); err == nil {
		t.Error("accepted a non-canonical scope")
	}
}

func TestValidCanonicalScope(t *testing.T) {
	for _, ok := range []string{"account.read", "phigros.score.read", "phigros.b30.write", "game_a.res_1.read"} {
		if !ValidCanonicalScope(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "phigros", "phigros.score", "phigros.score.delete", "Phigros.Score.read", "phigros..read"} {
		if ValidCanonicalScope(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
