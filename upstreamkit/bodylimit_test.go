package upstreamkit_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// A source's endpoints take the same tiny bodies Re0Auth's do, so they get the
// same cap — and the refusal comes back in the shape this server speaks, because
// a client that parses OAuth errors here should not meet an exception.
func TestBodyLimitOnTheKit(t *testing.T) {
	base, _ := cascadeKit(t, false)

	resp, err := http.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {strings.Repeat("x", oauth.MaxFormBytes+1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized token request = %d, want 413", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] == nil {
		t.Fatalf("refusal was not an OAuth error: %v", body)
	}
}

// And an ordinary request still reaches the endpoint, so the cap is not in the
// way of the thing it is meant to protect.
func TestBodyLimitLetsTheKitServeNormally(t *testing.T) {
	base, _ := cascadeKit(t, false)
	resp, err := http.Get(base + "/.well-known/re0auth-upstream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery = %d, want 200", resp.StatusCode)
	}
}
