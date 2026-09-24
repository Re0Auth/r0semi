package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/federation"
)

// rawBody reads a response body verbatim. The credential non-leak test needs the
// actual bytes, not a decoded map: a secret could hide in a key or a nested field
// that a typed decode would drop.
func rawBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestExportAccountOmitsCredentials is the assertion this endpoint is judged on:
// the export must not contain an upstream credential.
//
// It is written to be non-vacuous. It seeds a binding whose vault secret really is
// a known string, then asserts (a) the binding DOES appear in the export — so the
// export is not simply empty — and (b) no credential-shaped string appears
// anywhere in the serialized document. A test that only checked "no credential"
// over an empty export would prove nothing.
func TestExportAccountOmitsCredentials(t *testing.T) {
	base, browser, accounts, bindings, _, _, v := newBindEnv(t)
	signIn(t, browser, base)

	uid, err := accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	b := federation.Binding{User: uid, Game: "phigros", Source: "fake", TokenType: "Bearer", HasRefresh: true}
	if err := bindings.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	// The real secret, in the vault, under the binding's identity — so there is
	// something for the export to leak if the wiring is wrong.
	const secret = "up-secret-token-vault-only"
	seedBindingSecret(t, v, b, secret)

	resp := getURL(t, browser, base+"/v1/account/export")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d", resp.StatusCode)
	}
	raw := rawBody(t, resp)

	// (a) Non-vacuous: the seeded binding is present.
	if !strings.Contains(raw, `"phigros"`) {
		t.Fatalf("the export does not mention the seeded binding, so it proves nothing:\n%s", raw)
	}
	if !strings.Contains(raw, `"has_refresh":true`) {
		t.Fatalf("the seeded binding's metadata is missing:\n%s", raw)
	}
	// (b) The credential, and any credential-shaped field, must be absent.
	for _, forbidden := range []string{
		secret, "access_token", "refresh_token", "wrapped_dek", "WrappedDEK", "ciphertext",
	} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("the export contains %q:\n%s", forbidden, raw)
		}
	}
}

// TestExportAccountSaysCredentialsAreExcluded: the omission must be stated in the
// document, so a reader can tell a decision from a bug.
func TestExportAccountSaysCredentialsAreExcluded(t *testing.T) {
	base, browser, _, _, _, _, _ := newBindEnv(t)
	signIn(t, browser, base)

	body := decodeResp(t, getURL(t, browser, base+"/v1/account/export"))
	notice, ok := body["notice"].(map[string]any)
	if !ok {
		t.Fatalf("no notice in the export: %v", body)
	}
	if notice["credentials_excluded"] != true {
		t.Errorf("credentials_excluded = %v, want true", notice["credentials_excluded"])
	}
	if reason, _ := notice["reason"].(string); reason == "" {
		t.Error("the notice gives no reason")
	}
}

// TestExportAccountIncludesTheAccountShape checks the positive content: the
// profile is this account, and every section is present even when empty, so the
// document's shape does not depend on what the account happens to hold.
func TestExportAccountIncludesTheAccountShape(t *testing.T) {
	base, browser, accounts, _, _, _, _ := newBindEnv(t)
	signIn(t, browser, base)

	uid, err := accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}

	resp := getURL(t, browser, base+"/v1/account/export")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	body := decodeResp(t, resp)

	profile, ok := body["profile"].(map[string]any)
	if !ok || profile["user_id"] != string(uid) {
		t.Errorf("profile = %v, want user_id %s", body["profile"], uid)
	}
	for _, section := range []string{"identities", "bindings", "grants"} {
		if _, ok := body[section].([]any); !ok {
			t.Errorf("%s missing or not a list: %v", section, body[section])
		}
	}
	if _, err := json.Marshal(body); err != nil {
		t.Fatal(err)
	}
}

// TestExportAccountRequiresASession: it is session-scoped, so no session is 401.
func TestExportAccountRequiresASession(t *testing.T) {
	base, _, _, _, _, _, _ := newBindEnv(t)
	resp := getURL(t, newBrowser(t), base+"/v1/account/export")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
