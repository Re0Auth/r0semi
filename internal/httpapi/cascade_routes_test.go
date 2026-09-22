package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/oauth"
)

// cascade is a write with consequences outside Re0Auth, so it needs the CSRF
// token like any other — and the account still has to be connected to ask.
func cascade(t *testing.T, base string, client *http.Client, csrf string, body any) *http.Response {
	t.Helper()
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost,
		base+"/v1/bindings/phigros/fake/cascade_revocation", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return doReq(t, client, req)
}

// The acknowledgment is the point: an operation that signs somebody out of every
// device should not be reachable without writing down that it means that.
func TestCascadeRequiresAnAcknowledgement(t *testing.T) {
	base, client, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)
	connectSource(t, base, client)
	csrf := sessionCSRF(t, base, client)

	for _, body := range []map[string]any{
		{},
		{"acknowledge": ""},
		{"acknowledge": "yes"},
		{"acknowledge": "signs_out_everywhere"},
	} {
		resp := cascade(t, base, client, csrf, body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("acknowledge %v = %d, want 400", body["acknowledge"], resp.StatusCode)
		}
		resp.Body.Close()
	}

	// And nothing happened: the binding is still there.
	if len(bindingsOf(t, base, client)) != 1 {
		t.Fatal("a refused cascade removed the binding")
	}
}

func TestCascadeRequiresCSRF(t *testing.T) {
	base, client, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)
	connectSource(t, base, client)

	resp := cascade(t, base, client, "", map[string]any{"acknowledge": cascadeAcknowledgement})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cascade without CSRF = %d, want 403", resp.StatusCode)
	}
	if len(bindingsOf(t, base, client)) != 1 {
		t.Fatal("a refused cascade removed the binding")
	}
}

// The happy path, and the part that matters: the session ends, the binding goes,
// and the client's token stops working because the authorization behind it did.
func TestCascadeEndsTheSessionAndReportsIt(t *testing.T) {
	base, client, accounts, _, as, _ := newBindEnv(t)
	signIn(t, client, base)
	connectSource(t, base, client)
	csrf := sessionCSRF(t, base, client)

	uid, err := accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	at := mintToken(t, as, "cli", string(uid), oauth.ScopePhigrosProfile)
	if resp := authedGet(t, base+"/v1/games/phigros/profile", at); resp.StatusCode != http.StatusOK {
		t.Fatalf("profile before cascade = %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	resp := cascade(t, base, client, csrf, map[string]any{"acknowledge": cascadeAcknowledgement})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cascade = %d, want 200", resp.StatusCode)
	}
	if body := decodeResp(t, resp); body["upstream"] != "done" {
		t.Fatalf("upstream = %v", body["upstream"])
	}

	if len(bindingsOf(t, base, client)) != 0 {
		t.Fatal("the binding survived a cascade")
	}
	// The upstream session is gone, and so is everything that depended on it.
	resp = authedGet(t, base+"/v1/games/phigros/profile", at)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("profile after cascade = %d, want 409", resp.StatusCode)
	}
}

// Nothing connected means there is no token, and the token is how the source is
// told whose session to end. Answering 200 here would claim a logout that never
// happened.
func TestCascadeWithoutAConnection(t *testing.T) {
	base, client, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)
	csrf := sessionCSRF(t, base, client)

	resp := cascade(t, base, client, csrf, map[string]any{"acknowledge": cascadeAcknowledgement})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cascade with nothing connected = %d, want 404", resp.StatusCode)
	}
}

// The capability is reported per binding, so the account page can leave out an
// action that would fail.
func TestBindingsReportTheCascadeCapability(t *testing.T) {
	base, client, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)
	connectSource(t, base, client)

	bindings := bindingsOf(t, base, client)
	if len(bindings) != 1 {
		t.Fatalf("bindings = %v", bindings)
	}
	if bindings[0]["cascade_revocation"] != true {
		t.Fatalf("cascade_revocation = %v, want true for a source that was declared able",
			bindings[0]["cascade_revocation"])
	}
}
