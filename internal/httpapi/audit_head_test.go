package httpapi

import (
	"net/http"
	"testing"
)

// The head endpoint returns the chain head as lowercase hex, so an external
// system can anchor it.
func TestAdminAuditHeadReturnsTheChainHead(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	env.audit.head = []byte{0xde, 0xad, 0xbe, 0xef}
	resp := getURL(t, browser, env.base+"/v1/admin/audit/head")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("head = %d, want 200", resp.StatusCode)
	}
	body := decodeResp(t, resp)
	if body["head"] != "deadbeef" {
		t.Fatalf("head = %v, want deadbeef", body["head"])
	}
}
