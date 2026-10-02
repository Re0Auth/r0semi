package httpapi

import (
	"context"
	"net/url"
	"sort"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// W2 S11-9 probe: GET /v1/admin/clients is a paged listing.
//
// Before the fix the handler forwarded to a List that returned every client, so
// the endpoint's response size was a function of the deployment's client count
// and the documented query had no `limit`/`cursor` at all. This probe drives the
// real route: it pins that a limit bounds the page, that the cursor walks the
// whole inventory exactly once in one deterministic order, and that a bad
// limit or cursor is a 400 rather than a silent reset to the first page.
func TestW2S119AdminClientsPagination(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	// The fixture seeds "cli"; add five more so a page boundary is exercised with
	// the default (a single page) and with a limit (several pages).
	ctx := context.Background()
	want := []string{"cli"}
	for _, id := range []string{"w2-a", "w2-b", "w2-c", "w2-d", "w2-e"} {
		c, err := oauth.NewClient(id, id, oauth.ClientPublic, "",
			[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
		if err != nil {
			t.Fatal(err)
		}
		if err := env.clients.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
		want = append(want, id)
	}
	sort.Strings(want)

	// The default page (no parameters) still lists everything at this size, and it
	// is ordered by client id.
	body := decodeResp(t, getURL(t, browser, env.base+"/v1/admin/clients"))
	if got := adminIDs(t, body); !equalStrings(got, want) {
		t.Fatalf("unpaged listing = %v, want %v", got, want)
	}
	if _, present := body["next_cursor"]; present {
		t.Errorf("a last-page response carried next_cursor: %v", body["next_cursor"])
	}

	// Walk the whole listing with limit=2. Every page must be bounded by the
	// limit, the pages must concatenate to the full sorted inventory with no
	// repeat and no gap, and only the final page may omit next_cursor.
	var seen []string
	cursor := ""
	pages := 0
	for {
		target := env.base + "/v1/admin/clients?limit=2"
		if cursor != "" {
			target += "&cursor=" + url.QueryEscape(cursor)
		}
		resp := getURL(t, browser, target)
		if resp.StatusCode != 200 {
			t.Fatalf("page %d: GET %s = %d", pages+1, target, resp.StatusCode)
		}
		page := decodeResp(t, resp)
		rows := page["data"].([]any)
		if len(rows) > 2 {
			t.Errorf("page %d returned %d rows for limit=2", pages+1, len(rows))
		}
		seen = append(seen, adminIDs(t, page)...)
		pages++
		next, _ := page["next_cursor"].(string)
		if next == "" {
			break
		}
		if next == cursor {
			t.Fatalf("page %d repeated its own cursor %q", pages, next)
		}
		cursor = next
		if pages > len(want)+1 {
			t.Fatal("paging did not terminate")
		}
	}
	if pages < 2 {
		t.Fatalf("limit=2 over %d clients produced %d page(s); the page size was not applied", len(want), pages)
	}
	if !equalStrings(seen, want) {
		t.Fatalf("paged listing = %v, want %v (sorted, no repeats, no gaps)", seen, want)
	}

	// A malformed limit or a cursor this endpoint did not issue is refused. It is
	// never silently replaced by the default, which would make a paging loop
	// repeat the first page forever.
	for _, q := range []string{
		"limit=0", "limit=-1", "limit=101", "limit=abc", "limit=2.5",
		"cursor=%21%21%21", // not base64url
		"cursor=" + url.QueryEscape("bm90LWEtY3Vyc29y"), // base64, but not our payload
	} {
		resp := getURL(t, browser, env.base+"/v1/admin/clients?"+q)
		if resp.StatusCode != 400 {
			t.Errorf("GET /v1/admin/clients?%s = %d, want 400", q, resp.StatusCode)
			continue
		}
		if got := decodeResp(t, resp)["code"]; got != "invalid_request" {
			t.Errorf("GET /v1/admin/clients?%s problem code = %v, want invalid_request", q, got)
		}
	}

	// The ceiling is inclusive: exactly the maximum is a page, not a rejection.
	if resp := getURL(t, browser, env.base+"/v1/admin/clients?limit=100"); resp.StatusCode != 200 {
		t.Errorf("limit=100 = %d, want 200", resp.StatusCode)
	}
}

func adminIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	rows, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("response has no data array: %v", body)
	}
	out := make([]string, 0, len(rows))
	for _, raw := range rows {
		out = append(out, raw.(map[string]any)["client_id"].(string))
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
