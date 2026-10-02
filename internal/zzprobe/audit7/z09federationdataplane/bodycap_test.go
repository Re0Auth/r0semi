//go:build audit7

// Z09-2: the NORMALIZED read path has no "past the cap" verdict.
//
// Commit 18fed92 (round 4) fixed exactly this on the raw path: `io.ReadAll` over
// `io.LimitReader(..., maxBody+1)` plus `len(body) > maxBody` → ErrResponseTooLarge,
// with the comment "a truncated body returned as a complete 200 claims a
// completeness it does not have". The same commit's note says the normalized path
// "cannot have this problem: its body has to parse as JSON, and a cut one does
// not".
//
// That reasoning does not hold: `json.Valid` accepts *trailing whitespace*, so a
// body whose first 4 MiB are a complete JSON value followed by padding is cut
// mid-padding and still parses. The path reads with
// `io.ReadAll(io.LimitReader(resp.Body, maxBody))` and never compares the length to
// the cap, so the truncated body is handed back as a complete 200.
package zzprobe_z09federationdataplane

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

func TestZ09NormalizedReadServesAnOverCapBodyAsComplete(t *testing.T) {
	const pad = 5 << 20
	const head = `{"served_by":"padded"}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, head)
		_, _ = io.WriteString(w, strings.Repeat(" ", pad))
	}))
	t.Cleanup(up.Close)

	reg, err := federation.NewRegistry(federation.Source{
		Game: zzGame, Name: "src", Issuer: up.URL, RawBase: up.URL + "/native",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzProfileScope},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, mint := zzHarness(t, reg, []zzBind{
		{User: "usr_v", Game: zzGame, Source: "src", Access: "upstream-token"},
	}, nil)
	at := mint("usr_v", zzProfileScope)
	// The raw path needs its own explicit scope since Z20-2; a profile-only token
	// would be refused by the scope gate before the body cap is reached.
	atRaw := mint("usr_v", oauth.RawScope(zzGame))

	// The normalized read. The upstream wrote head+pad bytes; the cap is 4 MiB.
	code, _, body := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/profile", at)
	written := int64(len(head) + pad)
	t.Logf("normalized: upstream wrote %d bytes, cap is %d, caller got %d: status=%d json.Valid=%v",
		written, zzMaxBody, len(body), code, json.Valid(body))

	if code == http.StatusOK {
		if int64(len(body)) >= written {
			t.Fatalf("the caller received the whole body, so this probe is not about truncation")
		}
		t.Errorf("the normalized path answered 200 with a TRUNCATED body (%d of %d bytes) and no signal "+
			"that anything was cut. The raw path refuses the same body (control below); this path reads with "+
			"io.LimitReader(..., maxBody) and never compares the result to the cap, and the justification for "+
			"that (\"a cut body does not parse as JSON\") is false for a value followed by whitespace",
			len(body), written)
	}

	// Control: the same upstream, the same body, the raw passthrough. This is the
	// commit-18fed92 verdict, and it is what the normalized path lacks.
	codeRaw, _, rawBody := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/sources/src/raw/data", atRaw)
	t.Logf("raw control: status=%d bytes=%d body=%s", codeRaw, len(rawBody), firstN(rawBody, 120))
	if codeRaw == http.StatusOK {
		t.Errorf("the raw control answered 200 too, so the two paths do not differ and this probe proves " +
			"nothing about which one has the cap verdict")
	}
}

func firstN(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
