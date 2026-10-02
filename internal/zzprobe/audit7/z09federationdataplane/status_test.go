//go:build audit7

// Z09-1 regression guard (round 7, fixed): `sources[].status` is validated at
// the registry.
//
// The original defect: `docs/upstream-protocol.md` §10 fixes the lifecycle
// vocabulary as `active | degraded | retired`, but `NewRegistry` only defaulted
// an empty value and `statusRank`'s `default:` branch kept every other spelling
// selectable. The only thing that retired a source was an exact string
// comparison against "retired", so `Retired`, `retired ` or `disabled` kept
// answering reads — and kept deciding another source's scope gate. `token_class`
// had been validated at that same call since CS-4, for exactly this reason.
//
// This file used to assert the defect. It now asserts the fix, in the same
// three shapes the finding named: the registry refuses a spelling outside the
// vocabulary, it still accepts the four legal values, and a source that really
// is `retired` is still never served.
package zzprobe_z09federationdataplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
)

const (
	zzGame         = "phigros"
	zzProfileScope = "phigros.profile.read"
)

// zzStatusSource is a real upstream that answers the normalized resource path.
func zzStatusSource(t *testing.T, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// zzStatusRegistry builds a one-source registry. It is only used with values
// inside the vocabulary; the refusal cases call NewRegistry directly.
func zzStatusRegistry(t *testing.T, up string, status federation.SourceStatus) *federation.Registry {
	t.Helper()
	reg, err := federation.NewRegistry(federation.Source{
		Game: zzGame, Name: "src", DisplayName: "Src", Issuer: up,
		Status: status,
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzProfileScope},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry refused the in-vocabulary status %q: %v", status, err)
	}
	return reg
}

// TestZ09StatusOutsideTheLifecycleVocabularyIsRefused: every spelling an
// operator might reach for instead of the documented one is an error at the
// registry, named as a status problem — not a source that quietly stays live.
func TestZ09StatusOutsideTheLifecycleVocabularyIsRefused(t *testing.T) {
	for _, s := range []federation.SourceStatus{
		"Retired", "retired ", " RETIRED", "disabled", "off", "Active", "DEGRADED", "degraded ", "0",
	} {
		_, err := federation.NewRegistry(federation.Source{
			Game: zzGame, Name: "src", Issuer: "https://src.example",
			Status:    s,
			Resources: []federation.Resource{{Name: "profile", Scope: zzProfileScope}},
		})
		if err == nil {
			t.Errorf("NewRegistry accepted status %q. The vocabulary is active|degraded|retired "+
				"(docs/upstream-protocol.md §10), and the rest of the package reads an unrecognised value "+
				"as a selectable source that still decides the scope gate", s)
			continue
		}
		if !strings.Contains(err.Error(), "status") || !strings.Contains(err.Error(), string(s)) {
			t.Errorf("status %q was refused, but the error does not name the field and the value, which is "+
				"what makes it fixable at startup: %v", s, err)
		}
	}
}

// TestZ09TheLifecycleVocabularyIsStillAccepted: the check is a gate on the
// vocabulary, not a blanket refusal. An unset status is still active.
func TestZ09TheLifecycleVocabularyIsStillAccepted(t *testing.T) {
	for _, tc := range []struct {
		in   federation.SourceStatus
		want federation.SourceStatus
	}{
		{"", federation.StatusActive},
		{federation.StatusActive, federation.StatusActive},
		{federation.StatusDegraded, federation.StatusDegraded},
		{federation.StatusRetired, federation.StatusRetired},
	} {
		reg := zzStatusRegistry(t, "https://src.example", tc.in)
		got, ok := reg.Get(zzGame, "src")
		if !ok {
			t.Fatalf("status %q: the source is not in the registry", tc.in)
		}
		if got.Status != tc.want {
			t.Errorf("status %q resolved to %q, want %q", tc.in, got.Status, tc.want)
		}
	}
}

// TestZ09ARetiredSourceIsStillNeverServed: the fix did not move where retiring
// happens. A retired source is excluded from the candidate set (unpinned and
// pinned), so the read is refused rather than answered by an upstream that the
// operator believes is out of service.
func TestZ09ARetiredSourceIsStillNeverServed(t *testing.T) {
	cases := []struct {
		name   string
		status federation.SourceStatus
		served bool
	}{
		{"an active source is served", federation.StatusActive, true},
		{"a retired source is not served", federation.StatusRetired, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := zzStatusSource(t, `{"served_by":"src"}`)
			reg := zzStatusRegistry(t, up.URL, tc.status)
			srv, mint := zzHarness(t, reg, []zzBind{
				{User: "usr_v", Game: zzGame, Source: "src", Access: "upstream-token"},
			}, nil)
			at := mint("usr_v", zzProfileScope)

			code, hdr, body := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/profile", at)
			codePin, hdrPin, _ := zzGet(t, srv.Client(),
				srv.URL+"/v1/games/"+zzGame+"/profile?source=src", at)
			t.Logf("status=%q: unpinned=%d Re0Auth-Source=%q | pinned=%d Re0Auth-Source=%q | body=%s",
				tc.status, code, hdr.Get("Re0Auth-Source"), codePin, hdrPin.Get("Re0Auth-Source"), body)

			if got := code == http.StatusOK; got != tc.served {
				t.Errorf("status %q: served=%v (unpinned %d, pinned %d), want served=%v",
					tc.status, got, code, codePin, tc.served)
			}
		})
	}
}
