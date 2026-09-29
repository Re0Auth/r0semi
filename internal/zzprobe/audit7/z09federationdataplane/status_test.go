//go:build audit7

// Z09-1: `sources[].status` is never validated.
//
// `docs/upstream-protocol.md` §10 fixes the lifecycle vocabulary as
// `active | degraded | retired`, and `federation.candidates` excludes a source by
// comparing its status to the exact string "retired". Everything else — a
// capitalised spelling, a trailing space, a synonym — falls through `statusRank`'s
// `default:` branch to "worst rank, still selectable", so a source the operator
// believes is out of service keeps answering reads (and keeps deciding the scope
// gate, which is the other half of FO-V2).
//
// The other operator declaration of the same kind, `token_class`, IS validated at
// the registry — the CS-4 fix added exactly that check for exactly this reason
// ("a typo like long_live would otherwise be silently read as revocable").
// `status` is the value that check was not applied to.
package zzprobe_z09federationdataplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// zzStatusRegistry builds a one-source registry whose only difference between
// cases is the spelling of `status`.
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
		t.Fatalf("NewRegistry refused status %q: %v", status, err)
	}
	return reg
}

func TestZ09StatusSpellingDecidesWhetherARetiredSourceStillServes(t *testing.T) {
	cases := []struct {
		name string
		// status is what the operator wrote in the sources table.
		status federation.SourceStatus
		// wantServed is what docs/upstream-protocol.md §10 requires: only a value
		// in the lifecycle vocabulary may be selected, and "retired" never may.
		wantServed bool
	}{
		{"control: the exact spelling is out of service", federation.StatusRetired, false},
		{"a capitalised spelling", federation.SourceStatus("Retired"), false},
		{"a trailing space", federation.SourceStatus("retired "), false},
		{"another word", federation.SourceStatus("disabled"), false},
		{"control: an empty value is active and is served", federation.SourceStatus(""), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := zzStatusSource(t, `{"served_by":"src"}`)
			reg := zzStatusRegistry(t, up.URL, tc.status)
			srv, mint := zzHarness(t, reg, []zzBind{
				{User: "usr_v", Game: zzGame, Source: "src", Access: "upstream-token"},
			}, nil)
			at := mint("usr_v", zzProfileScope)

			// 1. unpinned: what a normal downstream read does.
			code, hdr, body := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/profile", at)

			// 2. pinned: `?source=` takes the other branch of candidates(), which
			//    is where the retired check is written out a second time.
			codePin, hdrPin, _ := zzGet(t, srv.Client(),
				srv.URL+"/v1/games/"+zzGame+"/profile?source=src", at)

			// 3. the public discovery document, which is supposed to publish the
			//    lifecycle state from that fixed vocabulary.
			_, _, srcBody := zzGet(t, srv.Client(), srv.URL+"/v1/sources", at)
			var listing struct {
				Data []struct {
					Status string `json:"status"`
				} `json:"data"`
			}
			if err := json.Unmarshal(srcBody, &listing); err != nil {
				t.Fatalf("GET /v1/sources is not the documented shape: %v (%s)", err, srcBody)
			}
			published := ""
			if len(listing.Data) > 0 {
				published = listing.Data[0].Status
			}

			t.Logf("status=%q: unpinned=%d Re0Auth-Source=%q | pinned=%d Re0Auth-Source=%q | "+
				"/v1/sources says status=%q | body=%s",
				tc.status, code, hdr.Get("Re0Auth-Source"), codePin, hdrPin.Get("Re0Auth-Source"), published, body)

			served := code == http.StatusOK
			switch {
			case served && !tc.wantServed:
				t.Errorf("a source whose status is %q was SELECTED and served data (unpinned %d, pinned %d). "+
					"docs/upstream-protocol.md §10 fixes the vocabulary as active|degraded|retired, and the only "+
					"thing that retires a source is an exact string comparison (federation.go statusRank's default "+
					"branch keeps an unrecognised value selectable). An operator who writes \"Retired\", \"retired \" "+
					"or any synonym believes the source is out of service while it keeps answering reads and keeps "+
					"deciding the scope gate", tc.status, code, codePin)
			case !served && tc.wantServed:
				t.Errorf("a source that IS in service (status %q) was not served (unpinned %d, pinned %d): the probe "+
					"is not discriminating", tc.status, code, codePin)
			}
			if tc.status != "" && published != string(tc.status) {
				t.Errorf("/v1/sources published status %q for a source configured with %q: the discovery document "+
					"repeats whatever the operator wrote, including values outside the vocabulary", published, tc.status)
			}
			if tc.status == "" && published != string(federation.StatusActive) {
				t.Errorf("/v1/sources published %q for an unset status; want %q", published, federation.StatusActive)
			}
		})
	}
}

// The registry-side statement, without a server: NewRegistry accepts every
// spelling. This is the direct comparison with the token_class check, which
// refuses an unrecognised value at the same call.
func TestZ09RegistryAcceptsAnyStatusSpelling(t *testing.T) {
	for _, s := range []federation.SourceStatus{
		"Retired", "retired ", " RETIRED", "disabled", "off", "Active", "DEGRADED", "degraded ",
	} {
		_, err := federation.NewRegistry(federation.Source{
			Game: zzGame, Name: "src", Issuer: "https://src.example",
			Status:    s,
			Resources: []federation.Resource{{Name: "profile", Scope: zzProfileScope}},
		})
		if err != nil {
			t.Logf("status %q was refused: %v", s, err)
			continue
		}
		t.Errorf("NewRegistry accepted status %q. `token_class` is validated at this same call with the "+
			"rationale that a typo must not be silently reinterpreted; `status` decides whether a source is "+
			"out of service and is not", s)
	}
}

// The other half of FO-V2, reached through the same defect: a retired source that
// was spelled differently still participates in the scope gate, so retiring a
// source silently changes what a token must hold to read a DIFFERENT source.
//
// This is the denial direction — the request is refused, not served — and it is
// why "the gate excludes retired sources" is only true for one spelling.
func TestZ09AMisspelledRetirementStillDecidesAnotherSourcesGate(t *testing.T) {
	cases := []struct {
		name   string
		status federation.SourceStatus
	}{
		{"control: the exact spelling is excluded from the gate", federation.StatusRetired},
		{"a capitalised spelling still decides the gate", federation.SourceStatus("Retired")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The source the user is NOT bound to declares the scope the token
			// holds; the source the user IS bound to declares the other one. If the
			// not-bound source is (correctly) out of the candidate set, the gate
			// requires only the live source's scope and the read is served.
			live := zzStatusSource(t, `{"served_by":"b-live"}`)
			off := zzStatusSource(t, `{"served_by":"a-off"}`)
			reg, err := federation.NewRegistry(
				federation.Source{
					Game: zzGame, Name: "a-off", DisplayName: "Off", Issuer: off.URL, Status: tc.status,
					Resources: []federation.Resource{
						{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.score.read"},
					},
				},
				federation.Source{
					Game: zzGame, Name: "b-live", DisplayName: "Live", Issuer: live.URL,
					Resources: []federation.Resource{
						{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: zzProfileScope},
					},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			srv, mint := zzHarness(t, reg, []zzBind{
				{User: "usr_v", Game: zzGame, Source: "b-live", Access: "live-token"},
			}, nil)
			at := mint("usr_v", zzProfileScope)

			code, hdr, body := zzGet(t, srv.Client(), srv.URL+"/v1/games/"+zzGame+"/profile", at)
			t.Logf("status(a-off)=%q: %d Re0Auth-Source=%q body=%s", tc.status, code, hdr.Get("Re0Auth-Source"), body)

			if code != http.StatusOK {
				t.Errorf("a token holding the scope of the source that would actually serve (b-live: %q) was "+
					"refused with %d, because a source spelled %q — an operator's attempt at %q — is still part of "+
					"the requirement set. The requirement set named it (see the body), so a source the operator "+
					"believes is out of service is deciding another source's authorization criterion. This is "+
					"FO-V2's shape, and its fix (candidates() excluding retired sources) holds only for the exact "+
					"spelling. Body: %s", zzProfileScope, code, tc.status, federation.StatusRetired, body)
			}
		})
	}
}
