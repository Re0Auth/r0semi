package oidchttp

// The introspection filter is the only thing between a client and another
// client's token details. Round 3 hardened it for the cross-client case; its
// failure shape was still "cannot attribute it, so describe it", which is
// fail-open. These cases pin the closed direction.

import (
	"bytes"
	"testing"
)

func TestFilterIntrospectionFailsClosedOnUnattributableTokens(t *testing.T) {
	h := &Handler{introspectionClients: map[string]bool{"rs": true}}
	active := []byte(`{"active":true,"client_id":"cli","scope":"account.id","sub":"usr_1"}`)
	inactive := []byte(`{"active":false}`)

	cases := []struct {
		name   string
		body   []byte
		caller string
		want   []byte
		why    string
	}{
		{
			name: "the issuing client sees its own token", body: active, caller: "cli", want: active,
			why: "ownership is the normal case and must keep working",
		},
		{
			name: "an allowlisted resource server sees it", body: active, caller: "rs", want: active,
			why: "the allowlist is how a resource server is given visibility on purpose",
		},
		{
			name: "another client learns nothing", body: active, caller: "other", want: inactive,
			why: "introspection must not be a cross-client oracle",
		},
		{
			name: "a token with no client id is not described", body: []byte(`{"active":true,"scope":"account.id"}`),
			caller: "cli", want: inactive,
			why: "a token nobody owns cannot be attributed, and unattributable means hidden",
		},
		{
			name: "a caller with no client id is not answered", body: active, caller: "", want: inactive,
			why: "the filter cannot apply a policy it cannot name a subject for",
		},
		{
			name: "an inactive token stays inactive", body: inactive, caller: "other", want: inactive,
			why: "there is nothing to hide in a response that already says active=false",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.filterIntrospection(tc.body, tc.caller)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("filterIntrospection = %s, want %s (%s)", got, tc.want, tc.why)
			}
		})
	}
}

// A body the filter cannot parse is passed through unchanged, and that is
// deliberate rather than a gap: the only successful introspection responses are
// written by the library as JSON, so a body that does not parse carries no token
// it could leak, and answering active=false would turn an odd response into a
// refusal for the token's own owner.
func TestFilterIntrospectionPassesThroughAnUnparseableBody(t *testing.T) {
	h := &Handler{introspectionClients: map[string]bool{}}
	body := []byte("not json at all")
	if got := h.filterIntrospection(body, "cli"); !bytes.Equal(got, body) {
		t.Fatalf("filterIntrospection = %s, want the body unchanged", got)
	}
}
