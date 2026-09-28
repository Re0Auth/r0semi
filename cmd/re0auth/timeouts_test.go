package main

import (
	"testing"
	"time"
)

// The arithmetic that keeps a data-plane refusal writable.
//
// A data-plane request can make several outbound calls in series — each candidate
// source, a token refresh, and the fetch again after a 401 — so its worst case is
// a multiple of the outbound deadline, not one deadline. That multiple used to
// exceed the server's write timeout (60s), and an exchange past the write timeout
// is closed with no response at all: the one answer a client cannot interpret.
//
// Two bounds now exist and they must stay ordered: the federation service stops the
// request at dataPlaneTimeout and the data plane answers 504 with an error body; the
// write timeout sits above it as a backstop for everything else. These constants
// live together here precisely so this ordering is checkable.
func TestDataPlaneTimeoutFitsInsideTheWriteTimeout(t *testing.T) {
	if dataPlaneTimeout >= writeTimeout {
		t.Fatalf("dataPlaneTimeout (%v) must be below writeTimeout (%v): past the write timeout the connection is "+
			"closed with no response, so the client would not receive the 504 the federation deadline produces",
			dataPlaneTimeout, writeTimeout)
	}
	// The backstop must leave room to write the refusal after the deadline fires.
	if slack := writeTimeout - dataPlaneTimeout; slack < 5*time.Second {
		t.Fatalf("only %v between the data-plane deadline and the write timeout: not enough to write the refusal", slack)
	}
	// And it must exceed ONE outbound call, or the refresh-plus-retry path could
	// never finish at all.
	const outboundDefault = 20 * time.Second
	if dataPlaneTimeout <= outboundDefault {
		t.Errorf("dataPlaneTimeout (%v) is not larger than the per-call outbound deadline (%v)", dataPlaneTimeout, outboundDefault)
	}
	// Read is the other bound on an exchange; a data-plane request must not be
	// capped by it either, since it is the response that takes the time here.
	if readTimeout >= dataPlaneTimeout {
		t.Errorf("readTimeout (%v) is not below dataPlaneTimeout (%v)", readTimeout, dataPlaneTimeout)
	}
}
