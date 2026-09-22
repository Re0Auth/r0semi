package vault

import "runtime"

// Scrub overwrites a byte slice that held credential material.
//
// It is **best effort**, and the limit is Go's rather than this function's: the
// garbage collector may already have copied the slice, and nothing here can reach
// a copy. memguard exists for callers who need a stronger guarantee, and to give
// one it has to own the allocation from the start. A documented best effort is
// more useful than an unverifiable claim, which is why docs/threat-model.md says
// so out loud rather than implying this is zeroization in the C sense.
//
// # runtime.KeepAlive and //go:noinline are the lines not to drop
//
// Without them the compiler is permitted to consider the slice dead once it is no
// longer read — which is precisely the state the loop exists to prevent — or to
// inline this into a caller where it can see that nothing reads the result. Both
// are what make the intent binding rather than incidental.
//
// This matters more than it looks: three copies of this function used to exist.
// All three had the noinline directive and one was missing KeepAlive, and the one
// missing it was the copy wiping the TapTap session token. Nobody chose that. It
// is what a duplicated guard costs over time, and why there is one copy now.
//
//go:noinline
func Scrub(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
