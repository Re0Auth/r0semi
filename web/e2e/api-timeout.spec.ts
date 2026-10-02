import { expect, test } from '@playwright/test';
import { api } from '../src/lib/api';

// A per-attempt deadline is only a deadline if it survives the whole attempt.
//
// `fetch` resolves as soon as the response *headers* arrive, so a timer cleared at
// that point does not cover the body: a server that sends `200 OK` and then never
// finishes answering would leave the caller pending forever. This spec pins the
// deadline to the body read by stalling the body and watching for the abort.
//
// It runs in the Playwright runner's Node context rather than a browser page
// because `src/lib/api.ts` is self-contained (no imports, no DOM globals at module
// scope), so the module under test can be exercised directly with a stubbed
// `globalThis.fetch` — no server, no page, no test-only path inside the app.

test('a stalled response body still trips the per-attempt deadline', async () => {
	// The abort has to be observable, so the stub records it and errors the body
	// stream the way a real transport does when its signal fires.
	let aborted = false;

	const realFetch = globalThis.fetch;
	globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
		const signal = init?.signal ?? undefined;
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				signal?.addEventListener('abort', () => {
					aborted = true;
					controller.error(new DOMException('aborted', 'AbortError'));
				});
				// No `close()` and no chunks: the body never ends on its own.
			}
		});
		return new Response(body, {
			status: 200,
			headers: { 'content-type': 'application/json' }
		});
	}) as typeof fetch;

	try {
		// The sentinel is deliberately longer than the 15s per-attempt deadline, so
		// it can only win when the deadline never fires — which is the bug.
		const outcome = await Promise.race([
			api
				.currentSession()
				.then(() => 'resolved')
				.catch((err) => `rejected:${err instanceof Error ? err.name : String(err)}`),
			new Promise<string>((resolve) => {
				const sentinel = setTimeout(() => resolve('still-pending-after-20s'), 20_000);
				// Do not hold the worker open for the remaining 5s once the race is over.
				(sentinel as unknown as { unref?: () => void }).unref?.();
			})
		]);

		expect(outcome).not.toBe('still-pending-after-20s');
		expect(aborted).toBe(true);
	} finally {
		globalThis.fetch = realFetch;
	}
});
