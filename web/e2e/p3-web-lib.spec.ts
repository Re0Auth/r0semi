import { expect, test } from '@playwright/test';
import { api, ApiError } from '../src/lib/api';
import { restoreFocus } from '../src/lib/a11y';

// Library-level probes for the P3 web items. They run in the Playwright runner's
// Node context, like `api-timeout.spec.ts`: `src/lib/api.ts` and `src/lib/a11y.ts`
// are self-contained enough to exercise directly with a stubbed `globalThis.fetch`
// or `globalThis.document`, so every probe drives the shipping module rather than
// a copy of its logic.

/** Runs `fn` with a stubbed `fetch`, restoring the real one afterwards. */
async function withFetch(
	stub: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
	fn: () => Promise<void>
) {
	const realFetch = globalThis.fetch;
	globalThis.fetch = stub as typeof fetch;
	try {
		await fn();
	} finally {
		globalThis.fetch = realFetch;
	}
}

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

// S12-9 [info]. A retried response is abandoned, but its body is still an open
// stream; leaving it unread keeps the transport delivering bytes nobody wants.
test('a retried response body is cancelled before the next attempt', async () => {
	let cancelled = false;
	let attempts = 0;

	await withFetch(
		async () => {
			attempts++;
			if (attempts === 1) {
				const body = new ReadableStream<Uint8Array>({
					cancel() {
						cancelled = true;
					}
				});
				return new Response(body, {
					status: 503,
					headers: { 'content-type': 'application/json' }
				});
			}
			return json(200, { data: [] });
		},
		async () => {
			const res = await api.listGrants();
			expect(res.data).toEqual([]);
			expect(attempts, 'the 503 should have been retried once').toBe(2);
			expect(cancelled, 'the discarded 503 body was never cancelled').toBe(true);
		}
	);
});

// S12-10. The list endpoints used to trust the `{ data: [...] }` envelope; a
// response without one threw inside a render, where the only handler left is
// SvelteKit's error boundary. Each of them must now fail as an ApiError instead.
test('a list endpoint whose data is missing fails as malformed_response', async () => {
	const cases: Array<[string, () => Promise<unknown>]> = [
		['grants', () => api.listGrants()],
		['identities', () => api.listIdentities()],
		['sources', () => api.listAllSources()],
		['bindings', () => api.listBindings()],
		['providers', () => api.listIDPProviders()],
		['admin clients', () => api.listAdminClients()]
	];

	for (const [what, call] of cases) {
		await withFetch(
			// An object where the page iterates: the exact shape that used to reach
			// the renderer and throw there.
			async () => json(200, { data: { not: 'a list' } }),
			async () => {
				const err = await call().then(
					() => null,
					(e) => e as unknown
				);
				expect(err, `${what} accepted a non-array data field`).toBeInstanceOf(ApiError);
				expect((err as ApiError).code, what).toBe('malformed_response');
			}
		);
	}
});

// The positive control: validation must not reject a well-formed envelope.
test('a well-formed list envelope still passes validation', async () => {
	await withFetch(
		async () => json(200, { data: [] }),
		async () => {
			expect((await api.listGrants()).data).toEqual([]);
		}
	);
});

// S12-10, the extension half. The list endpoints were the visible offenders, but
// every other JSON endpoint trusted its `as T` just the same: a 200 with the
// wrong shape reached the renderer and threw there. Each of them must now fail as
// an ApiError at the boundary, where the page's own error handling can show it.
test('the remaining JSON endpoints reject a wrong-shaped 200', async () => {
	// The body is deliberately one the stated interface does not allow — an empty
	// object wherever the page reads a field, and a nonsense enum where it branches.
	const cases: Array<[string, unknown, () => Promise<unknown>]> = [
		['session', {}, () => api.currentSession()],
		['authorization request', {}, () => api.getAuthorizationRequest('req')],
		[
			'authorization decision',
			{},
			() => api.decideAuthorizationRequest('req', 'csrf', { decision: 'approve' })
		],
		['device verification', { state: 'not-a-state' }, () => api.getDeviceVerification('CODE')],
		['pending device verification', { state: 'pending' }, () => api.getDeviceVerification('CODE')],
		['device decision', {}, () => api.decideDevice('csrf', { user_code: 'C', decision: 'approve' })],
		['account deletion', {}, () => api.deleteAccount('csrf')],
		['admin clients', { data: [] }, () => api.listAdminClients()],
		[
			'admin registration',
			{},
			() =>
				api.registerAdminClient('csrf', {
					name: 'n',
					type: 'public',
					redirect_uris: ['https://client.example/cb'],
					scopes: ['account.id']
				})
		],
		['kill switch report', {}, () => api.killSwitch('csrf', { target: 'all' })],
		['unbind result', { upstream: 'not-an-outcome' }, () => api.unbindSource('g', 's', 'csrf')],
		['cascade result', {}, () => api.cascadeRevoke('g', 's', 'csrf')]
	];

	for (const [what, body, call] of cases) {
		await withFetch(
			async () => json(200, body),
			async () => {
				const err = await call().then(
					() => null,
					(e) => e as unknown
				);
				expect(err, `${what} accepted a wrong-shaped body`).toBeInstanceOf(ApiError);
				expect((err as ApiError).code, what).toBe('malformed_response');
			}
		);
	}
});

// The negative control for the extension: the same endpoints must still accept
// the shapes the server actually sends. Without this, a shape rule that rejected
// everything would pass the test above and break the app.
test('well-formed bodies for the remaining endpoints still resolve', async () => {
	await withFetch(
		async () =>
			json(200, { user_id: 'u', primary_identity_id: 'i', csrf_token: 'c', identities: [] }),
		async () => {
			expect((await api.currentSession()).csrf_token).toBe('c');
		}
	);

	await withFetch(
		async () =>
			json(200, {
				state: 'pending',
				user_code: 'CODE',
				client: { id: 'cli', name: 'Phi CLI' },
				scopes: [],
				expires_at: '2026-01-01T00:00:00Z',
				csrf_token: 'c'
			}),
		async () => {
			const res = await api.getDeviceVerification('CODE');
			expect(res.state).toBe('pending');
		}
	);

	await withFetch(
		async () => json(200, { state: 'approved' }),
		async () => {
			expect((await api.decideDevice('c', { user_code: 'CODE', decision: 'approve' })).state).toBe(
				'approved'
			);
		}
	);

	await withFetch(
		async () => json(200, { redirect_to: 'https://client.example/cb?code=x' }),
		async () => {
			expect(
				(await api.decideAuthorizationRequest('req', 'c', { decision: 'approve' })).redirect_to
			).toBe('https://client.example/cb?code=x');
		}
	);

	await withFetch(
		async () => json(200, { data: [], csrf_token: 'c' }),
		async () => {
			expect((await api.listAdminClients()).csrf_token).toBe('c');
		}
	);

	await withFetch(
		async () => json(200, { result: { sessions: 1 } }),
		async () => {
			expect((await api.deleteAccount('c')).result).toEqual({ sessions: 1 });
		}
	);

	await withFetch(
		async () => json(200, { tokens_revoked: 1, sessions_revoked: 2, clients_suspended: 3 }),
		async () => {
			expect((await api.killSwitch('c', { target: 'all' })).tokens_revoked).toBe(1);
		}
	);

	await withFetch(
		async () => json(200, { upstream: 'nothing' }),
		async () => {
			expect((await api.unbindSource('g', 's', 'c')).upstream).toBe('nothing');
		}
	);
});

// S12-5, the validation half: the download filename is built from
// profile.user_id, so an export that does not carry one must be refused at the
// boundary rather than throwing inside the download.
test('an account export without profile.user_id is refused at the boundary', async () => {
	await withFetch(
		async () => json(200, { exported_at: 'now', profile: {}, identities: [] }),
		async () => {
			const err = await api.exportAccount().then(
				() => null,
				(e) => e as unknown
			);
			expect(err).toBeInstanceOf(ApiError);
			expect((err as ApiError).code).toBe('malformed_response');
		}
	);
});

test('a well-formed account export still resolves', async () => {
	await withFetch(
		async () => json(200, { profile: { user_id: 'u-1' }, identities: [], bindings: [], grants: [] }),
		async () => {
			expect((await api.exportAccount()).profile.user_id).toBe('u-1');
		}
	);
});

// S12-6. The id matched during focus restoration comes from the server or the
// deployment config. Splicing it into a selector makes a quote or a bracket an
// invalid selector that `querySelector` throws on; matching by attribute
// comparison must keep it out of the selector grammar entirely.
test('focus restoration matches an id by attribute value, not by selector', async () => {
	const hostile = 'cli"] , [data-revoke';
	const focused: string[] = [];
	const selectors: string[] = [];
	const element = {
		getAttribute: (name: string) => (name === 'data-revoke' ? hostile : null),
		focus: () => focused.push(hostile)
	};

	const realDocument = globalThis.document;
	globalThis.document = {
		querySelectorAll: (selector: string) => {
			selectors.push(selector);
			return [element];
		}
	} as unknown as Document;
	try {
		await restoreFocus('data-revoke', hostile);

		expect(focused, 'the trigger with the matching id was not focused').toEqual([hostile]);
		expect(selectors, 'the id reached the selector grammar').toEqual(['[data-revoke]']);
	} finally {
		globalThis.document = realDocument;
	}
});

// The negative control: a value that does not match must not steal focus from
// the element that does.
test('focus restoration ignores an element with a different id', async () => {
	const focused: string[] = [];
	const elements = [
		{ getAttribute: () => 'other', focus: () => focused.push('other') },
		{ getAttribute: () => 'wanted', focus: () => focused.push('wanted') }
	];

	const realDocument = globalThis.document;
	globalThis.document = {
		querySelectorAll: () => elements
	} as unknown as Document;
	try {
		await restoreFocus('data-revoke', 'wanted');
		expect(focused).toEqual(['wanted']);
	} finally {
		globalThis.document = realDocument;
	}
});
