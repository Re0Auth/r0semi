import { expect, test } from './fixtures';
import { authorizeURL, pkce, signIn } from './helpers';

// Second adversarial probe file (frontend audit): headers that only exist on the
// wire, and the failure mode of a shell served without any validator.

test('the browser plane carries the defensive headers a document needs', async ({ request }) => {
	const html = await request.get('/app/consent');
	const h = html.headers();
	const interesting = [
		'content-security-policy',
		'referrer-policy',
		'x-content-type-options',
		'x-frame-options',
		'cross-origin-opener-policy',
		'cross-origin-embedder-policy',
		'cross-origin-resource-policy',
		'permissions-policy',
		'cache-control',
		'etag',
		'last-modified',
		'content-length'
	];
	const seen: Record<string, string | undefined> = {};
	for (const k of interesting) seen[k] = h[k];
	// eslint-disable-next-line no-console
	console.log(`[probe] /app/consent headers: ${JSON.stringify(seen, null, 2)}`);

	expect(h['referrer-policy'], 'the consent URL carries id and error parameters').toBe('no-referrer');
	expect(h['x-content-type-options']).toBe('nosniff');
	expect(h['x-frame-options']).toBe('DENY');
	expect(h['content-security-policy']).toContain("frame-ancestors 'none'");
	expect(h['cache-control']).toBe('no-cache');
});

test('the shell has no validator, so revalidation always costs a full body', async ({ request }) => {
	const first = await request.get('/app/consent');
	const etag = first.headers()['etag'];
	const lastModified = first.headers()['last-modified'];
	const body = await first.text();
	// eslint-disable-next-line no-console
	console.log(
		`[probe] shell validators: etag=${JSON.stringify(etag)} last-modified=${JSON.stringify(lastModified)} bytes=${body.length}`
	);

	// Reported, not asserted: whether a validator exists is the finding. The
	// assertion is that a conditional request is either honoured or answered with a
	// decision the client can act on — never a 5xx.
	if (etag) {
		const conditional = await request.get('/app/consent', { headers: { 'if-none-match': etag } });
		expect([200, 304]).toContain(conditional.status());
	}
	if (lastModified) {
		const conditional = await request.get('/app/consent', {
			headers: { 'if-modified-since': lastModified }
		});
		expect([200, 304]).toContain(conditional.status());
	}
});

test('a Range request against the shell is answered, and the answer is recorded', async ({ request }) => {
	const res = await request.get('/app/', { headers: { range: 'bytes=0-9' } });
	const body = await res.text();
	// eslint-disable-next-line no-console
	console.log(
		`[probe] Range: bytes=0-9 on the shell -> ${res.status()} content-range=${JSON.stringify(
			res.headers()['content-range']
		)} body=${JSON.stringify(body)}`
	);
	// A truncated HTML document must not be served as though it were the document:
	// if this is 206, a client that asked for a range gets markup with no </html>.
	if (res.status() === 206) {
		expect(body.length, 'the shell answered a Range with a partial body').toBeLessThan(80);
	}
	expect(res.status()).toBeLessThan(500);
});

test('the app is framed nowhere and frames nothing', async ({ page }) => {
	await signIn(page);
	const { challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes: 'account.id' }));
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeEnabled();

	// The document can see no window it could be controlled through.
	const relations = await page.evaluate(() => ({
		opener: window.opener === null,
		top: window.top === window,
		frames: window.frames.length,
		ancestors: window.parent === window
	}));
	expect(relations.opener, 'the consent screen has an opener').toBe(true);
	expect(relations.top, 'the consent screen is not the top window').toBe(true);
	expect(relations.frames, 'something embedded a frame in the consent screen').toBe(0);
});
