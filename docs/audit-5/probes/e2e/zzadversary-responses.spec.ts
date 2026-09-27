import { expect, test } from './fixtures';
import { authorizeURL, pkce, signIn } from './helpers';

// Third adversarial probe file (frontend audit): what a server response the app
// did not expect does to the page.

test('a 3xx from the API does not become a client-side redirect', async ({ page }) => {
	await signIn(page);
	await page.goto('/app/grants');
	await expect(page.getByRole('heading', { name: '已授权的应用' })).toBeVisible();

	// A 302 with a Location is not something /v1 ever produces, but it is the exact
	// shape that turns "a load failed" into "the browser was sent somewhere else".
	// SvelteKit's own rule is that a redirect during a universal load must be
	// expressed with `redirect()`, so an unexpected 3xx must fail the load rather
	// than navigate.
	await page.route('**/v1/authorization_requests/**', (route) =>
		route.fulfill({
			status: 302,
			headers: { location: 'https://evil.example/harvest' }
		})
	);
	await page.goto('/app/consent?id=ar_probe');
	await page.waitForTimeout(600);

	// Reported: where the browser ended up. Asserted: not off-origin.
	// eslint-disable-next-line no-console
	console.log(`[probe] after a 302 from the API the browser is at ${page.url()}`);
	expect(new URL(page.url()).hostname, 'the app followed an API-supplied redirect').toBe('127.0.0.1');
});

test('a malformed problem body does not break the page or leak markup', async ({ page }) => {
	await signIn(page);

	const payload = {
		type: 'about:blank',
		title: `<img src=x onerror="window.__probe=1">`,
		status: 500,
		code: 'internal_error',
		detail: `<script>window.__probe=1</script>`,
		request_id: 'probe-1'
	};
	await page.route('**/v1/grants', (route) =>
		route.fulfill({ status: 500, contentType: 'application/problem+json', body: JSON.stringify(payload) })
	);
	await page.goto('/app/grants');

	// The failure has to be visible (so the user knows) and rendered as text (so a
	// server-controlled string cannot become markup).
	await expect(page.getByText('probe-1')).toBeVisible();
	expect(await page.locator('img[src="x"]').count()).toBe(0);
	expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).__probe ?? null)).toBeNull();
});

test('a scope list with an unknown risk level does not blank the consent screen', async ({ page }) => {
	await signIn(page);

	// Load the consent screen so the page is in its `ready` phase, then hand the
	// app the same response with every field the UI indexes by replaced by a value
	// the catalogue cannot produce. The app validates `id` and `scopes` are present
	// but not what is inside a scope object, so this is the one shape the boundary
	// check does not cover.
	await page.route('**/v1/authorization_requests/**', async (route) => {
		const res = await route.fetch();
		if (!res.ok()) {
			await route.fulfill({ response: res });
			return;
		}
		const body = await res.json();
		if (Array.isArray(body.scopes)) {
			for (const s of body.scopes) {
				s.risk = 'extremely-bad';
				s.explicit_consent = 'yes';
				s.description = undefined;
			}
		}
		await route.fulfill({ response: res, json: body });
	});

	// A handle this browser created: the app itself navigates to /app/consent?id=…
	// after /oauth/authorize, so fetch one the same way.
	const { challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes: 'account.id' }));
	await page.waitForTimeout(800);
	const text = (await page.locator('body').innerText()).replace(/\s+/g, ' ');
	// eslint-disable-next-line no-console
	console.log(`[probe] consent with an out-of-catalogue risk level renders: ${JSON.stringify(text.slice(0, 300))}`);
	// The page must still be a page: an unhandled exception here is a white screen
	// on the one screen where a person is deciding whether to grant access.
	expect(text.length, 'the consent screen rendered nothing').toBeGreaterThan(10);
	expect(text, 'the scope list did not render at all').toContain('account.id');
});
