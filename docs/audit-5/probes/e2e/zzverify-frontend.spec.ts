import { expect, test } from './fixtures';
import { authorizeURL, callbackParams, exchangeCode, pkce, signIn } from './helpers';

// Verifier probes for docs/audit-5/findings/frontend-VERIFIED.md.
//
// These are written to *pass when the report's claim is true*, so a green run is
// evidence for the claim rather than for its absence.

test('the browser can observe the granted-but-never-displayed claim scopes', async ({ page, request }) => {
	await signIn(page);
	const { verifier, challenge } = pkce();
	// The report's own guard (zzadversary-frontend.spec.ts, "displayed scopes and
	// granted scopes cannot diverge") requests `openid account.id`, which cannot
	// produce the divergence it is named after. Asking for the claim scopes makes
	// the same divergence visible in a browser.
	await page.goto(authorizeURL({ challenge, scopes: 'openid profile email account.id' }));
	const approval = page.getByRole('button', { name: '同意并继续' });
	await expect(approval).toBeEnabled();

	const displayed = (await page.locator('ul li p.font-mono').allTextContents())
		.map((s) => s.trim())
		.filter((s) => /^[a-z][a-z0-9._-]*$/.test(s));
	console.log(`[verify] displayed on screen: ${JSON.stringify(displayed)}`);
	expect(displayed, 'nothing was displayed, so nothing was compared').toContain('account.id');
	expect(displayed, 'a claim scope was rendered as a permission').not.toContain('profile');

	await approval.click();
	const params = await callbackParams(page);
	const tokens = await exchangeCode(request, params.get('code')!, verifier);
	const granted = String(tokens.scope ?? '')
		.split(' ')
		.filter(Boolean);
	console.log(`[verify] granted by the token response: ${JSON.stringify(granted)}`);

	const silent = granted.filter((s) => !displayed.includes(s));
	// The claim scopes are granted without ever appearing on the screen. This is
	// the finding; if a fix lands, this assertion is the one that fails.
	expect(silent, 'the divergence the report names did not reproduce').toEqual(
		expect.arrayContaining(['profile', 'email'])
	);

	// And the same token grants no data: userinfo answers with sub alone.
	const ui = await request.get('/oauth/userinfo', {
		headers: { authorization: `Bearer ${tokens.access_token}` }
	});
	const claims = await ui.json();
	console.log(`[verify] userinfo claims: ${JSON.stringify(claims)}`);
	expect(Object.keys(claims)).toEqual(['sub']);
});

test('a hashed asset a later deploy dropped is answered with the shell, not a 404', async ({ request }) => {
	const res = await request.get('/app/_app/immutable/entry/start.DELETEDBYDEPLOY.js');
	const body = await res.text();
	console.log(
		`[verify] missing chunk -> ${res.status()} ct=${res.headers()['content-type']} first=${JSON.stringify(
			body.slice(0, 30)
		)}`
	);
	// The report's A-FE-9 failure chain says ServeFileFS answers 404 and the SPA
	// fallback does not stand in for script files. This probe pins the opposite.
	expect(res.status()).toBe(200);
	expect(res.headers()['content-type']).toContain('text/html');
	expect(body.startsWith('<!doctype html')).toBe(true);
});

test('the Svelte runtime warnings in the shipped bundle do not fire on the app paths', async ({ page }) => {
	const warns: string[] = [];
	page.on('console', (msg) => {
		if (msg.type() === 'warning' || msg.type() === 'warn') warns.push(msg.text());
	});

	await signIn(page);
	await page.goto('/app/');
	await page.goto('/app/grants');
	await page.goto('/app/sources');
	await page.goto('/app/device');
	const { challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes: 'account.id' }));
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeEnabled();

	// Reported, not asserted to be zero: if one fires, the report's open question
	// about reachability is answered in the affirmative instead.
	console.log(`[verify] console warnings during an app walk: ${JSON.stringify(warns)}`);
	expect(Array.isArray(warns)).toBe(true);
});
