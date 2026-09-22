import { expect, test } from './fixtures';
import { idpBase } from './env';

// The login page is where every other flow starts, so these tests are about the
// entry point itself: what it offers, and the ways a login can fail without
// quietly minting a session or losing the user somewhere they did not ask for.
//
// The success path is exercised by `signIn()` in every other spec, through the
// real shipping flow and with no test-only bypass. It is not repeated here.

test('the sign-in page offers every configured provider', async ({ page }) => {
	await page.goto('/app/');

	// The built-in GitHub, the custom OIDC provider, and the one whose discovery
	// is down all appear: the page lists what is configured, and the label is the
	// deployment's display name rather than the raw provider id.
	await expect(page.getByRole('button', { name: '使用 GitHub 登录' })).toBeVisible();
	await expect(page.getByRole('button', { name: '使用 Authentik 登录' })).toBeVisible();
	await expect(page.getByRole('button', { name: '使用 Legacy SSO 登录' })).toBeVisible();
});

test('a callback with the wrong state is refused and creates no session', async ({ page }) => {
	// Start a real flow but do not follow its redirect, so the browser holds a
	// pending state. `page.request` shares the browser's cookie jar.
	const started = await page.request.get('/auth/github/start', { maxRedirects: 0 });
	expect(started.status()).toBe(302);
	const issued = new URL(started.headers()['location']).searchParams.get('state');
	expect(issued, 'the provider redirect carried no state').toBeTruthy();

	// Replay the callback with a state the session never issued.
	const res = await page.goto(`/auth/github/callback?code=x&state=not-${issued}`);
	expect(res?.status()).toBe(400);

	// And nobody was signed in.
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(401);
});

test('a provider that denies is reported back to where the user was going', async ({ page }) => {
	// The fake provider refuses the next authorization, the way a real one would
	// if the person pressed "cancel".
	const deny = await fetch(`${idpBase}/__error/access_denied`, { method: 'POST' });
	expect(deny.ok).toBe(true);

	await page.goto('/auth/github/start?return_to=/app/sources');

	// The handler follows the provider's decision back to `return_to`, carrying
	// the reason, and still creates no session.
	await expect(page).toHaveURL(/\/app\/sources\?error=access_denied/);
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(401);
});

// A denied login started from the home page has no explicit return_to, so it
// lands on `/`. The reason must survive the `/` -> `/app/` redirect, or the user
// is silently returned to the anonymous page with no idea what happened.
test('a denied login started from the home page still explains itself', async ({ page }) => {
	const deny = await fetch(`${idpBase}/__error/access_denied`, { method: 'POST' });
	expect(deny.ok).toBe(true);

	await page.goto('/app/');
	await page.getByRole('button', { name: '使用 GitHub 登录' }).click();

	await expect(page).toHaveURL(/\/app\/\?error=access_denied/);
	await expect(page.getByText('登录已取消，或未获得授权。')).toBeVisible();
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(401);
});

// The `return_to` query is attacker-controlled. A value that names another origin
// must be discarded, or the login page becomes an open redirect.
test('a return_to that points off-origin is discarded, not followed', async ({ page }) => {
	await fetch(`${idpBase}/__identity/redirect-probe`, { method: 'POST' });

	await page.goto('/auth/github/start?return_to=https://evil.example/steal');

	// The login itself succeeds, but the sanitized `/` wins: the browser lands in
	// the app, never at the attacker's origin.
	await expect(page.getByText('账号 ID')).toBeVisible();
	expect(page.url()).toMatch(/\/app\/$/);
	expect(page.url()).not.toContain('evil.example');
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(200);
});

// A custom OIDC provider whose discovery is unreachable cannot start a login. The
// user must be told, not shown a bare 502 from the login plane.
test('a provider whose discovery is down is explained, not a dead end', async ({ page }) => {
	await page.goto('/app/');
	await page.getByRole('button', { name: '使用 Legacy SSO 登录' }).click();

	await expect(page).toHaveURL(/\/app\/\?error=provider_unavailable/);
	await expect(page.getByText('该登录方式暂时不可用，请稍后再试。')).toBeVisible();
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(401);
});
