import { expect, test } from './fixtures';
import { idpBase } from './env';

// The login page is where every other flow starts, so these tests are about the
// entry point itself: that it offers exactly what the deployment configured, and
// that the two ways a callback goes wrong — a state this session never issued, or
// a provider that says no — fail without quietly minting a session.
//
// The success path is exercised by `signIn()` in every other spec, through the
// real shipping flow and with no test-only bypass. It is not repeated here.

test('the sign-in page offers every configured provider', async ({ page }) => {
	await page.goto('/app/');

	// The built-in GitHub and the custom OIDC provider are both listed, and the
	// label is the deployment's display name rather than the raw provider id.
	await expect(page.getByRole('button', { name: '使用 GitHub 登录' })).toBeVisible();
	await expect(page.getByRole('button', { name: '使用 Authentik 登录' })).toBeVisible();
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
