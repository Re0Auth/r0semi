import { expect, test } from './fixtures';
import { authorizeAndExchange, callWithToken, signIn } from './helpers';

// Signing out is the one write whose whole job is to end something, so this suite
// does not stop at "the button disappeared": it checks the session server-side,
// and it pins the boundary that sign-out is *not* token revocation.

test('signing out destroys the session', async ({ page }) => {
	await signIn(page);
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(200);

	await page.getByRole('button', { name: '退出登录' }).click();

	// The page falls back to the anonymous sign-in screen...
	await expect(page.getByRole('button', { name: /使用 GitHub 登录/ })).toBeVisible();
	// ...and the session is gone in the store, not only in the UI.
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(401);
});

// A session and a grant are different things. Signing out ends the browser
// session; it does not revoke tokens a client already holds. That is a deliberate
// boundary — revoking a grant is `DELETE /v1/grants/{client_id}` — and a test that
// stayed quiet about it would let either half drift.
test('signing out does not revoke an already-issued access token', async ({ page, request }) => {
	await signIn(page);
	// `account.id` alone, so the consent screen needs no data-source binding.
	const tokens = await authorizeAndExchange(page, request, 'account.id');

	const before = await callWithToken(request, '/v1/me', tokens.access_token);
	expect(before.status).toBe(200);

	// authorizeAndExchange left the browser on the client's callback page, so come
	// back to the account page to sign out.
	await page.goto('/app/');
	await page.getByRole('button', { name: '退出登录' }).click();
	await expect(page.getByRole('button', { name: /使用 GitHub 登录/ })).toBeVisible();

	const after = await callWithToken(request, '/v1/me', tokens.access_token);
	expect(after.status).toBe(200);
});

// The two data-protection controls have to be reachable from the account page,
// not only over the API: an unshipped right is not a right.
test('the account can export its data and then erase itself', async ({ page }) => {
	await signIn(page);

	const download = page.waitForEvent('download');
	await page.getByRole('button', { name: '导出我的数据' }).click();
	expect((await download).suggestedFilename()).toMatch(/^re0auth-account-usr_/);

	// Erasure is irreversible, so it takes a second step that names the act.
	await page.getByRole('button', { name: '删除账号' }).click();
	await expect(page.getByText('无法撤销')).toBeVisible();
	await page.getByRole('button', { name: '确认删除账号' }).click();

	await expect(page.getByText('账号已删除')).toBeVisible();
	// Gone in the store, not only in the UI.
	expect((await page.request.get('/v1/sessions/current')).status()).toBe(401);
});
