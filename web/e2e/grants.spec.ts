import { expect, test } from './fixtures';
import { CLIENT_NAME } from './env';
import { authorizeAndExchange, callWithToken, signIn } from './helpers';

// The account page. What matters here is not that a list renders, but that the
// list and the access agree: a client appears when it can act, and the moment it
// is revoked its token stops working. A page that showed the right names while
// the token still worked would be worse than no page.

test('an application appears when authorized, and revoking it ends its access', async ({
	page,
	request
}) => {
	await signIn(page);

	// Nothing authorized yet.
	await page.goto('/app/grants');
	await expect(page.getByText('还没有应用获得授权。')).toBeVisible();

	const tokens = await authorizeAndExchange(page, request, 'account.id');

	// Now it is listed, with the fact that matters most about it.
	await page.goto('/app/grants');
	await expect(page.getByText(CLIENT_NAME)).toBeVisible();
	await expect(page.getByText('可自动续期')).toBeVisible();
	// The scope is shown with the catalogue's wording, not as a bare identifier.
	await expect(page.getByText('账号 ID')).toBeVisible();

	// And the token it holds really does work before the revocation.
	expect((await callWithToken(request, '/v1/me', tokens.access_token)).status).toBe(200);

	// Revoking takes two clicks, so a mis-click is not a revocation.
	// exact: true because "确认撤销" also contains "撤销".
	await page.getByRole('button', { name: '撤销', exact: true }).click();
	await page.getByRole('button', { name: '确认撤销', exact: true }).click();

	await expect(page.getByText('还没有应用获得授权。')).toBeVisible();

	// The part that makes "revoked" mean something: the client's token is dead.
	const after = await callWithToken(request, '/v1/me', tokens.access_token);
	expect(after.status).toBe(401);
});

test('a revocation can be backed out of', async ({ page, request }) => {
	await signIn(page);
	const tokens = await authorizeAndExchange(page, request, 'account.id');

	await page.goto('/app/grants');
	await page.getByRole('button', { name: '撤销', exact: true }).click();
	await page.getByRole('button', { name: '取消', exact: true }).click();

	// The list is unchanged and, more to the point, so is the access.
	await expect(page.getByText(CLIENT_NAME)).toBeVisible();
	expect((await callWithToken(request, '/v1/me', tokens.access_token)).status).toBe(200);
});

test('the grants page is not a client-facing API', async ({ page, request }) => {
	// A client asking with its own token must not learn about the account's other
	// clients: the endpoint is session-scoped precisely so that it cannot.
	const me = await request.get('/v1/grants');
	expect(me.status()).toBe(401);

	await signIn(page);
	const tokens = await authorizeAndExchange(page, request, 'account.id');
	const withToken = await request.get('/v1/grants', {
		headers: { authorization: `Bearer ${tokens.access_token}` }
	});
	expect(withToken.status()).toBe(401);
});
