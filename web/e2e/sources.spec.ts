import { expect, test } from './fixtures';
import { idpBase } from './env';
import { authorizeAndExchange, callWithToken, connect, signIn } from './helpers';

// Binding is the step that makes the data plane work at all, and cascade
// revocation is the loudest thing the service can be asked to do. Neither is
// worth testing by looking at a list: one is proven by reading data through it
// and the other by the source actually being told.

test('a source can be connected, used, and disconnected', async ({ page, request }) => {
	await request.post(`${idpBase}/__reset`);
	await signIn(page);

	await page.goto('/app/sources');
	await expect(page.getByText('还没有连接数据源哦~')).toBeVisible();
	// And the page offers something to connect to. Without that it would be a dead
	// end for exactly the people who need it.
	await expect(page.locator('[data-source="phigros/e2e"]')).toBeVisible();

	await connect(page);
	// The source is no longer offered for connection, because it now is one.
	await expect(page.locator('[data-source="phigros/e2e"]')).toHaveCount(0);

	// The binding is what makes the data plane work, so ask for data.
	const tokens = await authorizeAndExchange(page, request, 'account.id phigros.b30.read');
	const read = await callWithToken(request, '/v1/games/phigros/b30', tokens.access_token);
	expect(read.status).toBe(200);

	// Disconnecting takes two clicks, so a mis-click is not a disconnection.
	await page.goto('/app/sources');
	const card = page.locator('[data-binding="phigros/e2e"]');
	await card.getByRole('button', { name: '断开连接', exact: true }).click();
	await card.getByRole('button', { name: '确认断开', exact: true }).click();
	await expect(page.getByText('还没有连接数据源哦~')).toBeVisible();

	// The same token now reports the source is unbound. That is what makes the
	// disconnection real rather than cosmetic.
	const after = await callWithToken(request, '/v1/games/phigros/b30', tokens.access_token);
	expect(after.status).toBe(409);
	expect(after.body.code).toBe('source_not_bound');

	// And the source itself was told to drop the token it issued, which is the half
	// of the job Re0Auth cannot do alone.
	const revocations = await (await request.get(`${idpBase}/__revocations`)).json();
	expect(revocations.tokens).toContain('e2e-source-rt');
});

test('a disconnection can be backed out of', async ({ page, request }) => {
	await request.post(`${idpBase}/__reset`);
	await signIn(page);
	await connect(page);

	const card = page.locator('[data-binding="phigros/e2e"]');
	await card.getByRole('button', { name: '断开连接', exact: true }).click();
	await card.getByRole('button', { name: '取消', exact: true }).click();

	await expect(card.getByRole('button', { name: '断开连接', exact: true })).toBeVisible();
	const revocations = await (await request.get(`${idpBase}/__revocations`)).json();
	expect(revocations.tokens).toHaveLength(0);
});

test('signing out everywhere ends the session and removes the binding', async ({ page, request }) => {
	await request.post(`${idpBase}/__reset`);
	await signIn(page);
	await connect(page);

	const card = page.locator('[data-binding="phigros/e2e"]');
	await card.getByRole('button', { name: '登出全部设备', exact: true }).click();
	// The warning has to be on screen before the button that acts on it, and it has
	// to say the thing that makes this different from disconnecting.
	await expect(card.getByText(/之后需要重新登录/)).toBeVisible();
	await card.getByRole('button', { name: '我明白，登出全部设备', exact: true }).click();

	await expect(page.getByText('还没有连接数据源哦~')).toBeVisible();

	// The source was asked to end the session, and asked on the cascade endpoint —
	// not the token one, which would have left the login standing.
	const cascades = await (await request.get(`${idpBase}/__cascades`)).json();
	expect(cascades.tokens).toContain('e2e-source-rt');
	const revocations = await (await request.get(`${idpBase}/__revocations`)).json();
	expect(revocations.tokens).toHaveLength(0);
});

test('a source that cannot sign out everywhere is not offered the action', async ({ page, request }) => {
	await request.post(`${idpBase}/__reset`);
	await signIn(page);
	await connect(page, 'phigros/plain');

	// The card is there, the disconnecting button is there, and the loud one is
	// absent — because the deployment has not been told this source can do it.
	const card = page.locator('[data-binding="phigros/plain"]');
	await expect(card.getByRole('button', { name: '断开连接', exact: true })).toBeVisible();
	await expect(card.getByRole('button', { name: '登出全部设备', exact: true })).toHaveCount(0);

	// And the server refuses rather than pretending to try, if something asks anyway.
	const refused = await page.evaluate(async () => {
		const session = await (await fetch('/v1/sessions/current')).json();
		const res = await fetch('/v1/bindings/phigros/plain/cascade_revocation', {
			method: 'POST',
			headers: { 'content-type': 'application/json', 'x-csrf-token': session.csrf_token },
			body: JSON.stringify({ acknowledge: 'signs_out_all_devices' })
		});
		return { status: res.status, body: await res.json() };
	});
	expect(refused.status).toBe(409);
	expect(refused.body.code).toBe('cascade_unsupported');

	// Nothing was removed, which is the point of refusing.
	await expect(card.getByRole('button', { name: '断开连接', exact: true })).toBeVisible();
});

// S12-7. The connectable list is the catalogue minus what is retired and what is
// already bound, and a connected card's resources are read back from that same
// catalogue. Indexing the catalogue by key (instead of scanning it per card) is an
// internal refactor, so what has to hold is the external contract — proven here
// against crafted payloads so a retired source exists at all, which the real
// deployment config deliberately does not offer.
test('the connectable list excludes retired and already-connected sources', async ({ page }) => {
	const source = (name: string, status: string, resources: string[]) => ({
		game: 'phigros',
		source: name,
		display_name: `${name} source`,
		token_class: 'revocable',
		status,
		raw: false,
		resources: resources.map((resource) => ({
			name: resource,
			schema: `re0auth.phigros.${resource}/1`,
			scope: `phigros.${resource}.read`
		}))
	});

	await page.route('**/v1/sessions/current', (route) =>
		route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({
				user_id: 'u-1',
				primary_identity_id: 'i-1',
				csrf_token: 'csrf',
				identities: []
			})
		})
	);
	await page.route('**/v1/bindings', (route) =>
		route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({
				data: [
					{
						game: 'phigros',
						source: 'bound',
						display_name: 'Bound Source',
						token_class: 'revocable',
						status: 'active',
						has_refresh: false,
						bindable: true,
						configured: true,
						cascade_revocation: false
					}
				]
			})
		})
	);
	await page.route('**/v1/sources', (route) =>
		route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({
				// Catalogue order is what the connectable list must preserve.
				data: [
					source('retired', 'retired', ['gone']),
					source('bound', 'active', ['b30', 'profile']),
					source('degraded', 'degraded', ['live']),
					source('fresh', 'active', ['score'])
				]
			})
		})
	);

	await page.goto('/app/sources');

	// Retired is never offered; nor is a source the account already has.
	await expect(page.locator('[data-source="phigros/retired"]')).toHaveCount(0);
	await expect(page.locator('[data-source="phigros/bound"]')).toHaveCount(0);

	// Everything else is, in catalogue order — so the filter kept the rest as-is.
	expect(
		await page
			.locator('[data-source]')
			.evaluateAll((cards) => cards.map((card) => card.getAttribute('data-source')))
	).toEqual(['phigros/degraded', 'phigros/fresh']);

	// The connected card's resources came from the catalogue, in its order: the
	// by-key lookup returns the same names a scan would have.
	await expect(page.locator('[data-binding="phigros/bound"]')).toContainText('可读取 b30、profile');
});

test('the bindings list is not a client-facing API', async ({ request }) => {
	// It names the account's connections, so it is session-scoped like grants.
	expect((await request.get('/v1/bindings')).status()).toBe(401);
});
