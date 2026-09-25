import { expect, test } from './fixtures';
import { idpBase } from './env';
import {
	authorizeURL,
	callWithToken,
	callbackParams,
	connectFromConsent,
	exchangeCode,
	pkce,
	signIn
} from './helpers';

// The consent screen is the one page whose entire job is to be trusted about what
// is being granted. These tests therefore do not stop at "it looks right": each
// one follows the decision through to what the client actually receives, because
// a page that renders correctly and grants the wrong thing is the failure that
// matters.
//
// One state is deliberately not covered here: an explicit-consent scope, where the
// approve button stays disabled until it is ticked on its own. The shipped
// catalogue contains no such scope and the binary offers no way to add one, so the
// state is unreachable from a browser. It is covered by the unit tests in oauth
// and internal/authz, which supply a synthetic critical scope; pretending to cover
// it here would require a test-only hook in the server, which is worse than the
// gap.

test('a signed-out visitor is offered a way in, not a dead end', async ({ page }) => {
	await page.goto('/app/consent?id=ar_whichever');
	await expect(page.getByRole('heading', { name: '授权请求' })).toBeVisible();
	await expect(page.getByText('需要先登录')).toBeVisible();

	// The offer has to be real. The button comes from the server's provider list,
	// so a deployment with no provider configured shows a sentence instead of a
	// button that leads to a 404.
	await expect(page.getByRole('button', { name: /使用 GitHub 登录/ })).toBeVisible();
});

test('signing in from consent returns to the pending request', async ({ page, request }) => {
	// Give the fake IdP the identity this test signs in as, without going through
	// the /app login page: this test starts at the authorization request.
	const identity = test.info().title;
	const tell = await fetch(`${idpBase}/__identity/${encodeURIComponent(identity)}`, { method: 'POST' });
	expect(tell.ok).toBe(true);

	const { verifier, challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes: 'account.id' }));

	// The visitor is anonymous on the consent page; the handle is bound to this
	// browser session and must survive the IdP round trip.
	await expect(page.getByText('需要先登录')).toBeVisible();
	await page.getByRole('button', { name: /使用 GitHub 登录/ }).click();

	// Before the fix this landed on /app/ and the pending request was silently
	// abandoned. It must come back to the same handle, signed in.
	await expect(page).toHaveURL(/\/app\/consent\?id=/);
	await expect(page.getByText('Phi CLI')).toBeVisible();
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeVisible();

	// And the task is still completable: approving yields a real code.
	await page.getByRole('button', { name: '同意并继续' }).click();
	const params = await callbackParams(page);
	expect(params.get('code')).toBeTruthy();
	const tokens = await exchangeCode(request, params.get('code')!, verifier);
	expect(tokens.access_token).toBeTruthy();
});

test('a handle this browser never created is explained, never confirmed', async ({ page }) => {
	await signIn(page);
	await page.goto('/app/consent?id=ar_not_mine');

	await expect(page.getByText('这个授权请求不可用')).toBeVisible();
	// And crucially, no consent UI: a stolen handle must not render as something
	// that looks approvable.
	await expect(page.getByRole('button', { name: '同意并继续' })).toHaveCount(0);
});

test('approving yields a code that exchanges for a token the API accepts', async ({ page, request }) => {
	await signIn(page);
	const { verifier, challenge } = pkce();

	// Exactly what a downstream client does: send the browser to /oauth/authorize.
	// account.id needs no data source, so this is the plain consent path.
	await page.goto(authorizeURL({ challenge, scopes: 'account.id' }));

	// It landed on the consent screen with a handle /oauth/authorize created and
	// bound to this browser session.
	await expect(page.getByRole('heading', { name: '授权请求' })).toBeVisible();
	await expect(page.getByText('Phi CLI')).toBeVisible();

	await page.getByRole('button', { name: '同意并继续' }).click();
	const params = await callbackParams(page);
	expect(params.get('error')).toBeNull();
	expect(params.get('state')).toBe('e2e-state');

	const tokens = await exchangeCode(request, params.get('code')!, verifier);
	expect(tokens.access_token).toBeTruthy();
	expect(tokens.scope).toContain('account.id');

	// The loop only closes if the business plane honours the token. A token that
	// nothing accepts would have satisfied every assertion above.
	const me = await callWithToken(request, '/v1/me', tokens.access_token);
	expect(me.status).toBe(200);
	expect(me.body.scopes).toContain('account.id');
});

// Progressive binding: a scope that can only be served through a data source
// cannot be approved until that source is connected, and connecting from the
// consent screen returns to the same pending request.
test('a scope that needs a data source is connected before it can be approved', async ({
	page,
	request
}) => {
	await signIn(page);
	const { verifier, challenge } = pkce();
	await page.goto(authorizeURL({ challenge }));

	// The request names phigros.b30.read, which the e2e deployment serves from a
	// source this account has not connected.
	await expect(page.getByText('还没有这个数据源的权限')).toBeVisible();
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeDisabled();

	await connectFromConsent(page);

	// Same handle, now satisfied: the pending request survived the round trip.
	await expect(page.getByText('还没有这个数据源的权限')).toHaveCount(0);
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeEnabled();

	await page.getByRole('button', { name: '同意并继续' }).click();
	const params = await callbackParams(page);
	const tokens = await exchangeCode(request, params.get('code')!, verifier);
	expect(tokens.scope).toContain('phigros.b30.read');

	// And the granted scope reaches the route that requires it, now with a bound
	// source behind it.
	const b30 = await callWithToken(request, '/v1/games/phigros/b30', tokens.access_token);
	expect(b30.status).toBe(200);
});

test('denying reports access_denied instead of a code', async ({ page }) => {
	await signIn(page);
	const { challenge } = pkce();
	await page.goto(authorizeURL({ challenge }));

	await page.getByRole('button', { name: '拒绝' }).click();

	const params = await callbackParams(page);
	expect(params.get('code')).toBeNull();
	expect(params.get('error')).toBe('access_denied');
	expect(params.get('state')).toBe('e2e-state');
});

test('unchecking a scope narrows the token, and the server is what enforces it', async ({ page, request }) => {
	await signIn(page);
	const { verifier, challenge } = pkce();
	await page.goto(authorizeURL({ challenge }));

	await page.locator('input[id="scope-phigros.b30.read"]').uncheck();
	await page.getByRole('button', { name: '同意并继续' }).click();

	const params = await callbackParams(page);
	const tokens = await exchangeCode(request, params.get('code')!, verifier);
	expect(tokens.scope).toContain('account.id');
	expect(tokens.scope ?? '').not.toContain('phigros.b30.read');

	// The checkbox is not what makes narrowing real. The same route that answered
	// 409 above must now refuse the token outright, because the scope is absent
	// from what the server granted.
	const b30 = await callWithToken(request, '/v1/games/phigros/b30', tokens.access_token);
	expect(b30.status).toBe(403);
});
