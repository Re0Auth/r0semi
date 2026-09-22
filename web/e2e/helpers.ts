import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { createHash, randomBytes } from 'node:crypto';
import { test } from './fixtures';
import { CALLBACK_URL, CLIENT_ID, DEFAULT_SCOPES, idpBase } from './env';

/** An RFC 7636 verifier and its S256 challenge. */
export function pkce() {
	// 32 random bytes base64url-encoded: 43 characters, inside the 43–128 the RFC
	// requires, and inside the unreserved alphabet.
	const verifier = randomBytes(32).toString('base64url');
	const challenge = createHash('sha256').update(verifier).digest('base64url');
	return { verifier, challenge };
}

/** The URL a downstream client would send the browser to. */
export function authorizeURL(opts: { challenge: string; scopes?: string; state?: string }) {
	const query = new URLSearchParams({
		response_type: 'code',
		client_id: CLIENT_ID,
		redirect_uri: CALLBACK_URL,
		scope: opts.scopes ?? DEFAULT_SCOPES,
		state: opts.state ?? 'e2e-state',
		code_challenge: opts.challenge,
		code_challenge_method: 'S256'
	});
	return `/oauth/authorize?${query}`;
}

/**
 * Signs in through the fake identity provider.
 *
 * There is no shortcut and that is deliberate. The session this produces went
 * through a real start redirect, PKCE storage, the code exchange, account
 * creation and a session id rotation — all of it the shipping login path.
 *
 * The identity defaults to the test's own title, so every test gets its own
 * account and cannot see another test's grants. Pass one explicitly when a test
 * *wants* two browsers to be the same account.
 *
 * `provider` is the button label, which is the deployment's display name for that
 * IdP; the default is the built-in GitHub.
 */
export async function signIn(page: Page, identity: string = test.info().title, provider = 'GitHub') {
	// Tell the provider who this sign-in is, before starting it. This is the fake's
	// own control channel; nothing in re0auth knows about it.
	const tell = await fetch(`${idpBase}/__identity/${encodeURIComponent(identity)}`, { method: 'POST' });
	expect(tell.ok, `the fake provider refused the identity: ${tell.status}`).toBe(true);

	await page.goto('/app/');
	const button = page.getByRole('button', { name: `使用 ${provider} 登录` });
	try {
		await button.click({ timeout: 10_000 });
	} catch {
		// A login that cannot even start is almost always the API refusing to
		// describe a provider rather than a UI defect, and a bare locator timeout
		// says nothing about which. Report what the page actually says.
		const text = (await page.locator('body').textContent())?.replace(/\s+/g, ' ').trim().slice(0, 300);
		throw new Error(`sign-in button never appeared; the page says: ${JSON.stringify(text)}`);
	}
	await expect(page.getByText('账号 ID')).toBeVisible();
}

/** Waits for the browser to land on the client's redirect URI and returns its query. */
export async function callbackParams(page: Page) {
	await page.waitForURL(/\/callback\?/, { timeout: 15_000 });
	return new URL(page.url()).searchParams;
}

/**
 * Runs the consent flow for the seeded client and returns the tokens.
 *
 * Factored out because more than one spec needs a working access token, and
 * because the flow is the same thing every time: send the browser to authorize,
 * approve, then exchange the code the way a client would.
 */
export async function authorizeAndExchange(
	page: Page,
	ctx: APIRequestContext,
	scopes = DEFAULT_SCOPES
): Promise<Record<string, string>> {
	const { verifier, challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes }));
	await page.getByRole('button', { name: '同意并继续' }).click();
	const params = await callbackParams(page);
	const code = params.get('code');
	if (!code) {
		throw new Error(`no authorization code came back: ${page.url()}`);
	}
	return exchangeCode(ctx, code, verifier);
}

export async function exchangeCode(
	ctx: APIRequestContext,
	code: string,
	verifier: string
): Promise<Record<string, string>> {
	const res = await ctx.post('/oauth/token', {
		form: {
			grant_type: 'authorization_code',
			client_id: CLIENT_ID,
			code,
			code_verifier: verifier,
			redirect_uri: CALLBACK_URL
		}
	});
	expect(res.ok(), `token exchange failed: ${res.status()} ${await res.text()}`).toBe(true);
	return res.json();
}

/** Asks for a device code, the way a CLI or console would. */
export async function beginDevice(
	ctx: APIRequestContext,
	scope = 'account.id'
): Promise<{ device_code: string; user_code: string; verification_uri: string; verification_uri_complete: string }> {
	const res = await ctx.post('/oauth/device_authorization', {
		form: { client_id: CLIENT_ID, scope }
	});
	expect(res.ok(), `device authorization failed: ${res.status()}`).toBe(true);
	return res.json();
}

/** Polls the token endpoint for a device code, as the waiting device would. */
export async function pollDevice(ctx: APIRequestContext, deviceCode: string) {
	const res = await ctx.post('/oauth/token', {
		form: {
			grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
			client_id: CLIENT_ID,
			device_code: deviceCode
		}
	});
	return { status: res.status(), body: await res.json() };
}

/**
 * Connects one named data source through the real binding flow, and waits for the
 * round trip to finish.
 *
 * It leaves the app for the source's own authorization page and comes back, so
 * the only reliable signal is the thing a completed bind produces: the disconnect
 * button on that source's card.
 */
export async function connect(page: Page, id = 'phigros/e2e') {
	await page.goto('/app/sources');
	await page.locator(`[data-source="${id}"]`).getByRole('button', { name: '连接', exact: true }).click();
	await expect(
		page.locator(`[data-binding="${id}"]`).getByRole('button', { name: '断开连接', exact: true })
	).toBeVisible({ timeout: 20_000 });
}

/**
 * Connects a source while already on the consent screen: clicks the prompt's
 * connect button, which leaves for the source and returns to the same pending
 * request.
 */
export async function connectFromConsent(page: Page) {
	await page.getByRole('button', { name: '连接', exact: true }).click();
	// The round trip ends back on this pending request. The prompt's connect
	// button is gone and approval is possible again; waiting on the enabled button
	// rather than the heading matters, because the heading renders while the page
	// is still loading.
	await expect(page.getByRole('button', { name: '连接', exact: true })).toHaveCount(0, {
		timeout: 20_000
	});
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeEnabled({ timeout: 20_000 });
}

/** Calls the business plane with an access token from this suite's own issuance. */
export async function callWithToken(ctx: APIRequestContext, path: string, accessToken: string) {
	const res = await ctx.get(path, { headers: { authorization: `Bearer ${accessToken}` } });
	// Parsed regardless of status: a caller asserting on an error's `code` needs the
	// body of a failed response just as much as a successful one.
	const text = await res.text();
	let body: unknown;
	try {
		body = text ? JSON.parse(text) : undefined;
	} catch {
		body = text;
	}
	return { status: res.status(), body: body as Record<string, unknown> };
}
