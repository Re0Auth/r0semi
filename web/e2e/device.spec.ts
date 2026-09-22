import { expect, test } from './fixtures';
import { beginDevice, callWithToken, pollDevice, signIn } from './helpers';

// RFC 8628 in a browser. The device is a separate party in every test here: it
// talks to the API directly, the way a console or a CLI would, and never shares
// the browser's session. That separation is the point — the whole flow exists so
// that something with no keyboard can get a token by borrowing a phone.

test('approving a device code lets the waiting device get a token', async ({ page, request }) => {
	const start = await beginDevice(request);

	// verification_uri is handed to a person's browser. A JSON endpoint there
	// leaves them staring at an object, which is what it used to do.
	expect(start.verification_uri).toMatch(/\/app\/device$/);
	expect(start.verification_uri_complete).toContain(`user_code=${start.user_code}`);

	await signIn(page);
	await page.goto(`/app/device?user_code=${encodeURIComponent(start.user_code)}`);
	await expect(page.getByText('Phi CLI')).toBeVisible();
	await page.getByRole('button', { name: '批准登录' }).click();
	await expect(page.getByText('已批准')).toBeVisible();

	// The device was waiting on the token endpoint the whole time.
	const { status, body } = await pollDevice(request, start.device_code);
	expect(status).toBe(200);
	expect(body.access_token).toBeTruthy();

	const me = await callWithToken(request, '/v1/me', body.access_token);
	expect(me.status).toBe(200);
});

test('the code can be typed in, not only followed from a link', async ({ page, request }) => {
	const start = await beginDevice(request);
	await signIn(page);

	// The path a console user takes when they read the code off a screen.
	await page.goto('/app/device');
	await page.locator('#user-code').fill(start.user_code);
	await page.getByRole('button', { name: '继续' }).click();

	await expect(page.getByText('Phi CLI')).toBeVisible();
	await page.getByRole('button', { name: '批准登录' }).click();
	await expect(page.getByText('已批准')).toBeVisible();
});

test('denying is reported to the device, which gets no token', async ({ page, request }) => {
	const start = await beginDevice(request);
	await signIn(page);
	await page.goto(`/app/device?user_code=${encodeURIComponent(start.user_code)}`);

	await page.getByRole('button', { name: '拒绝' }).click();
	await expect(page.getByText('已拒绝')).toBeVisible();

	// RFC 8628 §3.5: the refusal arrives as a token-endpoint error.
	const { status, body } = await pollDevice(request, start.device_code);
	expect(status).toBe(400);
	expect(body.error).toBe('access_denied');
	expect(body.access_token).toBeUndefined();
});

test('a code cannot be approved without signing in, and the device keeps waiting', async ({ page, request }) => {
	const start = await beginDevice(request);

	await page.goto(`/app/device?user_code=${encodeURIComponent(start.user_code)}`);
	await expect(page.getByText('需要先登录')).toBeVisible();
	// Signing in is required before the code is even looked at.
	await expect(page.getByRole('button', { name: '批准登录' })).toHaveCount(0);

	// The device must not have been approved by a page nobody signed into.
	const { status, body } = await pollDevice(request, start.device_code);
	expect(status).toBe(400);
	expect(body.error).toBe('authorization_pending');
});

test('an unknown code is refused with an explanation', async ({ page }) => {
	await signIn(page);
	await page.goto('/app/device?user_code=ZZZZ-ZZZZ');
	await expect(page.getByText('代码不可用')).toBeVisible();
	await expect(page.getByRole('button', { name: '批准登录' })).toHaveCount(0);
});

test('a second browser cannot decide a code it never loaded', async ({ browser, request }) => {
	const start = await beginDevice(request);

	// One browser loads the code, which puts it in that session.
	const mine = await browser.newContext();
	const minePage = await mine.newPage();
	await signIn(minePage);
	await minePage.goto(`/app/device?user_code=${encodeURIComponent(start.user_code)}`);
	await expect(minePage.getByText('Phi CLI')).toBeVisible();

	// A different browser, signed in as the same account, decides it directly.
	// Knowing a short user code is enough to load it — that is inherent to RFC
	// 8628 and not a defect — but it is not enough to decide it.
	const other = await browser.newContext();
	const otherPage = await other.newPage();
	await signIn(otherPage);
	const csrf = await otherPage.evaluate(async () => {
		const res = await fetch('/v1/sessions/current');
		return (await res.json()).csrf_token as string;
	});
	const decision = await otherPage.evaluate(
		async ({ code, csrf }) => {
			const res = await fetch('/v1/device/decision', {
				method: 'POST',
				headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
				body: JSON.stringify({ user_code: code, decision: 'approve' })
			});
			return { status: res.status, body: await res.json() };
		},
		{ code: start.user_code, csrf }
	);

	expect(decision.status).toBe(404);
	// And the device still has nothing.
	const { body } = await pollDevice(request, start.device_code);
	expect(body.error).toBe('authorization_pending');

	await mine.close();
	await other.close();
});
