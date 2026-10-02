import { expect, test } from './fixtures';
import { idpBase } from './env';
import { signIn } from './helpers';

// Browser-level probes for the P3 route items on the account page. They go
// through the real page in a real browser rather than through a copy of its
// logic, so what is asserted is what a visitor actually sees.

// S12-4 / Z08-8. `?error=` is attacker-controlled and used to be echoed verbatim
// inside the branded failure alert — escaped, so never script execution, but a
// phishing canvas whose text the deployment does not control.
test('an unknown ?error= is replaced by fixed copy and never echoed', async ({ page }) => {
	const payload = '您的账号已被停用，请联系 support@evil.example 恢复';

	await page.goto(`/app/?error=${encodeURIComponent(payload)}`);

	// The branded alert is still there; its text is the deployment's, not the URL's.
	await expect(page.getByRole('alert')).toContainText('登录没有完成，请重试。');
	expect(await page.locator('body').textContent(), 'the query value reached the page').not.toContain(
		'evil.example'
	);
});

// The whitelist half must keep working: a code the deployment knows still gets
// its own actionable sentence rather than the generic one.
test('a known ?error= still gets its mapped explanation', async ({ page }) => {
	await page.goto('/app/?error=access_denied');
	await expect(page.getByRole('alert')).toContainText('登录已取消，或未获得授权。');
});

// S12-3. After a denied login the page sits on `?error=...`. The sign-in button
// used to hand that whole query back as return_to, so the next, successful login
// landed on the stale reason and reported failure for a login that worked.
test('a stale ?error= does not ride along through a later successful sign-in', async ({ page }) => {
	const deny = await fetch(`${idpBase}/__error/access_denied`, { method: 'POST' });
	expect(deny.ok).toBe(true);
	const who = await fetch(`${idpBase}/__identity/p3-s12-3`, { method: 'POST' });
	expect(who.ok).toBe(true);

	await page.goto('/app/');
	await page.getByRole('button', { name: '使用 GitHub 登录' }).click();

	// The denial lands back on the account page with the reason.
	await expect(page).toHaveURL(/\/app\/\?error=access_denied/);
	await expect(page.getByRole('alert')).toContainText('登录已取消，或未获得授权。');

	// The same button again, this time the provider cooperates.
	await page.getByRole('button', { name: '使用 GitHub 登录' }).click();
	await expect(page.getByText('账号 ID')).toBeVisible({ timeout: 15_000 });

	// A live session and no failure alert: the stale reason was not re-read.
	await expect(page.getByRole('alert')).toHaveCount(0);
});

// S12-10. The error boundary used to print `page.error.message` for every
// non-404, which for an uncaught exception is a JavaScript message. The 404
// branch is the reachable one and has to keep working after that change.
test('an unknown route still gets the app’s own 404 copy', async ({ page }) => {
	await page.goto('/app/no-such-route-for-p3');
	await expect(page.getByText('这个页面不存在。')).toBeVisible();
	await expect(page.getByText('404')).toBeVisible();
});

// S12-10, the browser half. The boundary check has to be visible where a person
// is: a 200 carrying a shape the page cannot use must produce the page's own
// failure sentence, not an uncaught render error that the error boundary reports
// in JavaScript. Interception is how the audit's trigger — a captive portal or a
// half-migrated backend answering 200 with the wrong body — is reproduced without
// a test path inside the app.
test('a wrong-shaped 200 becomes the page’s own failure, not a render error', async ({ page }) => {
	await page.route('**/v1/sessions/current', (route) =>
		route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({})
		})
	);

	await page.goto('/app/');

	// The account page's failure line, assembled from the malformed_response
	// ApiError — proof the failure happened before a render had to cope with it.
	await expect(
		page.getByText('session response is missing or has an invalid user_id')
	).toBeVisible();
	// And the error boundary's own copy is not what a visitor is shown.
	await expect(page.getByText('页面没有加载成功。')).toHaveCount(0);
});

// S12-10, the 5xx half. The fixed-copy branch is what stands between an uncaught
// render failure and a JavaScript message becoming the page's headline, and it
// had no executable probe. Rather than add a route that throws to the shipped
// app, this makes the home page's own code chunk fail with a 5xx — the shape a
// proxy or a half-deployed edge produces — and asserts the deployment's sentence
// is shown for the 500 that results. The failing import's own message
// ("Failed to fetch dynamically imported module…") is a JavaScript string, which
// is exactly the class of message the branch exists to replace.
test('a 5xx while loading a route shows the fixed copy, not the internal message', async ({
	page
}) => {
	await page.route('**/nodes/*.js', async (route) => {
		const res = await route.fetch();
		const body = await res.text();
		// Only the page module for `/` becomes the failure; the error page's own
		// module must keep loading, or there would be nothing left to render.
		if (!body.includes('你的 Re0Auth 账号')) {
			return route.fulfill({ response: res, body });
		}
		return route.fulfill({ status: 500, contentType: 'text/plain', body: 'proxy failure' });
	});

	await page.goto('/app/');
	await expect(page.getByText('页面没有加载成功。')).toBeVisible();
	await expect(page.getByText('500')).toBeVisible();
});

// S12-5, the reliability half. The object URL was revoked in the same task as the
// click that starts the download, which can cancel it before the browser has read
// the blob. The anchor is instrumented so the ordering is observable rather than
// inferred from a single environment's tolerance.
test('the export download is real and its object URL is released after the click', async ({
	page
}) => {
	await page.addInitScript(() => {
		const state = {
			clicked: false,
			duringClick: false,
			revokedDuringClick: null as boolean | null
		};
		(window as unknown as { __export: typeof state }).__export = state;

		const realClick = HTMLAnchorElement.prototype.click;
		HTMLAnchorElement.prototype.click = function () {
			state.clicked = true;
			// True for the rest of this task and no longer: a revoke that runs while
			// it is still true happened "synchronously" with the click.
			state.duringClick = true;
			queueMicrotask(() => {
				state.duringClick = false;
			});
			return realClick.call(this);
		};

		const realRevoke = URL.revokeObjectURL;
		URL.revokeObjectURL = function (url: string) {
			state.revokedDuringClick = state.duringClick;
			return realRevoke.call(URL, url);
		};
	});

	await signIn(page, 'p3-s12-5-export');

	const started = page.waitForEvent('download');
	await page.getByRole('button', { name: '导出我的数据' }).click();
	const download = await started;

	expect(download.suggestedFilename()).toMatch(/^re0auth-account-.+\.json$/);
	expect(await download.failure()).toBeNull();

	const state = await page.evaluate(
		() =>
			(window as unknown as { __export: { clicked: boolean; revokedDuringClick: boolean | null } })
				.__export
	);
	expect(state.clicked, 'the export anchor was never clicked').toBe(true);
	expect(
		state.revokedDuringClick,
		'the object URL was revoked in the same task as the click'
	).toBe(false);
});
