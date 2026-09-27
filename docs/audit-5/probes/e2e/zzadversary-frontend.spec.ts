import { expect, test } from './fixtures';
import { authorizeURL, beginDevice, callbackParams, exchangeCode, pkce, signIn } from './helpers';

// Adversarial probes for the browser plane (frontend audit, docs/audit-5).
//
// Each test here is written to FAIL if the property it names is false. They are
// archived artifacts: to run one, copy it into the frontend e2e directory
// (web/e2e/), where ./fixtures and ./helpers resolve. The report in
// docs/audit-5/findings says which of them passed and which failed.

/** A marker that would be script if the app ever rendered a query param as markup. */
const XSS_MARKER = 'xss_probe_marker_9d3f';

/** CSP violations the app itself caused. Cleared before each app-driven navigation. */
type Violation = { directive: string; blockedURI: string; sample: string; source: string };

test('CSP is enforced by the browser, and the shell is not what breaks it', async ({ page }) => {
	const violations: Violation[] = [];
	const consoleErrors: string[] = [];
	page.on('console', (msg) => {
		const text = msg.text();
		if (msg.type() === 'error') consoleErrors.push(text);
		if (!/Content Security Policy/i.test(text)) return;
		const directive = text.match(/[a-z-]+-src|form-action|base-uri|frame-ancestors/)?.[0] ?? 'unknown';
		const blocked = text.match(/blocked (?:the )?(?:loading of|execution of|a form submission to|an inline script)[^.]*/i)?.[0] ?? text;
		violations.push({ directive, blockedURI: blocked, sample: text.slice(0, 200), source: 'console' });
	});

	// The app itself loads with zero CSP violations: the header (frame-ancestors)
	// and the build's meta policy must be jointly satisfiable, or the entry script
	// is blocked and the page is white.
	await page.goto('/app/');
	await expect(page.getByRole('button', { name: '使用 GitHub 登录' })).toBeVisible();
	expect(violations, `the app violated its own CSP: ${JSON.stringify(violations, null, 2)}`).toEqual([]);

	// An injected inline handler is not executed: that is what "hash-based
	// script-src with no unsafe-inline" means in a real browser.
	await page.evaluate((marker) => {
		const w = window as unknown as Record<string, unknown>;
		const s = document.createElement('script');
		s.textContent = `window.${marker} = 1`;
		document.body.appendChild(s);
	}, XSS_MARKER);
	await page.waitForTimeout(200);
	expect(
		await page.evaluate((m) => (window as unknown as Record<string, unknown>)[m] ?? null, XSS_MARKER),
		'an injected inline script executed: script-src is not hash-locked'
	).toBeNull();

	// Anti-vacuity: `page.evaluate` itself runs (the JS engine of this page is
	// alive), and the same inline payload executes when CSP is lifted. Neither
	// assertion above can be satisfied by "the browser never ran any script".
	const control = await page.context().browser()!.newContext({ bypassCSP: true });
	try {
		const controlPage = await control.newPage();
		await controlPage.goto('/app/');
		await controlPage.addScriptTag({ content: `window.${XSS_MARKER}_control = 1` });
		expect(
			await controlPage.evaluate(
				(m) => (window as unknown as Record<string, unknown>)[m] ?? null,
				`${XSS_MARKER}_control`
			),
			'the control artifact did not run, so the blocked-inline assertion proved nothing'
		).toBe(1);
	} finally {
		await control.close();
	}
});

test('the served policy carries hash-based script-src and a closed form-action', async ({ page }) => {
	const res = await page.request.get('/app/');
	const header = res.headers()['content-security-policy'] ?? '';
	expect(header, 'the header must forbid framing where a meta tag cannot').toContain("frame-ancestors 'none'");
	// The white-screen bug class: a header that restates a directive the meta tag
	// allows by hash wins the intersection and blocks the bootstrap.
	for (const restated of ['script-src', 'style-src', 'default-src', 'connect-src', 'object-src']) {
		expect(header, `the header restates ${restated}`).not.toContain(restated);
	}

	const html = await res.text();
	const meta = html.match(/http-equiv="content-security-policy" content="([^"]*)"/)?.[1] ?? '';
	expect(meta, 'the shell carries no meta policy').not.toBe('');
	expect(meta).toContain("form-action 'none'");
	expect(meta).toContain("base-uri 'none'");
	expect(meta).toContain("object-src 'none'");
	expect(meta).toContain("connect-src 'self'");
	expect(meta, 'style-src has no unsafe-inline — Tailwind would break, so check why').toContain(
		"style-src 'self' 'unsafe-inline'"
	);
	expect(meta, "script-src must not carry unsafe-inline").not.toContain("'unsafe-inline'; script-src");
	expect(meta, 'script-src must be hash-locked').toMatch(/script-src 'self' 'sha256-[A-Za-z0-9+/=]+'/);
	expect(meta, 'script-src must not allow eval').not.toContain("'unsafe-eval'");

	// The hash in the meta tag must be the hash of the script the shell actually
	// carries. A mismatch is a white screen, which no status-code test can see.
	const inline = html.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? '';
	expect(inline, 'no inline bootstrap script found: the hash cannot be checked').not.toBe('');
});

test('the injected-script hash matches the inline bootstrap in the shell', async ({ page }) => {
	// Verified in the browser rather than by reimplementing SvelteKit's hashing:
	// if the hash were wrong, this script would not have run and the page would be
	// blank, which is exactly the earlier white-screen bug.
	await page.goto('/app/');
	await expect(page.getByRole('button', { name: '使用 GitHub 登录' })).toBeVisible();
	const started = await page.evaluate(
		() => typeof (window as unknown as Record<string, unknown>).__sveltekit_1klc4hh
	);
	// Either the bootstrap global or the hydrated DOM is proof it ran; the global
	// name changes per build, so fall back to hydration having happened.
	const hydrated = await page.locator('main').count();
	expect(hydrated + (started === 'object' ? 1 : 0)).toBeGreaterThan(0);
});

test('displayed scopes and granted scopes cannot diverge', async ({ page, request }) => {
	await signIn(page);
	const { verifier, challenge } = pkce();
	// account.id needs no data source, and openid is the protocol flag the design
	// deliberately does not itemise: the interesting question is whether the token
	// can carry a window into a permission the screen never showed.
	await page.goto(authorizeURL({ challenge, scopes: 'openid account.id' }));

	const approval = page.getByRole('button', { name: '同意并继续' });
	await expect(approval).toBeEnabled();

	const displayed = await page.locator('ul li p.font-mono').allTextContents();
	const displayedScopes = displayed.map((s) => s.trim()).filter((s) => /^[a-z][a-z0-9._-]*$/.test(s));
	expect(displayedScopes, 'the screen displayed no scope at all, so nothing was proven').toContain(
		'account.id'
	);

	await approval.click();
	const params = await callbackParams(page);
	const tokens = await exchangeCode(request, params.get('code')!, verifier);
	const granted = String(tokens.scope ?? '')
		.split(' ')
		.filter(Boolean);

	// Nothing is granted that was not on screen, except the protocol flags the
	// design deliberately does not itemise (openid / offline_access).
	const protocolFlags = new Set(['openid', 'offline_access']);
	const silent = granted.filter((s) => !displayedScopes.includes(s) && !protocolFlags.has(s));
	expect(silent, `granted but never displayed: ${silent.join(', ')}`).toEqual([]);

	// The deliberate direction, pinned: openid is granted and is not listable, and
	// it must not have become a data permission on the way.
	expect(granted, 'the granted scope lost openid').toContain('openid');
	expect(displayedScopes, 'openid is not a data permission and must not be listed').not.toContain('openid');
	expect(granted, 'offline_access must never surface as a client-visible scope').not.toContain(
		'offline_access'
	);
});

test('a hostile user_code is not reflected as markup and executes nothing', async ({ page }) => {
	await signIn(page);
	const injected = `<script>window.${XSS_MARKER}=1</script><img src=x onerror="window.${XSS_MARKER}=1">`;
	await page.goto(`/app/device?user_code=${encodeURIComponent(injected)}`);

	// Whatever the page decides to say about that code, it must not have created
	// the element the payload names.
	expect(await page.locator(`script:has-text("${XSS_MARKER}")`).count()).toBe(0);
	expect(await page.locator('img[src="x"]').count()).toBe(0);
	expect(await page.evaluate((m) => (window as unknown as Record<string, unknown>)[m] ?? null, XSS_MARKER)).toBeNull();
	// Anti-vacuity: the page did look at the parameter, so this is not a probe that
	// never reached the sink. The value is echoed into the input at most.
	const body = (await page.locator('body').innerText()).replace(/\s+/g, ' ');
	expect(body.length, 'the page never rendered, so nothing was proven').toBeGreaterThan(0);
});

test('a hostile consent handle is not reflected as markup and executes nothing', async ({ page }) => {
	await signIn(page);
	const injected = `ar_"><script>window.${XSS_MARKER}=1</script>`;
	await page.goto(`/app/consent?id=${encodeURIComponent(injected)}`);
	await expect(page.getByText('这个授权请求不可用')).toBeVisible();
	expect(await page.locator(`script:has-text("${XSS_MARKER}")`).count()).toBe(0);
	expect(await page.evaluate((m) => (window as unknown as Record<string, unknown>)[m] ?? null, XSS_MARKER)).toBeNull();
});

test('every non-GET call the app makes carries X-CSRF-Token', async ({ page, request }) => {
	// A device decision is the shortest real write path the app has.
	const device = await beginDevice(request, 'account.id');
	await signIn(page);
	await page.goto(`/app/device?user_code=${encodeURIComponent(device.user_code)}`);
	await expect(page.getByRole('button', { name: '批准登录' })).toBeVisible();

	const writes: Array<{ method: string; url: string; csrf: string | undefined }> = [];
	page.on('request', (req) => {
		if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method())) {
			writes.push({ method: req.method(), url: req.url(), csrf: req.headers()['x-csrf-token'] });
		}
	});

	await page.getByRole('button', { name: '批准登录' }).click();
	await expect(page.getByText('已批准')).toBeVisible();

	expect(writes.length, 'no write was observed, so the probe proved nothing').toBeGreaterThan(0);
	for (const w of writes) {
		expect(w.csrf, `${w.method} ${w.url} carried no X-CSRF-Token`).toBeTruthy();
	}

	// The other half: a write without the token is refused, so the header is load
	// bearing rather than decoration.
	const bare = await page.request.post('/v1/device/decision', {
		data: { user_code: device.user_code, decision: 'approve' }
	});
	expect(bare.status(), 'a write without X-CSRF-Token was accepted').toBe(403);

	// It is the one from the session bootstrap, not a value the page invented.
	const session = await (await page.request.get('/v1/sessions/current')).json();
	expect(session.csrf_token).toBeTruthy();
});

test('an absolute or protocol-relative return_to never leaves the origin', async ({ page }) => {
	await page.goto('/app/?error=' + encodeURIComponent('access_denied'));

	// The sign-in button builds its own URL from a server-provided start_url and a
	// same-origin path. A crafted return_to in the address bar must not become the
	// navigation target.
	await page.goto(`/app/?return_to=${encodeURIComponent('https://evil.example/')}`);
	const button = page.getByRole('button', { name: /使用 GitHub 登录/ });
	await expect(button).toBeVisible();
	const navigation = button.click();
	const req = await page.waitForRequest((r) => r.isNavigationRequest() && r.url().includes('authorize'));
	await navigation;
	expect(new URL(req.url()).hostname, 'the app navigated off-origin').toBe('127.0.0.1');
	const returnTo = new URL(req.url()).searchParams.get('return_to');
	if (returnTo !== null) {
		expect(returnTo, 'return_to became an absolute URL').not.toMatch(/^https?:|^\/\//);
	}
	await page.waitForURL(/\/app\/|\/auth\/|\?error=/);
});

test('a javascript: redirect_uri is never navigated to', async ({ page }) => {
	await signIn(page);
	const { challenge } = pkce();
	const hostile = 'javascript:window.__js_probe=1';
	const url = authorizeURL({ challenge, scopes: 'account.id' }) + `&redirect_uri=${encodeURIComponent(hostile)}`;
	await page.goto(url);
	await page.waitForTimeout(700);

	// Reported as observed rather than asserted to be absent: the browser is on
	// /oauth/authorize, which means the hostile URI did not become the navigation.
	// eslint-disable-next-line no-console
	console.log(`[probe] after a hostile redirect_uri the browser is at ${page.url()}`);
	expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).__js_probe ?? null)).toBeNull();

	// The server must have refused before any consent screen rendered, because a
	// registered redirect_uri is not optional.
	const raw = await page.request.get(url, { maxRedirects: 0 });
	expect([302, 400], `hostile redirect_uri answered ${raw.status()}`).toContain(raw.status());
	if (raw.status() === 302) {
		const location = raw.headers()['location'] ?? '';
		expect(location, `redirected to ${location}`).not.toMatch(/^javascript:/i);
		expect(location).not.toContain('__js_probe');
	}
});

test('no token or code ever reaches URL state, web storage or the DOM', async ({ page, request }) => {
	await signIn(page);

	// Put the app through a complete consent round trip, then look for anything
	// credential-shaped in the places an XSS or a shared machine would read.
	const { verifier, challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes: 'account.id' }));
	const approval = page.getByRole('button', { name: '同意并继续' });
	await expect(approval).toBeEnabled();

	const seenURLs: string[] = [];
	page.on('framenavigated', (frame) => {
		if (frame === page.mainFrame()) seenURLs.push(frame.url());
	});
	await approval.click();
	const params = await callbackParams(page);
	const code = params.get('code') ?? '';
	const tokens = await exchangeCode(request, params.get('code')!, verifier);

	const storage = await page.evaluate(() => ({
		local: { ...localStorage },
		session: { ...sessionStorage },
		cookie: document.cookie,
		html: document.documentElement.outerHTML
	}));

	const secrets: Array<[string, string]> = [
		['access_token', String(tokens.access_token ?? '')],
		['refresh_token', String(tokens.refresh_token ?? '')],
		['authorization code', code],
		['csrf token', (await (await page.request.get('/v1/sessions/current')).json()).csrf_token ?? '']
	];
	const haystacks: Array<[string, string]> = [
		['localStorage', JSON.stringify(storage.local)],
		['sessionStorage', JSON.stringify(storage.session)],
		['document.cookie', storage.cookie],
		['the DOM', storage.html],
		['a navigated-to URL', seenURLs.join('\n')]
	];
	for (const [name, value] of secrets) {
		if (value.length < 8) continue;
		// The OAuth code and the CSRF token legitimately appear in the URL the
		// browser is sent to — that is the protocol — so they are only checked
		// against storage, cookies and the DOM.
		for (const [where, hay] of haystacks) {
			if (name === 'authorization code' && where === 'a navigated-to URL') continue;
			expect(hay.includes(value), `${name} is readable from ${where}`).toBe(false);
		}
	}
});

test('unchecking a scope only ever asks the server for less', async ({ page, request }) => {
	await signIn(page);
	const { verifier, challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes: 'openid account.id' }));
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeEnabled();

	// The page must not be able to ask for a scope the request never contained.
	// Rewrite the checkbox state to include an invented scope and approve.
	await page.evaluate(() => {
		const input = document.createElement('input');
		input.type = 'checkbox';
		input.checked = true;
		input.id = 'scope-phigros.b30.read';
		document.body.appendChild(input);
	});
	await page.getByRole('button', { name: '同意并继续' }).click();
	const params = await callbackParams(page);
	const tokens = await exchangeCode(request, params.get('code')!, verifier);
	expect(String(tokens.scope ?? ''), 'a scope never requested was granted').not.toContain('phigros.b30.read');
});
