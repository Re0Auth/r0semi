import AxeBuilder from '@axe-core/playwright';
import { expect, test } from './fixtures';
import { authorizeURL, beginDevice, pkce, signIn } from './helpers';
import { DEFAULT_SCOPES } from './env';
import type { Page } from '@playwright/test';

// Accessibility is checked by a tool rather than by reading markup, for the same
// reason the flows are checked by a real browser: "it looks right to me" is not a
// check, and the failures that matter (a control with no accessible name, a
// contrast ratio three shades too light, a landmark that never got a heading) are
// invisible to whoever wrote the markup.
//
// `svelte-check` already catches the a11y rules it knows about statically. This is
// the other half: the rendered page, with the data, in the states a person sees.
//
// A violation fails the run and prints which rule, which element and why — a bare
// "1 violation" tells nobody what to fix.

async function audit(page: Page) {
	// Audit the settled page. The reveal/enter animations fade a surface in over
	// 200–300ms, and axe samples whatever it is given: run mid-flight and every
	// colour in the card is measured at that moment's opacity, which reports
	// contrast failures that no person ever reads and that change from run to run.
	// Reduced motion collapses those animations to 0.01ms (app.css), so the audit
	// sees the colours the design actually specifies.
	await page.emulateMedia({ reducedMotion: 'reduce' });

	// The default ruleset, minus nothing: a rule silenced here would be one this
	// suite claims to check and does not. If one turns out to be wrong for a page,
	// that belongs in a comment next to a `.disableRules([...])` with the reason.
	const results = await new AxeBuilder({ page }).analyze();
	const findings = results.violations.flatMap((violation) =>
		violation.nodes.map(
			(node) =>
				`${violation.id} [${violation.impact}]: ${node.target.join(' ')}\n` +
				`      ${violation.help}\n      ${node.failureSummary ?? ''}`
		)
	);
	expect(findings, 'axe found accessibility violations').toEqual([]);
}

test('the sign-in page passes an audit', async ({ page }) => {
	await page.goto('/app/');
	await expect(page.getByRole('button', { name: '使用 GitHub 登录' })).toBeVisible();
	await audit(page);
});

test('the account page passes an audit', async ({ page }) => {
	await signIn(page);
	await expect(page.getByText('账号 ID')).toBeVisible();
	await audit(page);
});

test('the grants and sources pages pass an audit', async ({ page }) => {
	await signIn(page);

	// Empty states are pages too, and they are the ones nobody looks at twice.
	await page.goto('/app/grants');
	await expect(page.getByText('还没有应用获得授权。')).toBeVisible();
	await audit(page);

	await page.goto('/app/sources');
	await expect(page.getByRole('heading', { name: '数据源' })).toBeVisible();
	await audit(page);
});

test('the consent screen passes an audit', async ({ page }) => {
	await signIn(page);
	const { challenge } = pkce();
	await page.goto(authorizeURL({ challenge, scopes: DEFAULT_SCOPES }));
	await expect(page.getByRole('button', { name: '同意并继续' })).toBeVisible();
	await audit(page);
});

test('the device verification page passes an audit', async ({ page, request }) => {
	await signIn(page);
	const device = await beginDevice(request, 'account.id');
	await page.goto(`/app/device?user_code=${encodeURIComponent(device.user_code)}`);
	await expect(page.getByRole('button', { name: '批准' })).toBeVisible();
	await audit(page);
});
