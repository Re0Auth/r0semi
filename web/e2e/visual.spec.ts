import { expect, test, type Locator, type Page } from './fixtures';
import { authorizeURL, beginDevice, pkce, signIn } from './helpers';
import { DEFAULT_SCOPES } from './env';

// Visual regression. The other specs assert behaviour; these assert that a page
// still *looks* like itself, which is the only check that catches a stylesheet
// change nobody meant to make, a token edited to the wrong shade, or a layout that
// only collapses at one width.
//
// They are tagged `@visual` and excluded from the default run (`pnpm run
// test:e2e`), because a visual test with no baseline fails by definition — and
// baselines are **per platform**: font rasterisation differs enough between
// Linux, macOS and Windows that one platform's baseline is a guaranteed failure
// on another. The configuration keeps them apart
// (`snapshotPathTemplate` with `{platform}`), and the Linux set is produced by the
// `visual-baselines` workflow; web/README.md has the two-step.
//
// Both themes are covered rather than one: the tokens are two full sets, and a
// change that reads fine on light can be invisible-on-invisible on dark.

/** A page screenshot with the volatile parts masked. */
async function shot(page: Page, name: string, mask: Locator[] = []) {
	await expect(page).toHaveScreenshot(name, { fullPage: true, mask });
}

/** The account's `usr_…` id: generated per account, so never baseline material. */
const accountID = (page: Page) => page.locator('p.font-mono');
/**
 * The device code and its countdown: both generated, and the countdown ticks. The
 * code is `text-sm` and the scope ids below it are `text-xs`, so this masks the
 * code without also hiding the scope list — masking a static identifier would keep
 * the test green while removing the coverage it was there for.
 */
const deviceVolatile = (page: Page) => [
	page.locator('p.font-mono.text-sm'),
	page.locator('p.tabular-nums')
];

/**
 * The authorization request id, which the consent page prints and the server mints
 * per request. Masked by its own text rather than by position: a mask aimed at "the
 * second row" would keep passing after someone reordered the list, silently
 * covering the wrong thing and losing the coverage it was supposed to keep.
 */
const requestID = (page: Page) => page.getByText(requestIDOf(page), { exact: true });

function requestIDOf(page: Page): string {
	const id = new URL(page.url()).searchParams.get('id') ?? '';
	// The consent URL carries it; a mask list built from nothing would make this
	// baseline compare a page whose volatile part is still visible.
	if (!id) throw new Error(`the consent URL has no id: ${page.url()}`);
	return id;
}

for (const theme of ['light', 'dark'] as const) {
	test.describe(`${theme} theme`, () => {
		test.use({ colorScheme: theme });

		test('the sign-in page', { tag: '@visual' }, async ({ page }) => {
			await page.goto('/app/');
			await expect(page.getByRole('button', { name: '使用 GitHub 登录' })).toBeVisible();
			await shot(page, `sign-in-${theme}.png`);
		});

		test('the account page', { tag: '@visual' }, async ({ page }) => {
			await signIn(page, 'visual-account');
			await expect(page.getByText('账号 ID')).toBeVisible();
			await shot(page, `account-${theme}.png`, [accountID(page)]);
		});

		test('an empty grants list and the sources', { tag: '@visual' }, async ({ page }) => {
			await signIn(page, 'visual-account');

			// Empty states are pages too, and the ones nobody looks at twice.
			await page.goto('/app/grants');
			await expect(page.getByText('还没有应用获得授权。')).toBeVisible();
			await shot(page, `grants-empty-${theme}.png`);

			await page.goto('/app/sources');
			await expect(page.getByRole('heading', { name: '数据源' })).toBeVisible();
			await shot(page, `sources-${theme}.png`);
		});

		test('the consent screen', { tag: '@visual' }, async ({ page }) => {
			await signIn(page, 'visual-account');
			const { challenge } = pkce();
			await page.goto(authorizeURL({ challenge, scopes: DEFAULT_SCOPES }));
			await expect(page.getByRole('button', { name: '同意并继续' })).toBeVisible();
			await shot(page, `consent-${theme}.png`, [requestID(page)]);
		});

		test('the device verification page', { tag: '@visual' }, async ({ page, request }) => {
			await signIn(page, 'visual-account');
			const device = await beginDevice(request, 'account.id');
			await page.goto(`/app/device?user_code=${encodeURIComponent(device.user_code)}`);
			await expect(page.getByRole('button', { name: '批准' })).toBeVisible();
			await shot(page, `device-${theme}.png`, deviceVolatile(page));
		});
	});
}
