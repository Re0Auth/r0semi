import { expect, test } from './fixtures';
import { idpBase } from './env';
import { signIn } from './helpers';

// Identity management is the one part of the account whose failure mode is a
// locked-out user, so it is worth driving through a browser: link a second way
// in, remove the first, and confirm the last one gets no button at all.

/** Tells the fake IdP who the next sign-in (or link) should be. */
async function nextIdentity(identity: string) {
	const res = await fetch(`${idpBase}/__identity/${encodeURIComponent(identity)}`, { method: 'POST' });
	expect(res.ok, `the fake provider refused the identity: ${res.status}`).toBe(true);
}

// Identities are keyed by (provider, subject), so reusing a name across tests
// would make one test's linked identity leak into the next one's account. Each
// test names its own.
function myIdentities() {
	const scope = test.info().title;
	return { first: `${scope}-primary`, second: `${scope}-second` };
}

test('an identity can be linked and unlinked, but the last one stays', async ({ page }) => {
	const { first, second } = myIdentities();

	await nextIdentity(first);
	await signIn(page, first);

	// One identity is the whole account, so there is no way to remove it.
	await expect(page.getByText(`Octo ${first}`)).toBeVisible();
	await expect(page.getByRole('button', { name: '解绑', exact: true })).toHaveCount(0);

	// Linking is the opposite of signing in: it adds to the account already here.
	await nextIdentity(second);
	await page.getByRole('button', { name: /绑定 GitHub/ }).click();

	// The account is still the same one, now with two ways in.
	await expect(page.getByText(`Octo ${second}`)).toBeVisible();
	await expect(page.getByRole('button', { name: '解绑', exact: true })).toHaveCount(2);

	// Removing the first identity is allowed, and the session survives it.
	const primary = page.locator('li').filter({ hasText: `Octo ${first}` });
	await primary.getByRole('button', { name: '解绑', exact: true }).click();
	await primary.getByRole('button', { name: '确认解绑', exact: true }).click();

	await expect(page.getByText(`Octo ${first}`)).toHaveCount(0);
	await expect(page.getByText(`Octo ${second}`)).toBeVisible();

	// And the remaining identity is now the account, so it has no unlink button.
	await expect(page.getByRole('button', { name: '解绑', exact: true })).toHaveCount(0);
});

test('unlinking an identity can be backed out of', async ({ page }) => {
	const { first, second } = myIdentities();

	await nextIdentity(first);
	await signIn(page, first);
	await nextIdentity(second);
	await page.getByRole('button', { name: /绑定 GitHub/ }).click();
	await expect(page.getByText(`Octo ${second}`)).toBeVisible();

	const primary = page.locator('li').filter({ hasText: `Octo ${first}` });
	await primary.getByRole('button', { name: '解绑', exact: true }).click();
	await primary.getByRole('button', { name: '取消', exact: true }).click();

	await expect(page.getByText(`Octo ${first}`)).toBeVisible();
	await expect(page.getByRole('button', { name: '解绑', exact: true })).toHaveCount(2);
});
