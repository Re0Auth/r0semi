import { expect, test } from './fixtures';
import { signIn } from './helpers';

// A custom OIDC provider is any issuer named under `[idp.<name>]`: a self-hosted
// Keycloak/Authentik/Passkey login, or any OpenID Provider. This goes through the
// real thing — discovery, a signed id_token verified against the provider's JWKS,
// and the configured display name — because the fake signs with a real key. It is
// what makes "plug in your own IdP" a claim with a test behind it rather than a
// config field nobody has run.

test('signs in through a custom OIDC provider', async ({ page }) => {
	await signIn(page, 'oidc-tester', 'Authentik');

	// The linked identity names the custom provider, so this account is keyed
	// under `(authentik, …)` and not confused with a built-in one.
	await expect(page.getByText('authentik · oidc@example.com')).toBeVisible();
});
