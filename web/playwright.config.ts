import { defineConfig, devices } from '@playwright/test';
import { appBase, appPort, idpPort } from './e2e/env';

export default defineConfig({
	testDir: './e2e',

	// One worker, in order. The server rate-limits per client address, and every
	// test here comes from 127.0.0.1, so parallelism would turn a passing suite
	// into a flaky one for a reason that has nothing to do with the code.
	fullyParallel: false,
	workers: 1,

	// On CI a retry distinguishes a real race from a slow first paint. Locally a
	// retry would only hide flakiness from whoever can fix it.
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 1 : 0,
	reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',

	use: {
		baseURL: appBase,
		// A browser-test failure without a trace is a mystery, not a bug report.
		trace: 'on-first-retry',
		screenshot: 'only-on-failure'
	},

	projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

	webServer: {
		command: 'node e2e/server.mjs',
		// Ready when the discovery document answers — the same signal a real client
		// uses, so the wait is on the server being usable rather than merely alive.
		url: `${appBase}/.well-known/oauth-authorization-server`,
		env: { E2E_PORT: String(appPort), E2E_IDP_PORT: String(idpPort) },
		reuseExistingServer: !process.env.CI,
		timeout: 180_000,
		stdout: 'pipe',
		stderr: 'pipe'
	}
});
