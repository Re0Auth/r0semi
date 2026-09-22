import { test as base } from '@playwright/test';

/**
 * The base test, with the failures that should never happen made loud.
 *
 * A 401 on /v1/sessions/current is how this app says "nobody is signed in yet",
 * and a 404 is how it says "that handle is gone" — both are expected all over
 * these specs. What is not expected is a 429 or a 5xx, and both mean the server
 * was unavailable rather than that the page was wrong.
 *
 * This exists because of a real afternoon: the suite passed alone and failed at
 * random in full, because every browser shares 127.0.0.1 and the server's
 * per-address limiter eventually refused a page load. The failure surfaced as a
 * missing element — the one symptom that says nothing about its cause. Now the
 * line above the failure says what actually happened.
 */
export const test = base.extend({
	page: async ({ page }, use, testInfo) => {
		page.on('response', async (res) => {
			if (res.status() !== 429 && res.status() < 500) return;
			let body = '';
			try {
				body = (await res.text()).replace(/\s+/g, ' ').slice(0, 160);
			} catch {
				body = '(body unavailable)';
			}
			console.log(`[${testInfo.title}] ${res.status()} ${res.url()} ${body}`);
		});
		await use(page);
	}
});

export { expect } from '@playwright/test';
