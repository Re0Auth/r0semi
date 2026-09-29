// Zone 08 browser probe (round 7). Manual, not part of `go test` — the Go
// probes in this directory cover everything the wire can show; these two
// questions need a real engine.
//
// Run it against a memory-mode process on zone 08's port:
//
//	cd web && pnpm run build                 # so the binary embeds a real shell
//	taskkill /f /im re0auth.exe 2>nul
//	# start cmd/re0auth on 127.0.0.1:17801 with RE0AUTH_ADDR/ISSUER/KEK/
//	# OIDC_SIGNING_KEY/OIDC_TOKEN_KEY set (see .github/workflows/ci.yml)
//	node browser_probe.mjs http://127.0.0.1:17801
//
// It answers:
//   1. does the served document's own policy permit SvelteKit's inline
//      bootstrap — i.e. does the app render, and is the console free of CSP
//      violations? (A mismatch between the meta policy's script-src hash and the
//      emitted script is the blank-page regression the webui package documents.)
//   2. is the `?error=` value the SPA interpolates into the account page escaped
//      (a text node) or parsed as markup?
//
// Observed 2026-09-29 on HEAD bf81b2a (Chromium 1243, local build):
//   CONSENT_H1="授权请求"
//   CONSOLE=["error: Failed to load resource: ... 401 (Unauthorized)"]
//   PAGEERRORS=[]            CSP_VIOLATIONS=[]
//   ERROR_PAGE_HAS_PAYLOAD_TEXT=true   ERROR_PAGE_IMG_COUNT=0
//   ERROR_PAGE_WINDOW_FLAG=null
import { chromium } from 'file:///C:/git/r0semi/web/node_modules/playwright/index.mjs';

const base = process.argv[2];
const browser = await chromium.launch();
const page = await browser.newPage();

const consoleMessages = [];
const pageErrors = [];
page.on('console', (m) => consoleMessages.push(`${m.type()}: ${m.text()}`));
page.on('pageerror', (e) => pageErrors.push(String(e)));

await page.goto(`${base}/app/consent?id=does-not-matter`, { waitUntil: 'load' });
await page.waitForTimeout(1500);
const h1 = await page.locator('h1').first().textContent();
const cspViolations = consoleMessages.filter((m) => /Content Security Policy|Refused to/i.test(m));
console.log('CONSENT_H1=' + JSON.stringify(h1));
console.log('CONSOLE=' + JSON.stringify(consoleMessages));
console.log('PAGEERRORS=' + JSON.stringify(pageErrors));
console.log('CSP_VIOLATIONS=' + JSON.stringify(cspViolations));

const payload = '<img src=x onerror=window.__z08xss=1>';
await page.goto(`${base}/app/?error=${encodeURIComponent(payload)}`, { waitUntil: 'load' });
await page.waitForTimeout(1500);
const bodyText = await page.locator('body').innerText();
const imgCount = await page.locator('img').count();
const xss = await page.evaluate(() => window.__z08xss ?? null);
console.log('ERROR_PAGE_HAS_PAYLOAD_TEXT=' + bodyText.includes(payload));
console.log('ERROR_PAGE_IMG_COUNT=' + imgCount);
console.log('ERROR_PAGE_WINDOW_FLAG=' + JSON.stringify(xss));
console.log('ERROR_PAGE_TEXT=' + JSON.stringify(bodyText.slice(0, 400)));

await browser.close();
