// Zone 08 adversarial re-verification probe (round 7). Manual, not part of
// `go test`: it needs a real engine. It re-tests the one claim in
// Z08-frontend-browser.md that no Go probe can settle (Z08-8, the `?error=`
// interpolation) and independently checks the CSP claim in "探过没破" #7.
//
// It deliberately does not reuse the audited zone's script: a re-verification
// that runs the author's own probe only confirms the author's harness.
//
// Run against a memory-mode cmd/re0auth on the verifier's port (17802):
//   node browser_probe.mjs http://127.0.0.1:17802
//
// The escape detector has a positive control: the same locator/handler set is
// pointed at a data: URL that DOES execute, so "img count 0 / flag null" cannot
// be the result of a broken detector.

import { chromium } from 'file:///C:/git/r0semi/web/node_modules/playwright/index.mjs';

const base = process.argv[2] ?? 'http://127.0.0.1:17802';

const browser = await chromium.launch();
const page = await browser.newPage();
const consoleMessages = [];
const pageErrors = [];
page.on('console', (m) => consoleMessages.push(`${m.type()}: ${m.text()}`));
page.on('pageerror', (e) => pageErrors.push(String(e)));

// --- control: the app itself must render (a blank page would make the second
// half of this probe vacuous) ---
await page.goto(`${base}/app/consent?id=does-not-matter`, { waitUntil: 'load' });
await page.waitForTimeout(1500);
const consentH1 = await page.locator('h1').first().textContent();
const cspViolations = consoleMessages.filter((m) => /Content Security Policy|Refused to/i.test(m));

const payload = '<img src=x onerror=window.__z08xss=1>';
await page.goto(`${base}/app/?error=${encodeURIComponent(payload)}`, { waitUntil: 'load' });
await page.waitForTimeout(1500);
const bodyText = await page.locator('body').innerText();
const rawHtml = await page.content();
const imgCount = await page.locator('img').count();
const flag = await page.evaluate(() => window.__z08xss ?? null);

// --- positive control for the detector: the same payload in a document that is
// NOT escaped must set the flag, so "flag null" above is a real negative ---
const control = await browser.newPage();
await control.goto(`data:text/html,<body>${encodeURIComponent(payload)}</body>`);
await control.waitForTimeout(300);
const controlFlag = await control.evaluate(() => window.__z08xss ?? null);
const controlImgs = await control.locator('img').count();

console.log(JSON.stringify({
  consent_h1: consentH1,
  csp_violations: cspViolations,
  page_errors: pageErrors,
  payload_in_text: bodyText.includes(payload),
  payload_escaped_in_html: rawHtml.includes('&lt;img src=x onerror=window.__z08xss=1&gt;'),
  img_count: imgCount,
  window_flag: flag,
  control: { window_flag: controlFlag, img_count: controlImgs },
  body_excerpt: bodyText.slice(0, 200),
}, null, 2));

await browser.close();
if (controlFlag !== 1) {
  console.error('CONTROL FAILED: the detector cannot see executing markup; the escape conclusion is vacuous');
  process.exit(2);
}
if (flag !== null || imgCount !== 0) {
  console.error('XSS: the payload executed or parsed as markup');
  process.exit(3);
}
