import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('../ui-e2e/node_modules/playwright');

const BASE_URL = process.env.PROD_BASE_URL || 'https://gateway.prod.test:18443';
const AUTH_URL = process.env.PROD_AUTH_URL || 'https://auth.prod.test:18443';
const ADMIN_KEY = process.env.PROD_MASTER_ADMIN_KEY || 'sk-gw-prod-test-master-admin-key-2026-secure';

async function keycloakSignIn(page, username, password) {
  await page.locator('#username').waitFor({ state: 'visible', timeout: 15000 });
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#kc-login').click();
}

async function run() {
  const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP *.prod.test 127.0.0.1'],
  });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  const pageErrors = [];
  const consoleErrors = [];
  let allowExpected403 = false;
  page.on('pageerror', (err) => pageErrors.push(err.message));
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const txt = msg.text();
      if (!txt.includes('401') && !(allowExpected403 && txt.includes('403'))) {
        consoleErrors.push(txt);
      }
    }
  });

  try {
    // 1. Load /ui/ over TLS 1.3 and verify strict CSP + OIDC-only LoginView
    const uiResp = await page.goto(`${BASE_URL}/ui/`, { waitUntil: 'networkidle' });
    assert(uiResp && uiResp.status() === 200, `expected 200 from ${BASE_URL}/ui/`);
    const headers = uiResp.headers();
    assert((headers['strict-transport-security'] || '').includes('max-age='), 'expected HSTS header on /ui/');
    assert((headers['content-security-policy'] || '').toLowerCase().includes("script-src 'self'"), 'expected strict CSP');

    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });
    const kcBtn = page.getByRole('button', { name: /Continue with Keycloak Production/i });
    await kcBtn.waitFor({ state: 'visible' });

    // 2. Full PKCE S256 browser login against live Keycloak 26 as platform_admin
    await kcBtn.click();
    await page.waitForURL((u) => u.href.startsWith(`${AUTH_URL}/realms/goroute-prod/`), { timeout: 15000 });
    await keycloakSignIn(page, 'admin@goroute.local', 'ProdAdmin!2026');

    await page.waitForURL((u) => u.href.startsWith(`${BASE_URL}/ui`), { timeout: 15000 });
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible', timeout: 15000 });

    // Verify HttpOnly + Secure cookie isolation & persistence across reload (across 2 replicas)
    const cookies = await context.cookies(BASE_URL);
    const sessCookie = cookies.find((c) => c.name === 'goroute_session');
    assert(sessCookie, 'goroute_session cookie must be present');
    assert.equal(sessCookie.httpOnly, true, 'goroute_session must be HttpOnly');
    assert.equal(sessCookie.secure, true, 'goroute_session must be Secure');
    const docCookie = await page.evaluate(() => document.cookie);
    assert.equal(docCookie.includes('goroute_session'), false, 'goroute_session must not leak to document.cookie');

    await page.reload({ waitUntil: 'networkidle' });
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });
    await page.locator('aside button', { hasText: 'Gateway Config' }).click();
    await page.getByRole('button', { name: 'Rotate KEK' }).waitFor({ state: 'visible' });

    // 3. /ui/cli device approval flow while authenticated via live Keycloak session
    const cliStartRes = await page.evaluate(async () => {
      const r = await fetch('/auth/cli/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'keycloak' }),
      });
      return { status: r.status, body: await r.json() };
    });
    assert.equal(cliStartRes.status, 200, `POST /auth/cli/start failed: ${JSON.stringify(cliStartRes)}`);
    assert(cliStartRes.body.verification_url.startsWith(`${BASE_URL}/ui/cli?`), `unexpected verification_url: ${cliStartRes.body.verification_url}`);

    await page.goto(cliStartRes.body.verification_url, { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'Approve CLI Login' }).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: /Approve CLI Login/i }).click();
    await page.getByText('CLI Session Approved').waitFor({ state: 'visible' });

    const cliPollRes = await page.evaluate(async (loginId) => {
      const r = await fetch(`/auth/cli/poll/${encodeURIComponent(loginId)}`);
      return { status: r.status, body: await r.json() };
    }, cliStartRes.body.login_id);
    assert.equal(cliPollRes.status, 200, `GET /auth/cli/poll failed: ${JSON.stringify(cliPollRes)}`);
    assert.equal(cliPollRes.body.status, 'completed');
    assert(cliPollRes.body.api_key && cliPollRes.body.api_key.startsWith('sk-gw-'), 'expected minted sk-gw key');

    // 4. Seamless RP-Initiated Logout (with Vault-decrypted id_token_hint -> NO Keycloak confirmation prompt!)
    const logoutNavUrls = [];
    const onReq = (req) => {
      if (req.url().includes('/protocol/openid-connect/logout')) {
        logoutNavUrls.push(req.url());
      }
    };
    page.on('request', onReq);
    const logoutRespPromise = page.waitForResponse((r) => r.url().includes('/auth/logout') && r.request().method() === 'POST');
    await page.locator('button[title*="Click to sign out"]').click();
    const logoutResp = await logoutRespPromise;
    assert.equal(logoutResp.status(), 200, 'POST /auth/logout must return 200');

    // Wait for automatic redirect through Keycloak logout back to /ui/ Sign In screen
    await page.waitForURL((u) => u.href.startsWith(`${BASE_URL}/ui`), { timeout: 15000 });
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible', timeout: 15000 });
    page.off('request', onReq);
    assert(
      logoutNavUrls.some((u) => u.includes('id_token_hint=') && u.includes('post_logout_redirect_uri=')),
      `expected browser navigation to Keycloak RP-Initiated Logout with id_token_hint, saw: ${JSON.stringify(logoutNavUrls)}`
    );

    // Confirm Keycloak SSO session was genuinely terminated: clicking Keycloak login MUST prompt for credentials again
    await page.getByRole('button', { name: /Continue with Keycloak Production/i }).click();
    await page.waitForURL((u) => u.href.startsWith(`${AUTH_URL}/realms/goroute-prod/`), { timeout: 15000 });
    await page.locator('#username').waitFor({ state: 'visible', timeout: 15000 });

    // 5. Sign in as org_admin and verify ConfigView hides Rotate KEK
    allowExpected403 = true;
    await keycloakSignIn(page, 'orgadmin@goroute.local', 'ProdOrgAdmin!2026');
    await page.waitForURL((u) => u.href.startsWith(`${BASE_URL}/ui`), { timeout: 15000 });
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });
    await page.locator('aside button', { hasText: 'Gateway Config' }).click();
    await page.getByRole('heading', { name: 'Gateway Configuration' }).waitFor({ state: 'visible' });
    assert.equal(await page.getByRole('button', { name: 'Rotate KEK' }).count(), 0, 'org_admin must not see Rotate KEK');
    allowExpected403 = false;

    await page.locator('button[title*="Click to sign out"]').click();
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible', timeout: 15000 });

    // 6. Break-Glass Key emergency tab works cleanly
    await page.getByRole('button', { name: /Break-Glass Key/i }).click();
    await page.locator('input[placeholder="Enter Master Admin Key..."]').fill(ADMIN_KEY);
    await page.getByRole('button', { name: /Unlock Break-Glass Session/i }).click();
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });
    await page.locator('button[title*="Click to sign out"]').click();
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    assert.deepEqual(pageErrors, [], `unexpected pageerror: ${JSON.stringify(pageErrors)}`);
    assert.deepEqual(consoleErrors, [], `unexpected console.error: ${JSON.stringify(consoleErrors)}`);

    console.log('PROD DOCKER UI E2E PASS: Live Keycloak 26 TLS PKCE login, HttpOnly/Secure cookie, /ui/cli approval, seamless id_token_hint RP-Initiated Logout, org_admin RBAC, and Break-Glass Key verified.');
  } finally {
    await context.close();
    await browser.close();
  }
}

run().catch((err) => {
  console.error('PROD DOCKER UI E2E FAILED:', err);
  process.exit(1);
});
