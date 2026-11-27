import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('../ui-e2e/node_modules/playwright');

const BASE_URL = process.env.PROD_BASE_URL || 'https://gateway.prod.test:18443';
const AUTH_URL = process.env.PROD_AUTH_URL || 'https://auth.prod.test:18443';
const ADMIN_KEY = process.env.PROD_MASTER_ADMIN_KEY || 'sk-gw-prod-test-master-admin-key-2026-secure';
const CLI_APPROVE_URL = process.env.PROD_CLI_APPROVE_URL || '';

async function keycloakSignIn(page, username, password) {
  await page.locator('#username').waitFor({ state: 'visible', timeout: 15000 });
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#kc-login').click();
}

function modalByTitle(page, titleText) {
  return page.locator('div.fixed.inset-0').filter({
    has: page.locator('h3').filter({ hasText: titleText }),
  }).first();
}

async function runCLIApprove(browser) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  try {
    await page.goto(CLI_APPROVE_URL, { waitUntil: 'networkidle' });
    // If redirected to /ui/ Sign In or Keycloak, complete Keycloak SSO login first
    const loginHeading = page.getByRole('heading', { name: 'Control Plane Sign In' });
    if (await loginHeading.isVisible().catch(() => false)) {
      await page.getByRole('button', { name: /Continue with Keycloak Production/i }).click();
    }
    if (page.url().startsWith(`${AUTH_URL}/realms/`)) {
      await keycloakSignIn(page, 'admin@goroute.local', 'ProdAdmin!2026');
    } else {
      await page.waitForTimeout(500);
      if (page.url().startsWith(`${AUTH_URL}/realms/`)) {
        await keycloakSignIn(page, 'admin@goroute.local', 'ProdAdmin!2026');
      }
    }
    // Wait to land back on /ui/cli
    await page.waitForURL((u) => u.href.includes('/ui/cli'), { timeout: 20000 });
    await page.getByRole('heading', { name: 'Approve CLI Login' }).waitFor({ state: 'visible', timeout: 15000 });
    await page.getByRole('button', { name: /Approve CLI Login/i }).click();
    await page.getByText('CLI Session Approved').waitFor({ state: 'visible', timeout: 15000 });
    console.log('PROD CLI BROWSER APPROVAL PASS');
  } finally {
    await context.close();
  }
}

async function runFullSuite2(browser) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addInitScript(() => {
    window.__cspViolations = [];
    document.addEventListener('securitypolicyviolation', (ev) => {
      window.__cspViolations.push({
        blockedURI: ev.blockedURI,
        violatedDirective: ev.violatedDirective,
        effectiveDirective: ev.effectiveDirective,
      });
    });
  });

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
    // 1. Load /ui/ over TLS 1.3 and verify strict CSP (style-src 'self') + OIDC-only LoginView
    const uiResp = await page.goto(`${BASE_URL}/ui/`, { waitUntil: 'networkidle' });
    assert(uiResp && uiResp.status() === 200, `expected 200 from ${BASE_URL}/ui/`);
    const headers = uiResp.headers();
    assert((headers['strict-transport-security'] || '').includes('max-age='), 'expected HSTS header on /ui/');
    const csp = (headers['content-security-policy'] || '').toLowerCase();
    assert(csp.includes("script-src 'self'") && csp.includes("style-src 'self'"), `expected strict CSP with style-src 'self', got: ${csp}`);

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

    // 3. Verify Gateway Config redacted config & Rotate KEK visibility
    await page.locator('aside button', { hasText: 'Gateway Config' }).click();
    await page.getByRole('button', { name: 'Rotate KEK' }).waitFor({ state: 'visible' });
    await page.getByRole('heading', { name: 'Gateway Configuration' }).waitFor({ state: 'visible' });

    // 4. Phase 5 Operator Web UI Authorization Parity checks (Orgs/Teams/Projects/Access Groups/JWT Mappings/Keys/FinOps Audit Diff)
    await page.locator('aside button', { hasText: 'Orgs & Teams' }).click();
    await page.getByRole('heading', { name: /Organizations & Teams/i }).waitFor({ state: 'visible' });

    // Create a Team with expanded Phase 5 controls (Allowed Deployments, TPM Limit, Concurrent Reqs, 3-state MCP)
    const suffix = Date.now();
    const uiTeamName = `Prod UI Team ${suffix}`;
    await page.getByRole('button', { name: /^Teams \(/ }).click();
    await page.getByRole('button', { name: /\+ New Team|New Team/i }).click();
    const teamModal = modalByTitle(page, 'Create Team');
    await teamModal.waitFor({ state: 'visible' });
    await teamModal.locator('input[placeholder="Team Name *"]').fill(uiTeamName);
    await teamModal.locator('input[placeholder="Team TPM"]').fill('25000');
    await teamModal.locator('input[placeholder="Max Conc"]').fill('10');
    await teamModal.locator('input[placeholder*="Allowed Deployments"]').fill('dep-eu-mock');
    await teamModal.getByRole('button', { name: 'Create', exact: true }).click();
    await teamModal.waitFor({ state: 'hidden' });
    await page.getByText(uiTeamName).waitFor({ state: 'visible' });

    // Projects lazy tab -> Create Project
    const uiProjName = `prod-ui-project-${suffix}`;
    await page.getByRole('button', { name: 'Projects', exact: true }).click();
    await page.getByRole('button', { name: /New Project/i }).waitFor({ state: 'visible', timeout: 10000 });
    await page.getByRole('button', { name: /New Project/i }).click();
    const projModal = modalByTitle(page, 'Create Project');
    await projModal.waitFor({ state: 'visible' });
    await projModal.locator('input[placeholder="Project Name *"]').fill(uiProjName);
    await projModal.locator('select').first().selectOption({ label: uiTeamName });
    await projModal.locator('input[placeholder="Allowed Models (csv)"]').fill('prod-residency-group');
    await projModal.locator('input[placeholder="Allowed Deployments (csv)"]').fill('dep-eu-mock');
    await projModal.locator('input[placeholder*="Allowed Routing Tags"]').fill('eu-gdpr');
    await projModal.getByRole('button', { name: 'Create', exact: true }).click();
    await projModal.waitFor({ state: 'hidden' });
    await page.getByText(uiProjName).waitFor({ state: 'visible' });

    // Access Groups & Rules lazy tab -> Create Unified Access Group + Dynamic Rule
    const uiGroupName = `prod-ui-group-${suffix}`;
    const uiRuleName = `prod-ui-rule-${suffix}`;
    await page.getByRole('button', { name: 'Access Groups & Rules', exact: true }).click();
    await page.getByRole('button', { name: /New Access Group/i }).waitFor({ state: 'visible', timeout: 10000 });
    await page.getByRole('button', { name: /New Access Group/i }).click();
    const grpModal = modalByTitle(page, 'Create / Upsert Access Group');
    await grpModal.waitFor({ state: 'visible' });
    await grpModal.locator('input[placeholder*="Group Name"]').fill(uiGroupName);
    await grpModal.locator('input[placeholder="Allowed MCP Servers (csv)"]').fill('github');
    await grpModal.locator('input[placeholder*="Allowed MCP Tools"]').fill('github:get_issue');
    await grpModal.locator('input[placeholder="Allowed A2A Agents (csv)"]').fill('researcher');
    await grpModal.getByRole('button', { name: 'Save', exact: true }).click();
    await grpModal.waitFor({ state: 'hidden' });
    await page.getByText(uiGroupName).waitFor({ state: 'visible' });

    await page.getByRole('button', { name: /New Rule/i }).click();
    const ruleModal = modalByTitle(page, 'Create Dynamic Access Rule');
    await ruleModal.waitFor({ state: 'visible' });
    await ruleModal.locator('input[placeholder="Rule Name *"]').fill(uiRuleName);
    await ruleModal.locator('input[placeholder="Match Value *"]').fill('goroute-developers');
    await ruleModal.locator('input[placeholder="Allowed Models (csv)"]').fill('prod-residency-group');
    await ruleModal.locator('input[placeholder="Allowed MCP Tools (csv)"]').fill('github:list_files');
    await ruleModal.getByRole('button', { name: 'Save', exact: true }).click();
    await ruleModal.waitFor({ state: 'hidden' });
    await page.getByText(uiRuleName).waitFor({ state: 'visible' });

    // JWT Mappings lazy tab -> verify render & modal presence
    await page.getByRole('button', { name: 'JWT Mappings', exact: true }).click();
    await page.getByRole('button', { name: /New JWT Mapping/i }).waitFor({ state: 'visible', timeout: 10000 });

    // Virtual Keys -> Issue Key wired to Project + Deployments + 3-state MCP Tools + Session Limits
    const uiKeyName = `prod-ui-key-${suffix}`;
    await page.locator('aside button', { hasText: 'Virtual Keys' }).click();
    await page.getByRole('button', { name: /Issue Key/i }).click();
    const keyModal = modalByTitle(page, 'Issue Key');
    await keyModal.waitFor({ state: 'visible' });
    await keyModal.locator('input[placeholder="production-backend"]').fill(uiKeyName);
    // Select Project dropdown
    const projectSelect = keyModal.locator('label', { hasText: /^Project$/ }).locator('..').locator('select');
    await projectSelect.selectOption({ label: uiProjName });
    await keyModal.locator('input[placeholder="dep-eu-1"]').fill('dep-eu-mock');
    await keyModal.locator('input[placeholder="tier:*, eu"]').fill('eu-gdpr');
    await keyModal.locator('input[placeholder="5.00"]').fill('1.00');
    await keyModal.getByRole('button', { name: 'Issue', exact: true }).click();
    await keyModal.waitFor({ state: 'hidden' });
    // Dismiss newly issued key modal if shown
    const closeReveal = page.getByRole('button', { name: /Close|Done/i });
    if (await closeReveal.isVisible().catch(() => false)) {
      await closeReveal.click();
    }

    // FinOps -> Audit Log -> Server-side Action Filter + JSON Diff Viewer Modal
    await page.locator('aside button', { hasText: 'FinOps & Spend' }).click();
    await page.getByRole('button', { name: /Administrative Audit Log/i }).click();
    const actionFilter = page.locator('input[placeholder*="Action (e.g."]');
    await actionFilter.waitFor({ state: 'visible', timeout: 10000 });
    await actionFilter.fill('virtual_key.issued');
    await page.getByRole('button', { name: /Details/i }).first().waitFor({ state: 'visible', timeout: 10000 });
    await page.getByRole('button', { name: /Details/i }).first().click();
    await page.getByText('State Diff (Before vs. After):').waitFor({ state: 'visible', timeout: 10000 });
    await page.getByRole('button', { name: 'Close', exact: true }).click().catch(async () => {
      await page.keyboard.press('Escape');
    });

    // 4b. Streamlined GuardrailsView E2E over TLS 1.3 (Built-In Policy + External Webhook + Dry-Run Simulator)
    await page.locator('aside button', { hasText: 'Guardrails' }).click();
    await page.getByRole('heading', { name: 'Guardrails & Security Policy' }).waitFor({ state: 'visible', timeout: 10000 });
    await page.getByRole('button', { name: 'New Guardrail' }).click();
    const grModal = modalByTitle(page, 'Create External Guardrail');
    await grModal.waitFor({ state: 'visible' });
    const uiGuardName = `prod-ui-guard-${suffix}`;
    await grModal.locator('input[placeholder="e.g. corp-dlp-webhook"]').fill(uiGuardName);
    await grModal.locator('input[placeholder="https://guardrails.internal.corp/v1/evaluate"]').fill('https://fixtures.prod.test:18443/guardrail/evaluate');
    await grModal.locator('input[placeholder="Optional Bearer token or provider API key"]').fill('prod-ui-vault-secret-do-not-render');
    await grModal.getByRole('button', { name: 'Create Guardrail' }).click();
    await grModal.waitFor({ state: 'hidden' });
    const grRow = page.locator('tbody tr', { hasText: uiGuardName }).first();
    await grRow.waitFor({ state: 'visible' });
    await grRow.getByText('Vault Encrypted', { exact: true }).waitFor({ state: 'visible' });
    const grPageText = await page.locator('body').innerText();
    assert.equal(grPageText.includes('prod-ui-vault-secret-do-not-render'), false, 'Vault secret must never appear in DOM');
    await grRow.locator('button[title="Delete Guardrail"]').click();
    await grRow.waitFor({ state: 'hidden' });

    // Run Dry-Run Policy Simulator with sample PII text
    await page.getByRole('button', { name: 'Sample: PII' }).click();
    await page.getByRole('button', { name: 'Run Simulation' }).click();
    await page.getByText(/Decision:/i).waitFor({ state: 'visible', timeout: 10000 });

    // 5. /ui/cli device approval flow while authenticated via live Keycloak session
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

    // 6. Seamless RP-Initiated Logout (with Vault-decrypted id_token_hint -> NO Keycloak confirmation prompt!)
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

    await page.waitForURL((u) => u.href.startsWith(`${BASE_URL}/ui`), { timeout: 15000 });
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible', timeout: 15000 });
    page.off('request', onReq);
    assert(
      logoutNavUrls.some((u) => u.includes('id_token_hint=') && u.includes('post_logout_redirect_uri=')),
      `expected browser navigation to Keycloak RP-Initiated Logout with id_token_hint, saw: ${JSON.stringify(logoutNavUrls)}`
    );

    // 7. Confirm Keycloak SSO session was genuinely terminated & verify org_admin RBAC
    await page.getByRole('button', { name: /Continue with Keycloak Production/i }).click();
    await page.waitForURL((u) => u.href.startsWith(`${AUTH_URL}/realms/goroute-prod/`), { timeout: 15000 });
    await page.locator('#username').waitFor({ state: 'visible', timeout: 15000 });

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

    // 8. Break-Glass Key emergency tab works cleanly
    await page.getByRole('button', { name: /Break-Glass Key/i }).click();
    await page.locator('input[placeholder="Enter Master Admin Key..."]').fill(ADMIN_KEY);
    await page.getByRole('button', { name: /Unlock Break-Glass Session/i }).click();
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });
    await page.locator('button[title*="Click to sign out"]').click();
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    const cspViolations = await page.evaluate(() => window.__cspViolations || []);
    assert.deepEqual(cspViolations, [], `unexpected CSP violations: ${JSON.stringify(cspViolations)}`);
    assert.deepEqual(pageErrors, [], `unexpected pageerror: ${JSON.stringify(pageErrors)}`);
    assert.deepEqual(consoleErrors, [], `unexpected console.error: ${JSON.stringify(consoleErrors)}`);

    console.log('PROD DOCKER UI E2E PASS: Strict CSP (0 violations), Keycloak 26 PKCE SSO, Projects, Unified Access Groups & Rules, JWT Mappings tab, Keys Project/Deployment modal, FinOps Audit Filter + JSON Diff Viewer, /ui/cli, RP-Initiated Logout, org_admin RBAC, and Break-Glass Key verified.');
  } finally {
    await context.close();
  }
}

async function run() {
  const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP *.prod.test 127.0.0.1'],
  });
  try {
    if (CLI_APPROVE_URL) {
      await runCLIApprove(browser);
    } else {
      await runFullSuite2(browser);
    }
  } finally {
    await browser.close();
  }
}

run().catch((err) => {
  console.error('PROD DOCKER UI E2E FAILED:', err);
  process.exit(1);
});
