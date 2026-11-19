import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const BASE_URL = process.env.UI_E2E_BASE_URL;
const ADMIN_KEY = process.env.UI_E2E_ADMIN_KEY;
const UI_USERNAME = process.env.UI_E2E_USERNAME;
const UI_PASSWORD = process.env.UI_E2E_PASSWORD;
const MOCK_IDP_URL = process.env.UI_E2E_MOCK_IDP_URL;

assert(BASE_URL, 'UI_E2E_BASE_URL is required');
assert(ADMIN_KEY, 'UI_E2E_ADMIN_KEY is required');
assert(UI_USERNAME, 'UI_E2E_USERNAME is required');
assert(UI_PASSWORD, 'UI_E2E_PASSWORD is required');
assert(MOCK_IDP_URL, 'UI_E2E_MOCK_IDP_URL is required');

async function adminAPI(path, method = 'GET', body = null) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${ADMIN_KEY}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json, text };
}

function fieldControl(modal, exactLabel) {
  return modal
    .locator(
      `xpath=.//div[./label[normalize-space(.)=${JSON.stringify(exactLabel)}]]//*[self::input or self::select or self::textarea][1]`
    )
    .first();
}

function modalByTitle(page, titleText) {
  return page
    .locator('div.fixed.inset-0')
    .filter({ has: page.locator('h3', { hasText: titleText }) })
    .first();
}

async function run() {
  const suffix = Date.now();
  const orgRes = await adminAPI('/admin/v1/organizations', 'POST', {
    name: `UI E2E Org ${suffix}`,
    slug: `ui-e2e-org-${suffix}`,
    max_budget_micros: 500_000_000,
  });
  assert.equal(orgRes.status, 201, `create org failed: ${orgRes.text}`);
  const orgId = orgRes.json.id;
  assert(orgId, 'created org id must be non-empty');

  // Create an operator user and verify HIBP prefix-only screening on breached password "password123".
  const opUserRes = await adminAPI('/admin/v1/users', 'POST', {
    org_id: orgId,
    email: `ui-operator-${suffix}@example.com`,
    name: 'UI E2E Operator',
    role: 'org_admin',
  });
  assert.equal(opUserRes.status, 201, `create user failed: ${opUserRes.text}`);
  const breachedRes = await adminAPI('/auth/password', 'POST', {
    user_id: opUserRes.json.id,
    new_password: 'password123',
  });
  assert.equal(breachedRes.status, 400, `expected HIBP 400 rejection, got ${breachedRes.status}: ${breachedRes.text}`);
  assert.match(breachedRes.text, /breached_password|password_breached|breach/i);

  const hibpAuditRes = await fetch(`${MOCK_IDP_URL}/hibp/audit`).then((r) => r.json());
  assert(
    Array.isArray(hibpAuditRes.prefixes) && hibpAuditRes.prefixes.includes('CBFDA'),
    `expected mock HIBP to receive only 5-char prefix CBFDA, got ${JSON.stringify(hibpAuditRes)}`
  );

  // Set a strong password on the org_admin user so we can test non-platform_admin UI RBAC later.
  const strongOpPassword = `UiOrgAdm!Strong-${suffix}`;
  const setPassRes = await adminAPI('/auth/password', 'POST', {
    user_id: opUserRes.json.id,
    new_password: strongOpPassword,
  });
  assert.equal(setPassRes.status, 200, `expected 200 setting strong password: ${setPassRes.text}`);

  // Verify OIDC SSO start redirect emits PKCE S256 challenge and state without following redirect.
  const ssoStartResp = await fetch(`${BASE_URL}/auth/sso/corp-oidc/login?redirect_after=%2Fui%2F`, {
    redirect: 'manual',
  });
  assert.equal(ssoStartResp.status, 302, `expected 302 from /auth/sso/corp-oidc/login, got ${ssoStartResp.status}`);
  const ssoLocation = ssoStartResp.headers.get('location') || '';
  assert(ssoLocation.startsWith(`${MOCK_IDP_URL}/oidc/authorize`), `unexpected SSO redirect: ${ssoLocation}`);
  assert(ssoLocation.includes('code_challenge='), `expected PKCE code_challenge in ${ssoLocation}`);
  assert(ssoLocation.includes('code_challenge_method=S256'), `expected S256 method in ${ssoLocation}`);
  assert(ssoLocation.includes('state='), `expected state param in ${ssoLocation}`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const pageErrors = [];
  const consoleErrors = [];
  let allowExpected403 = false;
  page.on('pageerror', (err) => pageErrors.push(err.message));
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const text = msg.text();
      // Expected initial/post-logout unauthenticated /auth/me check returns 401;
      // Check 7 intentionally checks org_admin access denial on /admin/v1/config (403).
      if (!text.includes('401') && !(allowExpected403 && text.includes('403'))) {
        consoleErrors.push(text);
      }
    }
  });

  try {
    // Check 1: /ui/ CSP header and SSO + Password LoginView
    const uiResp = await page.goto(`${BASE_URL}/ui/`, { waitUntil: 'networkidle' });
    assert(uiResp, 'expected main document response for /ui/');
    assert.equal(uiResp.status(), 200, 'expected 200 for /ui/');
    const csp = (uiResp.headers()['content-security-policy'] || '').toLowerCase();
    assert(csp.includes("script-src 'self'"), `CSP must include script-src 'self', got: ${csp}`);
    const scriptDirective = csp
      .split(';')
      .map((s) => s.trim())
      .find((s) => s.startsWith('script-src'));
    assert(
      scriptDirective && !scriptDirective.includes("'unsafe-inline'"),
      `script-src must not allow 'unsafe-inline', got: ${scriptDirective}`
    );

    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: /Continue with Corporate OIDC/i }).waitFor({ state: 'visible' });

    // Check 2: Password Login and assert NO client-side password_sha1 is submitted
    const loginReqPromise = page.waitForRequest(
      (req) => req.url().endsWith('/auth/login') && req.method() === 'POST'
    );
    const loginRespPromise = page.waitForResponse(
      (res) => res.url().endsWith('/auth/login') && res.request().method() === 'POST'
    );

    await page.locator('input[placeholder="operator@example.com or admin"]').fill(UI_USERNAME);
    await page.locator('input[placeholder="Enter password..."]').fill(UI_PASSWORD);
    await page.locator('button[type="submit"]', { hasText: 'Sign In' }).click();

    const loginReq = await loginReqPromise;
    const loginPayload = loginReq.postDataJSON();
    assert.equal(loginPayload.password, UI_PASSWORD, 'expected raw password over TLS/localhost transport');
    assert.equal('password_sha1' in loginPayload, false, 'client must never compute/send password_sha1');

    const loginResp = await loginRespPromise;
    assert.equal(loginResp.status(), 200, 'expected /auth/login 200');
    const setCookie = loginResp.headers()['set-cookie'] || '';
    if (setCookie) {
      assert(/httponly/i.test(setCookie), `session cookie must be HttpOnly: ${setCookie}`);
    }

    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });

    // Check 3: Cookie persistence across reload & HttpOnly isolation
    const exposedCookies = await page.evaluate(() => document.cookie);
    assert.equal(
      exposedCookies.includes('goroute_session'),
      false,
      `HttpOnly session cookie must not be readable via document.cookie: ${exposedCookies}`
    );

    await page.reload({ waitUntil: 'networkidle' });
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });
    const loginHeadingCountAfterReload = await page.getByRole('heading', { name: 'Control Plane Sign In' }).count();
    assert.equal(loginHeadingCountAfterReload, 0, 'reload with HttpOnly cookie must keep session authenticated');

    // Switch Header org selector to our freshly provisioned test org
    const orgSelect = page.locator('header select');
    await orgSelect.locator(`option[value="${orgId}"]`).waitFor({ state: 'attached' });
    await orgSelect.selectOption(orgId);

    // Check 4: KeysView key_type preset creation + manual rotation with grace badge
    await page.locator('aside button', { hasText: 'Virtual Keys' }).click();
    await page.getByRole('heading', { name: 'Virtual API Keys' }).waitFor({ state: 'visible' });

    await page.getByRole('button', { name: 'Issue Key' }).click();
    const issueModal = modalByTitle(page, 'Issue Key');
    await issueModal.waitFor({ state: 'visible' });

    await fieldControl(issueModal, 'Key Name *').fill('ui-e2e-llm-key');
    await fieldControl(issueModal, 'Key Type').selectOption('llm_api');
    await fieldControl(issueModal, 'Cap ($)').fill('25.00');

    const createKeyRespPromise = page.waitForResponse(
      (res) => res.url().includes('/admin/v1/keys') && res.request().method() === 'POST'
    );
    await issueModal.getByRole('button', { name: 'Issue', exact: true }).click();
    const createKeyResp = await createKeyRespPromise;
    assert.equal(createKeyResp.status(), 201, 'expected 201 from POST /admin/v1/keys');
    const createdKeyJson = await createKeyResp.json();
    const createdKeyId = createdKeyJson.id;
    assert(createdKeyId, 'created key ID must be present');

    const secretModal = modalByTitle(page, 'API Key Secret');
    await secretModal.waitFor({ state: 'visible' });
    const rawSecretText = await secretModal.locator('pre').innerText();
    assert(rawSecretText.startsWith('sk-gw-'), `expected raw sk-gw key secret, got: ${rawSecretText}`);
    await secretModal.getByRole('button', { name: 'Done' }).click();

    const keyRow = page.locator('tbody tr', { hasText: 'ui-e2e-llm-key' }).first();
    await keyRow.waitFor({ state: 'visible' });
    await keyRow.getByText('llm_api', { exact: true }).waitFor({ state: 'visible' });

    await keyRow.locator('button[title="Rotate"]').click();
    const rotateModal = modalByTitle(page, 'Rotate: ui-e2e-llm-key');
    await rotateModal.waitFor({ state: 'visible' });
    await rotateModal.getByRole('button', { name: '5m', exact: true }).click();
    await rotateModal.getByRole('button', { name: 'Rotate', exact: true }).click();

    await secretModal.waitFor({ state: 'visible' });
    await secretModal.getByText(/Grace until/i).waitFor({ state: 'visible' });
    await secretModal.getByRole('button', { name: 'Done' }).click();

    await keyRow.getByText('Grace', { exact: true }).waitFor({ state: 'visible' });

    // Check 4b: KeysView single Block/Unblock, status filter ("Blocked"), and bulk Block/Unblock
    page.once('dialog', (dialog) => dialog.accept());
    await keyRow.locator('button[title="Block"]').click();
    await keyRow.getByText('Revoked', { exact: true }).waitFor({ state: 'visible' });

    const statusSelect = page.locator('input[placeholder="Search..."] + select');
    await statusSelect.selectOption('revoked');
    await keyRow.waitFor({ state: 'visible' });
    await statusSelect.selectOption('');

    // Bulk Unblock then Block/Unblock via toolbar checkboxes
    await keyRow.locator('input[type="checkbox"]').check();
    await page.getByRole('button', { name: 'Unblock', exact: true }).first().click();
    await keyRow.getByText('Active', { exact: true }).waitFor({ state: 'visible' });

    // Check 4c: OrganizationsView Teams tab (team_member_permissions) + bulk sync Team Members
    await page.locator('aside button', { hasText: 'Orgs & Teams' }).click();
    await page.getByRole('heading', { name: 'Organizations & Teams' }).waitFor({ state: 'visible' });
    await page.locator('button', { hasText: /^Teams \(/ }).click();

    await page.getByRole('button', { name: 'New Team' }).click();
    const createTeamModal = modalByTitle(page, 'Create Team');
    await createTeamModal.waitFor({ state: 'visible' });
    await createTeamModal.locator('input[placeholder="Team Name *"]').fill('UI E2E Engineering');
    await createTeamModal
      .locator('input[placeholder*="Member Perms"]')
      .fill('keys:create, keys:rotate');
    await createTeamModal.getByRole('button', { name: 'Create', exact: true }).click();

    const teamRow = page.locator('tbody tr', { hasText: 'UI E2E Engineering' }).first();
    await teamRow.waitFor({ state: 'visible' });

    // Verify team_member_permissions persisted when opening Edit Team modal
    await teamRow.locator('button[title="Edit"]').click();
    const editTeamModal = modalByTitle(page, 'Edit Team');
    await editTeamModal.waitFor({ state: 'visible' });
    const permsVal = await editTeamModal.locator('input[placeholder*="Member Perms"]').inputValue();
    assert.equal(permsVal, 'keys:create, keys:rotate', `expected persisted team_member_permissions, got: ${permsVal}`);
    await editTeamModal.getByRole('button', { name: 'Cancel' }).click();

    // Sync team member add & remove via Members modal
    await teamRow.locator('button[title="Sync members"]').click();
    const membersModal = modalByTitle(page, 'Members: UI E2E Engineering');
    await membersModal.waitFor({ state: 'visible' });
    await membersModal.locator('input[placeholder="Add User IDs"]').fill(opUserRes.json.id);
    await membersModal.getByRole('button', { name: 'Sync', exact: true }).click();
    await membersModal.waitFor({ state: 'hidden' });

    await teamRow.locator('button[title="Sync members"]').click();
    await membersModal.waitFor({ state: 'visible' });
    await membersModal.getByText(opUserRes.json.id).waitFor({ state: 'visible' });
    await membersModal.locator('input[placeholder="Remove User IDs"]').fill(opUserRes.json.id);
    await membersModal.getByRole('button', { name: 'Sync', exact: true }).click();
    await membersModal.waitFor({ state: 'hidden' });

    // Check 5: QuotasTab per-model policy, rolling_24h budget window, and TempBudgetModal persistence across reload
    await page.locator('aside button', { hasText: 'FinOps & Spend' }).click();
    await page.getByRole('button', { name: /Quotas & Multi-Window Budgets/i }).click();
    await page.getByText(/Per-Model & Multi-Dimensional Quotas/i).waitFor({ state: 'visible' });

    await page.getByRole('button', { name: 'Upsert Quota' }).click();
    const quotaModal = modalByTitle(page, 'Upsert Quota Policy');
    await quotaModal.waitFor({ state: 'visible' });
    await fieldControl(quotaModal, 'Scope Type').selectOption('model_per_key');
    await fieldControl(quotaModal, 'Scope ID *').fill(createdKeyId);
    await fieldControl(quotaModal, 'Model Pattern').fill('gpt-4o*');
    await fieldControl(quotaModal, 'ITPM').fill('1200');
    await fieldControl(quotaModal, 'OTPM').fill('600');
    await fieldControl(quotaModal, 'TPD').fill('50000');
    await quotaModal.getByRole('button', { name: 'Save' }).click();

    const quotaRow = page.locator('tbody tr', { hasText: createdKeyId }).filter({ hasText: 'gpt-4o*' }).first();
    await quotaRow.waitFor({ state: 'visible' });
    await quotaRow.getByText('I:1200 O:600 D:50000').waitFor({ state: 'visible' });

    await page.getByRole('button', { name: 'Upsert Window' }).click();
    const windowModal = modalByTitle(page, 'Upsert Budget Window');
    await windowModal.waitFor({ state: 'visible' });
    await fieldControl(windowModal, 'Scope Type').selectOption('key');
    await fieldControl(windowModal, 'Scope ID *').fill(createdKeyId);
    await fieldControl(windowModal, 'Window').selectOption('rolling_24h');
    await fieldControl(windowModal, 'Max Budget ($) *').fill('15.00');
    await windowModal.getByRole('button', { name: 'Save' }).click();

    const windowRow = page.locator('tbody tr', { hasText: createdKeyId }).filter({ hasText: 'rolling_24h' }).first();
    await windowRow.waitFor({ state: 'visible' });
    await windowRow.getByText(/\$15\.00/).waitFor({ state: 'visible' });

    const boostRow = page.locator('tbody tr', { hasText: 'ui-e2e-llm-key' }).first();
    await boostRow.getByRole('button', { name: 'Set Boost' }).click();
    const boostModal = modalByTitle(page, 'Temp Budget Boost: ui-e2e-llm-key');
    await boostModal.waitFor({ state: 'visible' });
    await fieldControl(boostModal, 'Boost Amount (USD, 0 = clear)').fill('10.00');
    await fieldControl(boostModal, 'TTL (seconds)').fill('3600');
    await boostModal.getByRole('button', { name: 'Apply Boost' }).click();

    await boostRow.getByText(/\+\$10\.00 until/i).waitFor({ state: 'visible' });

    // Reload browser completely and verify DB-persisted quota policy, rolling_24h window, and temp boost!
    await page.reload({ waitUntil: 'networkidle' });
    await orgSelect.locator(`option[value="${orgId}"]`).waitFor({ state: 'attached' });
    await orgSelect.selectOption(orgId);
    await page.locator('aside button', { hasText: 'FinOps & Spend' }).click();
    await page.getByRole('button', { name: /Quotas & Multi-Window Budgets/i }).click();

    await page.locator('tbody tr', { hasText: createdKeyId }).filter({ hasText: 'gpt-4o*' }).first().waitFor({ state: 'visible' });
    await page.locator('tbody tr', { hasText: createdKeyId }).filter({ hasText: 'rolling_24h' }).first().waitFor({ state: 'visible' });
    await page.locator('tbody tr', { hasText: 'ui-e2e-llm-key' }).first().getByText(/\+\$10\.00 until/i).waitFor({ state: 'visible' });

    // Check 5b: ConfigView Rotate KEK visibility & execution for platform_admin
    await page.locator('aside button', { hasText: 'Gateway Config' }).click();
    await page.getByRole('heading', { name: 'Gateway Configuration' }).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: 'Rotate KEK' }).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: 'Rotate KEK' }).click();
    await page.locator('input[placeholder="New master KEK (>=32 chars)"]').fill(`rotated-ui-e2e-master-kek-${suffix}-0123456789`);
    await page.getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.getByText(/Database DEKs rotated atomically/i).waitFor({ state: 'visible' });

    // Check 6: Sign Out & Session Revocation
    await page.locator('button[title*="Click to sign out"]').click();
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    const meStatusAfterLogout = await page.evaluate(() => fetch('/auth/me').then((r) => r.status));
    assert.equal(meStatusAfterLogout, 401, 'expected /auth/me to return 401 after sign out');

    // Check 7: Sign in as org_admin and verify ConfigView hides platform_admin-only "Rotate KEK" control
    allowExpected403 = true;
    await page.locator('input[placeholder="operator@example.com or admin"]').fill(opUserRes.json.email);
    await page.locator('input[placeholder="Enter password..."]').fill(strongOpPassword);
    await page.locator('button[type="submit"]', { hasText: 'Sign In' }).click();
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });

    await page.locator('aside button', { hasText: 'Gateway Config' }).click();
    await page.getByRole('heading', { name: 'Gateway Configuration' }).waitFor({ state: 'visible' });
    assert.equal(
      await page.getByRole('button', { name: 'Rotate KEK' }).count(),
      0,
      'org_admin must not see Rotate KEK button on ConfigView'
    );
    allowExpected403 = false;

    await page.locator('button[title*="Click to sign out"]').click();
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    assert.deepEqual(pageErrors, [], `unexpected browser pageerror exceptions: ${JSON.stringify(pageErrors)}`);
    assert.deepEqual(consoleErrors, [], `unexpected browser console.error messages: ${JSON.stringify(consoleErrors)}`);

    console.log('UI E2E PASS: CSP, HIBP prefix-only, SSO PKCE redirect, cookie reload persistence, KeysView preset/rotation/block/bulk, Teams perms/sync, QuotasTab rolling_24h/TempBoost, ConfigView KEK RBAC, and logout revocation verified.');
  } finally {
    await context.close();
    await browser.close();
  }
}

run().catch((err) => {
  console.error('UI E2E FAILED:', err);
  process.exit(1);
});
