import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const BASE_URL = process.env.UI_E2E_BASE_URL;
const ADMIN_KEY = process.env.UI_E2E_ADMIN_KEY;
const MOCK_IDP_URL = process.env.UI_E2E_MOCK_IDP_URL;

assert(BASE_URL, 'UI_E2E_BASE_URL is required');
assert(ADMIN_KEY, 'UI_E2E_ADMIN_KEY is required');
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

  // Create a user for team membership sync checks.
  const opUserRes = await adminAPI('/admin/v1/users', 'POST', {
    org_id: orgId,
    email: `ui-member-${suffix}@example.com`,
    name: 'UI E2E Member',
    role: 'developer',
  });
  assert.equal(opUserRes.status, 201, `create user failed: ${opUserRes.text}`);

  // Verify legacy local-password routes are removed in OIDC-only mode.
  for (const legacyPath of ['/auth/login', '/auth/password']) {
    const legacyResp = await fetch(`${BASE_URL}${legacyPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert(
      legacyResp.status === 404 || legacyResp.status === 405,
      `expected removed endpoint ${legacyPath} to return 404/405, got ${legacyResp.status}`
    );
  }

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
  const cspViolations = [];
  let allowExpected403 = false;
  await page.exposeFunction('__recordCSPViolation', (detail) => {
    cspViolations.push(detail);
  });
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      if (typeof window.__recordCSPViolation === 'function') {
        window.__recordCSPViolation(`${e.violatedDirective}: ${e.blockedURI || 'inline'}`);
      }
    });
  });
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
    // Check 1: /ui/ CSP header and OIDC-only LoginView
    const uiResp = await page.goto(`${BASE_URL}/ui/`, { waitUntil: 'networkidle' });
    assert(uiResp, 'expected main document response for /ui/');
    assert.equal(uiResp.status(), 200, 'expected 200 for /ui/');
    const csp = (uiResp.headers()['content-security-policy'] || '').toLowerCase();
    assert(csp.includes("script-src 'self'"), `CSP must include script-src 'self', got: ${csp}`);
    assert(csp.includes("style-src 'self'"), `CSP must include style-src 'self', got: ${csp}`);
    assert(!csp.includes("'unsafe-inline'"), `CSP must not allow 'unsafe-inline' in any directive, got: ${csp}`);
    const scriptDirective = csp
      .split(';')
      .map((s) => s.trim())
      .find((s) => s.startsWith('script-src'));
    assert(
      scriptDirective && !scriptDirective.includes("'unsafe-inline'"),
      `script-src must not allow 'unsafe-inline', got: ${scriptDirective}`
    );
    const styleDirective = csp
      .split(';')
      .map((s) => s.trim())
      .find((s) => s.startsWith('style-src'));
    assert(
      styleDirective && !styleDirective.includes("'unsafe-inline'"),
      `style-src must not allow 'unsafe-inline', got: ${styleDirective}`
    );

    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });
    assert.equal(
      await page.locator('input[autocomplete="current-password"]').count(),
      0,
      'LoginView must not render password input in OIDC-only mode'
    );
    await page.getByRole('button', { name: /Continue with Corporate OIDC/i }).waitFor({ state: 'visible' });

    // Check 2: Full Browser OIDC Authorization Code + PKCE Flow (platform_admin)
    const callbackRespPromise = page.waitForResponse(
      (res) => res.url().includes('/auth/sso/corp-oidc/callback')
    );
    await page.getByRole('button', { name: /Continue with Corporate OIDC/i }).click();
    const callbackResp = await callbackRespPromise;
    assert.equal(callbackResp.status(), 302, 'expected OIDC callback 302 redirect back to /ui/');
    const setCookie = callbackResp.headers()['set-cookie'] || '';
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

    // Check 4b: KeysView single Block/Unblock, status filter ("Blocked"), toolbar bulk Block/Unblock, and $0 spend reset
    page.once('dialog', (dialog) => dialog.accept());
    await keyRow.locator('button[title="Block"]').click();
    await keyRow.getByText('Revoked', { exact: true }).waitFor({ state: 'visible' });

    const statusSelect = page.locator('input[placeholder="Search..."] + select');
    await statusSelect.selectOption('revoked');
    await keyRow.waitFor({ state: 'visible' });
    await statusSelect.selectOption('');

    // Bulk Unblock -> Bulk Block -> Bulk Unblock via toolbar checkboxes (actionMut clears selection on each success)
    const bulkToolbar = page.locator('div', { has: page.getByRole('button', { name: 'Clear', exact: true }) }).last();
    await keyRow.locator('input[type="checkbox"]').check();
    await bulkToolbar.getByRole('button', { name: 'Unblock', exact: true }).click();
    await keyRow.getByText('Active', { exact: true }).waitFor({ state: 'visible' });

    await keyRow.locator('input[type="checkbox"]').check();
    await bulkToolbar.getByRole('button', { name: 'Block', exact: true }).click();
    await keyRow.getByText('Revoked', { exact: true }).waitFor({ state: 'visible' });

    await keyRow.locator('input[type="checkbox"]').check();
    await bulkToolbar.getByRole('button', { name: 'Unblock', exact: true }).click();
    await keyRow.getByText('Active', { exact: true }).waitFor({ state: 'visible' });

    // Single-key $0 spend reset action
    const resetSpendPromise = page.waitForResponse(
      (res) => res.url().includes(`/admin/v1/keys/${createdKeyId}/reset-spend`) && res.request().method() === 'POST'
    );
    page.once('dialog', (dialog) => dialog.accept());
    await keyRow.locator('button[title="Reset spend"]').click();
    const resetSpendResp = await resetSpendPromise;
    assert.equal(resetSpendResp.status(), 200, 'expected 200 from POST /admin/v1/keys/{id}/reset-spend');

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
    await createTeamModal.locator('input[placeholder="Min Priority Rank"]').fill('2');
    await createTeamModal.locator('input[placeholder="Allowed Routing Tags"]').fill('tier:fast, eu');
    await createTeamModal.getByRole('button', { name: 'Create', exact: true }).click();

    const teamRow = page.locator('tbody tr', { hasText: 'UI E2E Engineering' }).first();
    await teamRow.waitFor({ state: 'visible' });

    // Verify team_member_permissions and routing policies persisted when opening Edit Team modal
    await teamRow.locator('button[title="Edit"]').click();
    const editTeamModal = modalByTitle(page, 'Edit Team');
    await editTeamModal.waitFor({ state: 'visible' });
    const permsVal = await editTeamModal.locator('input[placeholder*="Member Perms"]').inputValue();
    assert.equal(permsVal, 'keys:create, keys:rotate', `expected persisted team_member_permissions, got: ${permsVal}`);
    assert.equal(await editTeamModal.locator('input[placeholder="Min Priority Rank"]').inputValue(), '2');
    assert.equal(await editTeamModal.locator('input[placeholder="Allowed Routing Tags"]').inputValue(), 'tier:fast, eu');
    await editTeamModal.getByRole('button', { name: 'Cancel' }).click();

    // Sync team member add & remove via Members modal
    await teamRow.locator('button[title="Sync members"]').click();
    const membersModal = modalByTitle(page, 'Members: UI E2E Engineering');
    await membersModal.waitFor({ state: 'visible' });
    await membersModal.locator('input[placeholder*="Upsert User IDs"]').fill(opUserRes.json.id);
    await membersModal.getByRole('button', { name: 'Sync', exact: true }).click();
    await membersModal.waitFor({ state: 'hidden' });

    await teamRow.locator('button[title="Sync members"]').click();
    await membersModal.waitFor({ state: 'visible' });
    await membersModal.getByText(opUserRes.json.id).waitFor({ state: 'visible' });
    await membersModal.locator('input[placeholder*="Remove User IDs"]').fill(opUserRes.json.id);
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
    await fieldControl(quotaModal, 'RPD').fill('250');
    await fieldControl(quotaModal, 'ITPM').fill('1200');
    await fieldControl(quotaModal, 'OTPM').fill('600');
    await fieldControl(quotaModal, 'TPD').fill('50000');
    await quotaModal.getByRole('button', { name: 'Save' }).click();

    const quotaRow = page.locator('tbody tr', { hasText: createdKeyId }).filter({ hasText: 'gpt-4o*' }).first();
    await quotaRow.waitFor({ state: 'visible' });
    await quotaRow.getByText(/RPD:250/).waitFor({ state: 'visible' });
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

    // Check 5a: ModelsView Model Group Edit/Delete & Deployment Edit/Drain/Delete
    await adminAPI('/admin/v1/catalogue/import?provider=openai', 'POST');
    const catList = await adminAPI('/admin/v1/catalogue');
    const sampleModelId = catList.json?.data?.find((m) => m.provider === 'openai')?.id || 'openai/gpt-4o-mini';
    const credRes = await adminAPI('/admin/v1/credentials', 'POST', {
      org_id: orgId,
      provider: 'openai',
      name: `ui-e2e-openai-${suffix}`,
      api_key: 'sk-ui-e2e-mock-key-1234',
    });
    assert.equal(credRes.status, 201, `expected 201 creating credential: ${credRes.text}`);

    await page.locator('aside button', { hasText: 'Models & Routing' }).click();
    await page.locator('button', { hasText: /^Routing Topologies/ }).click();

    await page.getByRole('button', { name: 'New Model Group' }).click();
    const createGroupModal = modalByTitle(page, 'Create Model Group Alias');
    await createGroupModal.waitFor({ state: 'visible' });
    await fieldControl(createGroupModal, 'Alias Name *').fill('ui-e2e-route-group');
    await createGroupModal.getByLabel('Drop Unsupported Params').check();
    await createGroupModal.getByRole('button', { name: 'Create Model Group' }).click();

    const groupCard = page.locator('div.rounded-xl', { hasText: 'ui-e2e-route-group' }).first();
    await groupCard.waitFor({ state: 'visible' });
    await groupCard.getByText('drop-params', { exact: true }).waitFor({ state: 'visible' });

    await groupCard.locator('button[title="Edit Model Group"]').click();
    const editGroupModal = modalByTitle(page, 'Edit Model Group Alias');
    await editGroupModal.waitFor({ state: 'visible' });
    await editGroupModal.getByLabel('Disable Cooldowns').check();
    await editGroupModal.getByRole('button', { name: 'Save Changes' }).click();
    await groupCard.getByText('no-cooldown', { exact: true }).waitFor({ state: 'visible' });

    await groupCard.getByRole('button', { name: 'Add Deployment' }).click();
    const addDepModal = modalByTitle(page, 'Add Deployment to Model Group');
    await addDepModal.waitFor({ state: 'visible' });
    await fieldControl(addDepModal, 'Global Model ID *').fill(sampleModelId);
    // Test default "Auto-resolve org credential" when exactly one matching OpenAI credential exists.
    assert.equal(await fieldControl(addDepModal, 'Provider Credential (optional)').inputValue(), '');
    await fieldControl(addDepModal, 'Max Parallel').fill('4');
    await addDepModal.getByRole('button', { name: 'Add Deployment' }).click();

    await groupCard.getByText('Par:4', { exact: true }).waitFor({ state: 'visible' });
    await groupCard.locator('button[title="Drain Deployment"]').click();
    await groupCard.getByText('disabled', { exact: true }).waitFor({ state: 'visible' });

    await groupCard.locator('button[title="Edit Deployment"]').click();
    const editDepModal = modalByTitle(page, 'Edit Deployment');
    await editDepModal.waitFor({ state: 'visible' });
    assert.equal(await fieldControl(editDepModal, 'Status').inputValue(), 'disabled');
    await fieldControl(editDepModal, 'Priority Tier').fill('2');
    await editDepModal.getByRole('button', { name: 'Save Deployment' }).click();
    await groupCard.getByText('P:2', { exact: true }).waitFor({ state: 'visible' });

    page.once('dialog', (d) => d.accept());
    await groupCard.locator('button[title="Delete Deployment"]').click();
    await groupCard.getByText(/No child deployments attached/i).waitFor({ state: 'visible' });

    page.once('dialog', (d) => d.accept());
    await groupCard.locator('button[title="Delete Model Group"]').click();
    await groupCard.waitFor({ state: 'hidden' });

    // Check 5a-bis: Named Guardrail Registry sensitive_route_target persistence
    await page.locator('aside button', { hasText: 'Guardrails' }).click();
    await page.getByRole('button', { name: 'Named Guardrails & Registry' }).click();
    await page.getByRole('button', { name: 'New Guardrail' }).click();
    const defModal = modalByTitle(page, 'Create Named Guardrail');
    await defModal.waitFor({ state: 'visible' });
    await defModal.locator('input[placeholder="e.g. prod-pii-presidio"]').fill(`ui-e2e-route-guard-${suffix}`);
    await defModal.locator('input[placeholder="e.g. private-local"]').fill('private-local');
    await defModal.getByRole('button', { name: 'Create Guardrail' }).click();
    const defCard = page.locator('div.rounded-lg', { hasText: `ui-e2e-route-guard-${suffix}` }).first();
    await defCard.waitFor({ state: 'visible' });
    await defCard.getByText('route:private-local', { exact: true }).waitFor({ state: 'visible' });
    await defCard.getByRole('button', { name: 'Edit' }).click();
    const editDefModal = modalByTitle(page, /Edit Guardrail:/);
    await editDefModal.waitFor({ state: 'visible' });
    assert.equal(await editDefModal.locator('input[placeholder="e.g. private-local"]').inputValue(), 'private-local');
    await editDefModal.getByRole('button', { name: 'Cancel' }).click();

    // Check 5b: ConfigView Rotate KEK visibility & execution for platform_admin
    await page.locator('aside button', { hasText: 'Gateway Config' }).click();
    await page.getByRole('heading', { name: 'Gateway Configuration' }).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: 'Rotate KEK' }).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: 'Rotate KEK' }).click();
    await page.locator('input[placeholder="New master KEK (>=32 chars)"]').fill(`rotated-ui-e2e-master-kek-${suffix}-0123456789`);
    await page.getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.getByText(/Database DEKs rotated atomically/i).waitFor({ state: 'visible' });

    // Check 5c: Agentic Hub -> MCP Multi-Release Specification Selector & Server Spec Auto-Transport
    await page.locator('aside button', { hasText: /MCP|Agentic/i }).click();
    await page.getByText('Gateway MCP Specification').waitFor({ state: 'visible' });
    for (const ver of ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28']) {
      await page.getByRole('button', { name: new RegExp(ver) }).waitFor({ state: 'visible' });
    }
    await page.getByRole('button', { name: /2025-03-26/ }).click();
    await page.getByRole('button', { name: 'Apply Spec' }).click();
    await page.getByText('Active: 2025-03-26').waitFor({ state: 'visible' });
    await page.reload({ waitUntil: 'networkidle' });
    await page.locator('aside button', { hasText: /MCP|Agentic/i }).click();
    await page.getByText('Active: 2025-03-26').waitFor({ state: 'visible' });

    await page.getByRole('button', { name: /2026-07-28/ }).click();
    await page.getByRole('button', { name: 'Apply Spec' }).click();
    await page.getByText('Active: 2026-07-28').waitFor({ state: 'visible' });

    await page.getByRole('button', { name: /Register MCP Server/i }).click();
    const regSrvModal = modalByTitle(page, /Register Upstream MCP Server/i);
    await regSrvModal.waitFor({ state: 'visible' });
    await fieldControl(regSrvModal, 'Protocol Version').selectOption('2024-11-05');
    assert.equal(await fieldControl(regSrvModal, 'Transport').inputValue(), 'http_sse_2024');
    await fieldControl(regSrvModal, 'Protocol Version').selectOption('2026-07-28');
    assert.equal(await fieldControl(regSrvModal, 'Transport').inputValue(), 'streamable_http');
    await regSrvModal.getByRole('button', { name: 'Cancel' }).click();

    // Check 5d: Caching UI wiring across OverviewView (rich cache card + safe scoped Purge modal),
    // PlaygroundView (JSON Cacheable mode + Cache Controls), and FinOpsView (cache filter pills)
    await page.locator('aside button', { hasText: /Overview|Telemetry/i }).click();
    await page.getByRole('heading', { name: 'Telemetry & Upstream Health' }).waitFor({ state: 'visible' });
    await page.getByText('Response Cache').waitFor({ state: 'visible' });
    await page.getByRole('button', { name: /Purge Cache/i }).click();
    const purgeModal = modalByTitle(page, /Invalidate Response Cache/i);
    await purgeModal.waitFor({ state: 'visible' });
    assert.equal(
      await purgeModal.getByLabel('Invalidation Scope').inputValue(),
      'org',
      'Purge Cache modal must default to Current Organization scope'
    );
    await purgeModal.getByRole('button', { name: 'Confirm Purge' }).click();
    await purgeModal.getByText(/Invalidation revision:/i).waitFor({ state: 'visible' });
    assert.equal(
      await purgeModal.getByText(/epoch/i).count(),
      0,
      'Purge Cache modal must not reference legacy epoch wording'
    );
    await purgeModal.getByRole('button', { name: 'Cancel' }).click();

    await page.locator('aside button', { hasText: 'Playground' }).click();
    await page.getByRole('button', { name: 'JSON (Cacheable)' }).click();
    await page.getByRole('button', { name: 'Cache Controls' }).click();
    await page.getByLabel('Cache Mode').waitFor({ state: 'visible' });
    await page.getByLabel('Seed').fill('42');
    await page.getByLabel('Semantic Similarity').fill('0.90');

    await page.locator('aside button', { hasText: 'FinOps & Spend' }).click();
    await page.getByRole('button', { name: 'Cache Hits', exact: true }).click();
    await page.getByRole('button', { name: 'Semantic Cache', exact: true }).click();
    await page.getByRole('button', { name: 'All', exact: true }).click();
    await page.locator('input[placeholder*="trace"]').waitFor({ state: 'visible' });

    // Check 5e: Observability & Pure OTLP UI wiring (OverviewView telemetry strip + ConfigView OTLP/Health/Audit cards)
    await page.locator('aside button', { hasText: /Overview|Telemetry/i }).click();
    await page.getByRole('heading', { name: 'Telemetry & Upstream Health' }).waitFor({ state: 'visible' });
    await page.getByText(/P99:/).waitFor({ state: 'visible' });
    await page.getByText(/Redis CB:/).waitFor({ state: 'visible' });
    await page.getByText(/TTFT:/).waitFor({ state: 'visible' });
    await page.getByText(/Guardrail Blocks:/).waitFor({ state: 'visible' });
    await page.getByText(/Redactions:/).waitFor({ state: 'visible' });
    await page.getByText(/Outbox:/).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: /OTLP:/i }).click();
    await page.getByRole('heading', { name: 'Gateway Configuration' }).waitFor({ state: 'visible' });
    await page.getByRole('heading', { name: 'OpenTelemetry (OTLP)' }).waitFor({ state: 'visible' });
    await page.getByRole('heading', { name: 'Health Probing' }).waitFor({ state: 'visible' });
    await page.getByRole('heading', { name: 'Audit & SIEM' }).waitFor({ state: 'visible' });

    // Check 6: Sign Out & Session Revocation
    await page.locator('button[title*="Click to sign out"]').click();
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    const meStatusAfterLogout = await page.evaluate(() => fetch('/auth/me').then((r) => r.status));
    assert.equal(meStatusAfterLogout, 401, 'expected /auth/me to return 401 after sign out');

    // Check 7: Sign in as org_admin via OIDC and verify ConfigView hides platform_admin-only "Rotate KEK" control
    allowExpected403 = true;
    await page.getByRole('button', { name: /Continue with Org Admin OIDC/i }).click();
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

    // Check 8: Break-Glass Key tab (invalid key error -> valid master key -> platform_admin access -> sign out)
    await page.getByRole('button', { name: /Break-Glass Key/i }).click();
    const keyInput = page.locator('input[placeholder="Enter Master Admin Key..."]');
    await keyInput.waitFor({ state: 'visible' });
    await keyInput.fill('sk-gw-invalid-break-glass-key');
    await page.getByRole('button', { name: /Unlock Break-Glass Session/i }).click();
    await page.getByText(/Sign In Failed/i).waitFor({ state: 'visible' });

    await keyInput.fill(ADMIN_KEY);
    await page.getByRole('button', { name: /Unlock Break-Glass Session/i }).click();
    await page.locator('button[title*="Click to sign out"]').waitFor({ state: 'visible' });
    await page.locator('aside button', { hasText: 'Gateway Config' }).click();
    await page.getByRole('button', { name: 'Rotate KEK' }).waitFor({ state: 'visible' });

    // Check 9: /ui/cli device approval route completes POST /auth/cli/start -> /ui/cli -> /auth/cli/poll
    const cliStartRes = await fetch(`${BASE_URL}/auth/cli/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'corp-oidc' }),
    });
    assert.equal(cliStartRes.status, 200, `POST /auth/cli/start failed: ${cliStartRes.status}`);
    const cliStartJson = await cliStartRes.json();
    assert(cliStartJson.login_id, 'expected login_id from /auth/cli/start');
    assert(cliStartJson.verification_url.includes('/ui/cli?'), `unexpected verification_url: ${cliStartJson.verification_url}`);

    await page.goto(cliStartJson.verification_url, { waitUntil: 'networkidle' });
    // Re-unlock with break-glass key on fresh page load (master_key mode is in-memory)
    await page.getByRole('button', { name: /Break-Glass Key/i }).click();
    await page.locator('input[placeholder="Enter Master Admin Key..."]').fill(ADMIN_KEY);
    await page.getByRole('button', { name: /Unlock Break-Glass Session/i }).click();
    await page.getByRole('heading', { name: 'Approve CLI Login' }).waitFor({ state: 'visible' });
    await page.getByRole('button', { name: /Approve CLI Login/i }).click();
    await page.getByText('CLI Session Approved').waitFor({ state: 'visible' });

    const cliPollRes = await fetch(`${BASE_URL}/auth/cli/poll/${cliStartJson.login_id}`);
    assert.equal(cliPollRes.status, 200, `GET /auth/cli/poll failed: ${cliPollRes.status}`);
    const cliPollJson = await cliPollRes.json();
    assert.equal(cliPollJson.status, 'completed');
    assert(cliPollJson.api_key && cliPollJson.api_key.startsWith('sk-gw-'), 'expected minted sk-gw key from /auth/cli/poll');

    await page.locator('button[title*="Click to sign out"]').click();
    await page.getByRole('heading', { name: 'Control Plane Sign In' }).waitFor({ state: 'visible' });

    assert.deepEqual(pageErrors, [], `unexpected browser pageerror exceptions: ${JSON.stringify(pageErrors)}`);
    assert.deepEqual(consoleErrors, [], `unexpected browser console.error messages: ${JSON.stringify(consoleErrors)}`);
    assert.deepEqual(cspViolations, [], `unexpected browser CSP violations: ${JSON.stringify(cspViolations)}`);

    console.log('UI E2E PASS: CSP, OIDC-only PKCE login/callback/logout, cookie reload persistence, KeysView preset/rotation/block/bulk, Teams perms/sync, QuotasTab rolling_24h/TempBoost, ConfigView KEK RBAC, Break-Glass Key, /ui/cli approval, and logout revocation verified.');
  } finally {
    await context.close();
    await browser.close();
  }
}

run().catch((err) => {
  console.error('UI E2E FAILED:', err);
  process.exit(1);
});
