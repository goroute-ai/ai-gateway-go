import crypto from 'node:crypto';
import http from 'node:http';

const port = Number(process.env.MOCK_IDP_PORT || 0);
const host = '127.0.0.1';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const pubJwk = {
  ...publicKey.export({ format: 'jwk' }),
  kid: 'mock-ui-rsa-1',
  alg: 'RS256',
  use: 'sig',
  key_ops: ['verify'],
};

const authCodes = new Map();
let baseUrl = '';

function signJWT(payload) {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'mock-ui-rsa-1' })
  ).toString('base64url');
  const claims = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${header}.${claims}`;
  const sig = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  return `${signingInput}.${sig}`;
}

function computeATHash(accessToken) {
  return crypto.createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url');
}

function sendJSON(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const PERSONAS = {
  '/oidc': {
    sub: 'ui-sso-operator-1',
    email: 'sso-operator@example.com',
    name: 'UI Platform Admin',
    role: 'platform_admin',
    clientId: 'goroute-ui-client',
  },
  '/org-oidc': {
    sub: 'ui-org-admin-1',
    email: 'org-admin@example.com',
    name: 'UI Org Admin',
    role: 'org_admin',
    clientId: 'goroute-org-client',
  },
};

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url || '/', baseUrl || `http://${host}`);

  if (reqUrl.pathname === '/healthz') {
    return sendJSON(res, 200, { status: 'ok' });
  }

  for (const [prefix, persona] of Object.entries(PERSONAS)) {
    if (reqUrl.pathname === `${prefix}/.well-known/openid-configuration`) {
      return sendJSON(res, 200, {
        issuer: `${baseUrl}${prefix}`,
        authorization_endpoint: `${baseUrl}${prefix}/authorize`,
        token_endpoint: `${baseUrl}${prefix}/token`,
        userinfo_endpoint: `${baseUrl}${prefix}/userinfo`,
        end_session_endpoint: `${baseUrl}${prefix}/logout`,
        jwks_uri: `${baseUrl}${prefix}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
      });
    }

    if (reqUrl.pathname === `${prefix}/jwks`) {
      return sendJSON(res, 200, { keys: [pubJwk] });
    }

    if (reqUrl.pathname === `${prefix}/authorize`) {
      const redirectUri = reqUrl.searchParams.get('redirect_uri') || '';
      const state = reqUrl.searchParams.get('state') || '';
      const nonce = reqUrl.searchParams.get('nonce') || '';
      const codeChallenge = reqUrl.searchParams.get('code_challenge') || '';
      const code = `ui-code-${crypto.randomUUID()}`;
      authCodes.set(code, { nonce, codeChallenge, prefix });
      const redir = new URL(redirectUri);
      redir.searchParams.set('code', code);
      redir.searchParams.set('state', state);
      res.writeHead(302, { Location: redir.toString() });
      return res.end();
    }

    if (reqUrl.pathname === `${prefix}/token` && req.method === 'POST') {
      const chunks = [];
      for await (const ch of req) chunks.push(ch);
      const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      const code = params.get('code') || '';
      const meta = authCodes.get(code) || {};
      authCodes.delete(code);
      const accessToken = `mock-ui-access-token-${code}`;
      const now = Math.floor(Date.now() / 1000);
      const idToken = signJWT({
        iss: `${baseUrl}${prefix}`,
        sub: persona.sub,
        aud: persona.clientId,
        email: persona.email,
        email_verified: true,
        name: persona.name,
        role: persona.role,
        nonce: meta.nonce || undefined,
        at_hash: computeATHash(accessToken),
        iat: now,
        exp: now + 600,
      });
      return sendJSON(res, 200, {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 600,
        id_token: idToken,
      });
    }

    if (reqUrl.pathname === `${prefix}/userinfo`) {
      return sendJSON(res, 200, {
        sub: persona.sub,
        email: persona.email,
        name: persona.name,
      });
    }

    if (reqUrl.pathname === `${prefix}/logout`) {
      const postLogout = reqUrl.searchParams.get('post_logout_redirect_uri') || 'http://127.0.0.1/';
      res.writeHead(302, { Location: postLogout });
      return res.end();
    }
  }

  res.writeHead(404);
  res.end('not found');
});

server.listen(port, host, () => {
  const addr = server.address();
  baseUrl = `http://${host}:${addr.port}`;
  console.log(`MOCK_IDP_LISTENING ${baseUrl}`);
});

const shutdown = () => server.close(() => process.exit(0));
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
