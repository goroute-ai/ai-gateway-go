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
};

const hibpPrefixes = [];
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

function sendJSON(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url || '/', baseUrl || `http://${host}`);

  if (reqUrl.pathname === '/healthz') {
    return sendJSON(res, 200, { status: 'ok' });
  }

  if (reqUrl.pathname === '/oidc/.well-known/openid-configuration') {
    return sendJSON(res, 200, {
      issuer: `${baseUrl}/oidc`,
      authorization_endpoint: `${baseUrl}/oidc/authorize`,
      token_endpoint: `${baseUrl}/oidc/token`,
      userinfo_endpoint: `${baseUrl}/oidc/userinfo`,
      jwks_uri: `${baseUrl}/oidc/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
    });
  }

  if (reqUrl.pathname === '/oidc/jwks') {
    return sendJSON(res, 200, { keys: [pubJwk] });
  }

  if (reqUrl.pathname === '/oidc/authorize') {
    const redirectUri = reqUrl.searchParams.get('redirect_uri') || '';
    const state = reqUrl.searchParams.get('state') || '';
    const nonce = reqUrl.searchParams.get('nonce') || '';
    const codeChallenge = reqUrl.searchParams.get('code_challenge') || '';
    const code = `ui-code-${crypto.randomUUID()}`;
    authCodes.set(code, { nonce, codeChallenge });
    const redir = new URL(redirectUri);
    redir.searchParams.set('code', code);
    redir.searchParams.set('state', state);
    res.writeHead(302, { Location: redir.toString() });
    return res.end();
  }

  if (reqUrl.pathname === '/oidc/token' && req.method === 'POST') {
    const chunks = [];
    for await (const ch of req) chunks.push(ch);
    const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
    const code = params.get('code') || '';
    const meta = authCodes.get(code) || {};
    authCodes.delete(code);
    const now = Math.floor(Date.now() / 1000);
    const idToken = signJWT({
      iss: `${baseUrl}/oidc`,
      sub: 'ui-sso-operator-1',
      aud: 'goroute-ui-client',
      email: 'sso-operator@example.com',
      email_verified: true,
      nonce: meta.nonce || undefined,
      iat: now,
      exp: now + 600,
    });
    return sendJSON(res, 200, {
      access_token: 'mock-ui-access-token',
      token_type: 'Bearer',
      expires_in: 600,
      id_token: idToken,
    });
  }

  if (reqUrl.pathname.startsWith('/hibp/range/')) {
    const prefix = reqUrl.pathname.slice('/hibp/range/'.length).toUpperCase();
    hibpPrefixes.push(prefix);
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    if (prefix === 'CBFDA') {
      // Remaining 35 hex suffix of SHA-1("password123")
      return res.end('C6008F9CAB4083784CBD1874F76618D2A97:99999\r\n');
    }
    return res.end('00000000000000000000000000000000000:0\r\n');
  }

  if (reqUrl.pathname === '/hibp/audit') {
    return sendJSON(res, 200, { prefixes: hibpPrefixes, count: hibpPrefixes.length });
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
