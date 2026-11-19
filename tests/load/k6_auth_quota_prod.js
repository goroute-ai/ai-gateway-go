import http from 'k6/http';
import { check } from 'k6';
import { Rate, Counter } from 'k6/metrics';

const unexpectedErrors = new Rate('unexpected_errors');
const rateLimitHits = new Counter('rate_limit_hits');

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    oidc_jwt_traffic: {
      executor: 'constant-arrival-rate',
      exec: 'oidcTraffic',
      rate: 15,
      timeUnit: '1s',
      duration: '8s',
      preAllocatedVUs: 8,
      maxVUs: 20,
    },
    quota_enforcement_burst: {
      executor: 'shared-iterations',
      exec: 'quotaBurst',
      vus: 5,
      iterations: 20,
      startTime: '1s',
    },
  },
  thresholds: {
    unexpected_errors: ['rate==0'],
    rate_limit_hits: ['count>0'],
    'http_req_duration{scenario:oidc_jwt_traffic}': ['p(95)<250'],
  },
};

const BASE = __ENV.GATEWAY_BASE_URL || 'https://localhost:28443';
const OIDC_JWT = __ENV.GATEWAY_OIDC_JWT || '';
const QUOTA_BURST_KEY = __ENV.GATEWAY_QUOTA_BURST_KEY || '';
const CHAT_MODEL = __ENV.GATEWAY_CHAT_MODEL || 'prod-chat';

const statusCallback = http.expectedStatuses(200, 201, 429);
http.setResponseCallback(statusCallback);

export function oidcTraffic() {
  const payload = JSON.stringify({
    model: CHAT_MODEL,
    messages: [{ role: 'user', content: `OIDC load check ${__VU}-${__ITER}` }],
  });
  const res = http.post(`${BASE}/v1/chat/completions`, payload, {
    headers: {
      Authorization: `Bearer ${OIDC_JWT}`,
      'Content-Type': 'application/json',
    },
  });
  const ok = check(res, {
    'oidc chat completion 200': (r) => r.status === 200 && r.body.includes('Hello from mock-upstream!'),
  });
  unexpectedErrors.add(!ok);
}

export function quotaBurst() {
  const payload = JSON.stringify({
    model: CHAT_MODEL,
    messages: [{ role: 'user', content: `Quota burst check ${__VU}-${__ITER}` }],
  });
  const res = http.post(`${BASE}/v1/chat/completions`, payload, {
    headers: {
      Authorization: `Bearer ${QUOTA_BURST_KEY}`,
      'Content-Type': 'application/json',
    },
  });
  if (res.status === 429) {
    rateLimitHits.add(1);
  }
  const ok = check(res, {
    'quota burst 200 or 429': (r) => r.status === 200 || r.status === 429,
  });
  unexpectedErrors.add(!ok);
}
