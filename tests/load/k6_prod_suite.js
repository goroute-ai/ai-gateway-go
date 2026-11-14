import http from 'k6/http';
import { check } from 'k6';
import { Rate, Counter } from 'k6/metrics';

const unexpectedErrors = new Rate('unexpected_errors');
const rateLimitHits = new Counter('rate_limit_hits');

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    health_readiness: {
      executor: 'constant-arrival-rate',
      exec: 'healthCheck',
      rate: 40,
      timeUnit: '1s',
      duration: '10s',
      preAllocatedVUs: 10,
      maxVUs: 25,
    },
    inference_sync_and_cache: {
      executor: 'constant-arrival-rate',
      exec: 'syncInference',
      rate: 30,
      timeUnit: '1s',
      duration: '12s',
      preAllocatedVUs: 15,
      maxVUs: 40,
    },
    inference_sse_stream: {
      executor: 'constant-vus',
      exec: 'streamInference',
      vus: 4,
      duration: '10s',
    },
    rate_limit_burst: {
      executor: 'shared-iterations',
      exec: 'rateLimitBurst',
      vus: 5,
      iterations: 20,
      startTime: '2s',
    },
  },
  thresholds: {
    unexpected_errors: ['rate==0'],
    'http_req_duration{scenario:health_readiness}': ['p(95)<50'],
    'http_req_duration{scenario:inference_sync_and_cache}': ['p(95)<250'],
    rate_limit_hits: ['count>0'],
  },
};

const BASE = __ENV.GATEWAY_BASE_URL || 'https://localhost:28443';
const VIRTUAL_KEY = __ENV.GATEWAY_VIRTUAL_KEY || '';
const BURST_KEY = __ENV.GATEWAY_BURST_KEY || VIRTUAL_KEY;
const CHAT_MODEL = __ENV.GATEWAY_CHAT_MODEL || 'prod-chat';

const statusCallback = http.expectedStatuses(200, 201, 429);
http.setResponseCallback(statusCallback);

export function healthCheck() {
  const res = http.get(`${BASE}/readyz`);
  const ok = check(res, {
    'readyz 200': (r) => r.status === 200,
  });
  unexpectedErrors.add(!ok);
}

export function syncInference() {
  const payload = JSON.stringify({
    model: CHAT_MODEL,
    messages: [{ role: 'user', content: 'Benchmark cacheable prompt' }],
  });
  const res = http.post(`${BASE}/v1/chat/completions`, payload, {
    headers: {
      Authorization: `Bearer ${VIRTUAL_KEY}`,
      'Content-Type': 'application/json',
    },
  });
  const ok = check(res, {
    'chat completion 200': (r) => r.status === 200 && r.body.includes('Hello from mock-upstream!'),
  });
  unexpectedErrors.add(!ok);
}

export function streamInference() {
  const payload = JSON.stringify({
    model: CHAT_MODEL,
    stream: true,
    messages: [{ role: 'user', content: 'Stream load benchmark prompt' }],
  });
  const res = http.post(`${BASE}/v1/chat/completions`, payload, {
    headers: {
      Authorization: `Bearer ${VIRTUAL_KEY}`,
      'Content-Type': 'application/json',
      'X-Gateway-Cache-Control': 'gateway-stream-cache',
    },
  });
  const ok = check(res, {
    'sse stream 200 & DONE': (r) => r.status === 200 && r.body.includes('[DONE]'),
  });
  unexpectedErrors.add(!ok);
}

export function rateLimitBurst() {
  const payload = JSON.stringify({
    model: CHAT_MODEL,
    messages: [{ role: 'user', content: `Burst check ${__VU}-${__ITER}` }],
  });
  const res = http.post(`${BASE}/v1/chat/completions`, payload, {
    headers: {
      Authorization: `Bearer ${BURST_KEY}`,
      'Content-Type': 'application/json',
    },
  });
  if (res.status === 429) {
    rateLimitHits.add(1);
  }
  const ok = check(res, {
    'burst 200 or 429': (r) => r.status === 200 || r.status === 429,
  });
  unexpectedErrors.add(!ok);
}
