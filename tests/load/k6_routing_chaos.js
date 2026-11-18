import http from 'k6/http';
import { check } from 'k6';
import { Rate, Counter, Trend } from 'k6/metrics';

const unexpectedErrors = new Rate('unexpected_errors');
const fallbackTriggered = new Counter('fallback_triggered_count');
const faultInjectionLatencyMs = new Trend('fault_injection_latency_ms');
const hedgedLatencyMs = new Trend('hedged_tail_latency_ms');

const HEDGE_DELAY_MS = Number(__ENV.GATEWAY_HEDGE_AFTER_MS || '400');

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    fault_injection_30pct_503: {
      executor: 'constant-arrival-rate',
      exec: 'faultInjectionFallback',
      rate: 25,
      timeUnit: '1s',
      duration: '15s',
      preAllocatedVUs: 10,
      maxVUs: 35,
    },
    hedged_tail_latency_protection: {
      executor: 'constant-arrival-rate',
      exec: 'hedgedTailProtection',
      rate: 20,
      timeUnit: '1s',
      duration: '15s',
      preAllocatedVUs: 10,
      maxVUs: 40,
      startTime: '1s',
    },
  },
  thresholds: {
    unexpected_errors: ['rate==0'],
    'http_req_duration{scenario:fault_injection_30pct_503}': ['p(99)<1500'],
    'http_req_duration{scenario:hedged_tail_latency_protection}': ['p(99)<650'],
    fallback_triggered_count: ['count>0'],
  },
};

const BASE = __ENV.GATEWAY_BASE_URL || 'http://localhost:8080';
const VIRTUAL_KEY = __ENV.GATEWAY_VIRTUAL_KEY || '';
const CHAOS_MODEL = __ENV.GATEWAY_CHAOS_MODEL || 'chaos-primary';
const HEDGED_MODEL = __ENV.GATEWAY_HEDGED_MODEL || 'hedged-primary,hedged-backup';

const statusCallback = http.expectedStatuses(200);
http.setResponseCallback(statusCallback);

function getHeader(res, name) {
  if (!res || !res.headers) {
    return '';
  }
  const target = name.toLowerCase();
  for (const key of Object.keys(res.headers)) {
    if (key.toLowerCase() === target) {
      const val = res.headers[key];
      return Array.isArray(val) ? String(val[0] || '') : String(val || '');
    }
  }
  return '';
}

export function faultInjectionFallback() {
  const payload = JSON.stringify({
    model: CHAOS_MODEL,
    messages: [{ role: 'user', content: `Chaos 503 fault injection probe ${__VU}-${__ITER}` }],
  });
  const res = http.post(`${BASE}/v1/chat/completions`, payload, {
    headers: {
      Authorization: `Bearer ${VIRTUAL_KEY}`,
      'Content-Type': 'application/json',
      'X-Chaos-Fail-Rate': '0.30',
      'X-Chaos-Status': '503',
    },
  });

  const routeReason = getHeader(res, 'X-Gateway-Route-Reason');
  const fallbackAttempted = getHeader(res, 'X-Gateway-Fallback-Attempted');
  if (fallbackAttempted.toLowerCase() === 'true') {
    fallbackTriggered.add(1);
  }
  faultInjectionLatencyMs.add(res.timings.duration);

  const ok = check(res, {
    'chaos request recovered with 200': (r) => r.status === 200,
    'X-Gateway-Route-Reason header present': () => routeReason.length > 0,
    'X-Gateway-Fallback-Attempted header valid': () =>
      fallbackAttempted === 'true' || fallbackAttempted === 'false',
  });
  unexpectedErrors.add(!ok);
}

export function hedgedTailProtection() {
  const payload = JSON.stringify({
    model: HEDGED_MODEL,
    messages: [{ role: 'user', content: `Hedged tail latency protection ${__VU}-${__ITER}` }],
    goroute_extensions: {
      hedge_after_ms: HEDGE_DELAY_MS,
    },
  });
  const res = http.post(`${BASE}/v1/chat/completions`, payload, {
    headers: {
      Authorization: `Bearer ${VIRTUAL_KEY}`,
      'Content-Type': 'application/json',
    },
  });

  const routeReason = getHeader(res, 'X-Gateway-Route-Reason');
  const fallbackAttempted = getHeader(res, 'X-Gateway-Fallback-Attempted');
  hedgedLatencyMs.add(res.timings.duration);

  const ok = check(res, {
    'hedged request 200': (r) => r.status === 200,
    'hedged route reason header present': () => routeReason.length > 0,
    'X-Gateway-Fallback-Attempted header present': () =>
      fallbackAttempted === 'true' || fallbackAttempted === 'false',
    'hedged tail latency below 650ms': (r) => r.timings.duration < 650,
  });
  unexpectedErrors.add(!ok);
}
