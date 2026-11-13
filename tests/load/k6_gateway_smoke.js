import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    gateway_api_load: {
      executor: 'constant-arrival-rate',
      rate: 250,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 32,
      maxVUs: 64,
    },
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    http_req_duration: ['p(99)<15'],
  },
};

const BASE = __ENV.GATEWAY_BASE_URL || 'http://ai-gateway-test:8080';
const ADMIN_KEY = __ENV.GATEWAY_MASTER_ADMIN_KEY || 'sk-gw-test-master-admin-key';

export default function () {
  const healthRes = http.get(`${BASE}/readyz`);
  check(healthRes, {
    'readyz 200': (r) => r.status === 200,
  });

  const metricsRes = http.get(`${BASE}/metrics`, {
    headers: { Authorization: `Bearer ${ADMIN_KEY}` },
  });
  check(metricsRes, {
    'metrics 200': (r) => r.status === 200 && r.body.includes('gateway_requests_total'),
  });

  const orgsRes = http.get(`${BASE}/admin/v1/organizations`, {
    headers: { Authorization: `Bearer ${ADMIN_KEY}` },
  });
  check(orgsRes, {
    'organizations 200': (r) => r.status === 200,
  });
}
