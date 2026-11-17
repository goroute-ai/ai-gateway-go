let csrfToken: string | null = null;
let deprecatedKeyHandler: ((revokeAt: string | null) => void) | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function setDeprecatedKeyHandler(handler: ((revokeAt: string | null) => void) | null) {
  deprecatedKeyHandler = handler;
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {},
  adminKey?: string
): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  if (adminKey && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${adminKey}`);
  }
  const method = (options.method || 'GET').toUpperCase();
  if (!adminKey && csrfToken && MUTATING_METHODS.has(method) && !headers.has('X-CSRF-Token')) {
    headers.set('X-CSRF-Token', csrfToken);
  }

  const response = await fetch(endpoint, {
    ...options,
    credentials: options.credentials ?? 'same-origin',
    headers,
  });

  if (response.headers.get('X-Gateway-Key-Deprecated') === 'true' && deprecatedKeyHandler) {
    deprecatedKeyHandler(response.headers.get('X-Gateway-Key-Revoke-At'));
  }

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    const message =
      errorBody.error?.message ||
      errorBody.message ||
      `HTTP ${response.status}: ${response.statusText}`;
    const error = new Error(message);
    (error as any).status = response.status;
    (error as any).code = errorBody.error?.code;
    throw error;
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}
