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

  const response = await fetch(endpoint, {
    ...options,
    headers,
  });

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
