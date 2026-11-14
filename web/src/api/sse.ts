export interface ChatStreamChunk {
  content?: string;
  reasoning_content?: string;
  tool_calls?: Array<{
    index: number;
    id?: string;
    type?: string;
    function?: {
      name?: string;
      arguments?: string;
    };
  }>;
  finish_reason?: string | null;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface ChatStreamHeaders {
  requestId?: string;
  provider?: string;
  model?: string;
  cache?: string;
  costMicros?: number;
  tokenEstimate?: number;
  guardrailAction?: string;
}

export async function streamChatCompletion(
  endpoint: string,
  apiKey: string,
  payload: Record<string, any>,
  onChunk: (chunk: ChatStreamChunk) => void,
  signal: AbortSignal,
  onHeaders?: (headers: ChatStreamHeaders) => void
): Promise<void> {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ ...payload, stream: true }),
    signal,
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    const message =
      errorBody.error?.message ||
      errorBody.message ||
      `HTTP ${response.status}: ${response.statusText}`;
    const err = new Error(message);
    (err as any).status = response.status;
    (err as any).details = errorBody.error;
    throw err;
  }

  // Extract real gateway telemetry headers
  if (onHeaders) {
    const rawCost = response.headers.get('x-gateway-cost-micros');
    const rawEst = response.headers.get('x-gateway-token-estimate');
    onHeaders({
      requestId: response.headers.get('x-gateway-request-id') || undefined,
      provider: response.headers.get('x-gateway-provider') || undefined,
      model: response.headers.get('x-gateway-model') || undefined,
      cache: response.headers.get('x-gateway-cache') || undefined,
      costMicros: rawCost ? parseInt(rawCost, 10) : undefined,
      tokenEstimate: rawEst ? parseInt(rawEst, 10) : undefined,
      guardrailAction: response.headers.get('x-gateway-guardrail-action') || undefined,
    });
  }

  const reader = response.body?.getReader();
  if (!reader) throw new Error('Response body is not readable');

  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  const processFrame = (rawEvent: string): boolean => {
    const lines = rawEvent.split(/\r?\n/);
    let currentEvent = '';
    let dataAccumulator = '';

    for (const line of lines) {
      if (line.startsWith(':') || !line.trim()) continue;
      if (line.startsWith('event:')) {
        currentEvent = line.slice(6).trim();
      } else if (line.startsWith('data:')) {
        const dataSlice = line.slice(line.startsWith('data: ') ? 6 : 5);
        if (dataSlice.trim() === '[DONE]') return true;
        dataAccumulator += (dataAccumulator ? '\n' : '') + dataSlice;
      }
    }

    if (!dataAccumulator) return false;

    let parsed: any;
    try {
      parsed = JSON.parse(dataAccumulator);
    } catch {
      if (currentEvent === 'error') {
        throw new Error(dataAccumulator);
      }
      return false;
    }

    if (currentEvent === 'error' || parsed.error) {
      const errInfo = parsed.error || parsed;
      const msg =
        (typeof errInfo === 'string' ? errInfo : errInfo?.message) ||
        'Stream interrupted by gateway error';
      const err = new Error(msg);
      if (errInfo && typeof errInfo === 'object') {
        if (errInfo.code) (err as any).code = errInfo.code;
        if (errInfo.status) (err as any).status = errInfo.status;
        (err as any).details = errInfo;
      }
      throw err;
    }

    const choice = parsed.choices?.[0];
    if (choice || parsed.usage) {
      onChunk({
        content: choice?.delta?.content,
        reasoning_content:
          choice?.delta?.reasoning_content || choice?.delta?.reasoning,
        tool_calls: choice?.delta?.tool_calls,
        finish_reason: choice?.finish_reason,
        usage: parsed.usage,
      });
    }
    return false;
  };

  const drainBuffer = (flushAll: boolean): boolean => {
    while (true) {
      const lf = buffer.indexOf('\n\n');
      const crlf = buffer.indexOf('\r\n\r\n');
      const idx = lf === -1 ? crlf : crlf === -1 ? lf : Math.min(lf, crlf);
      if (idx === -1) break;
      const delimLen = buffer.startsWith('\r\n\r\n', idx) ? 4 : 2;
      const rawEvent = buffer.slice(0, idx);
      buffer = buffer.slice(idx + delimLen);
      if (processFrame(rawEvent)) return true;
    }
    if (flushAll && buffer.trim()) {
      const tail = buffer;
      buffer = '';
      if (processFrame(tail)) return true;
    }
    return false;
  };

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        buffer += decoder.decode();
        drainBuffer(true);
        break;
      }

      buffer += decoder.decode(value, { stream: true });
      if (drainBuffer(false)) return;
    }
  } finally {
    reader.releaseLock();
  }
}
