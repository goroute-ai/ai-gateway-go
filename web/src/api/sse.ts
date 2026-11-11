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

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      // Split on double newline event boundary
      let boundaryIndex: number;
      while (
        (boundaryIndex = buffer.indexOf('\n\n')) !== -1 ||
        (boundaryIndex = buffer.indexOf('\r\n\r\n')) !== -1
      ) {
        const delimiterLength = buffer.startsWith('\r\n\r\n', boundaryIndex) ? 4 : 2;
        const rawEvent = buffer.slice(0, boundaryIndex);
        buffer = buffer.slice(boundaryIndex + delimiterLength);

        const lines = rawEvent.split(/\r?\n/);
        let dataAccumulator = '';

        for (const line of lines) {
          if (line.startsWith(':') || !line.trim()) continue;
          if (line.startsWith('data: ')) {
            const dataSlice = line.slice(6);
            if (dataSlice.trim() === '[DONE]') return;
            dataAccumulator += (dataAccumulator ? '\n' : '') + dataSlice;
          }
        }

        if (dataAccumulator) {
          try {
            const parsed = JSON.parse(dataAccumulator);
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
          } catch {
            // Wait for complete JSON event
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}
