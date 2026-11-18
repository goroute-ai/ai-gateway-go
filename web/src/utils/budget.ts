export const usdToMicros = (raw: string): number | undefined => {
  const v = parseFloat(raw);
  return !isNaN(v) && v >= 0 ? Math.round(v * 1_000_000) : undefined;
};

export const microsToUsdInput = (micros?: number): string =>
  micros ? String(micros / 1_000_000) : '';

export const formatUSD = (micros?: number, digits = 2): string =>
  `$${((micros ?? 0) / 1_000_000).toFixed(digits)}`;

export function parseBudgetFallbacks(raw: string): Record<string, string[]> {
  const trimmed = raw.trim();
  if (!trimmed) return {};
  if (trimmed.startsWith('{')) {
    const parsed = JSON.parse(trimmed);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('budget_fallbacks JSON must be an object mapping model -> fallback models');
    }
    const out: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (Array.isArray(v)) out[k] = v.map(String).filter(Boolean);
    }
    return out;
  }
  const out: Record<string, string[]> = {};
  for (const line of trimmed.split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const model = line.slice(0, idx).trim();
    const targets = line
      .slice(idx + 1)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (model && targets.length > 0) out[model] = targets;
  }
  return out;
}

export function formatBudgetFallbacks(fallbacks?: Record<string, string[]>): string {
  if (!fallbacks) return '';
  return Object.entries(fallbacks)
    .filter(([, v]) => Array.isArray(v) && v.length > 0)
    .map(([k, v]) => `${k}: ${v.join(', ')}`)
    .join('\n');
}
