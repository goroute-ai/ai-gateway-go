import React from 'react';

const fmtVal = (v: unknown) => (v === undefined ? '—' : typeof v === 'string' ? v : JSON.stringify(v));

export const JsonDiffViewer: React.FC<{
  before?: Record<string, any>;
  after?: Record<string, any>;
}> = ({ before, after }) => {
  if (!before && !after) return null;
  const b = before || {};
  const a = after || {};
  const keys = Array.from(new Set([...Object.keys(b), ...Object.keys(a)])).sort();
  const changed = keys.filter((k) => JSON.stringify(b[k]) !== JSON.stringify(a[k]));
  if (changed.length === 0) {
    return <div className="text-xs font-mono text-brand-muted">No field changes recorded.</div>;
  }
  return (
    <div className="border border-border-subtle rounded-lg overflow-hidden text-xs font-mono">
      <div className="grid grid-cols-3 bg-surface-elevated border-b border-border-subtle px-3 py-1.5 text-[10px] uppercase text-brand-muted">
        <span>Field</span>
        <span>Before</span>
        <span>After</span>
      </div>
      <div className="divide-y divide-border-subtle max-h-60 overflow-y-auto">
        {changed.map((k) => (
          <div key={k} className="grid grid-cols-3 gap-2 px-3 py-1.5 items-start">
            <span className="text-brand-title font-semibold break-all">{k}</span>
            <span className="text-status-danger/90 break-all">{fmtVal(b[k])}</span>
            <span className="text-status-success break-all">{fmtVal(a[k])}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
