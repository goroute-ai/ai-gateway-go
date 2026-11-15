import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { Badge } from '../../components/common/Badge';
import { ErrorAlert } from '../../components/common/ErrorAlert';
import { INPUT_CLS, BTN_PRIMARY } from '../../components/common/Modal';
import type {
  GuardrailSimulateResponse,
  GuardrailViolation,
} from '../../types';
import {
  Zap,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Activity,
  DollarSign,
  ShieldCheck,
} from 'lucide-react';

const formatMicroDollars = (micros?: number) => {
  const val = micros ?? 0;
  return `$${(val / 1_000_000).toLocaleString('en-US', {
    minimumFractionDigits: 4,
    maximumFractionDigits: 6,
  })}`;
};

export const SimulatorUsageTab: React.FC = () => {
  const { adminKey, activeOrgId } = useAuth();

  // Simulator / Apply state
  const [endpointMode, setEndpointMode] = useState<'simulate' | 'apply'>('simulate');
  const [virtualKeyToken, setVirtualKeyToken] = useState('');
  const [direction, setDirection] = useState<'input' | 'output'>('input');
  const [guardrailName, setGuardrailName] = useState('');
  const [tagsText, setTagsText] = useState('');
  const [streamChunkSize, setStreamChunkSize] = useState('0');
  const [modelName, setModelName] = useState('');
  const [payloadType, setPayloadType] = useState<'texts' | 'messages' | 'tool_calls'>('texts');
  const [textsInput, setTextsInput] = useState('');
  const [jsonPayload, setJsonPayload] = useState(
    JSON.stringify([{ role: 'user', content: 'Hello, summarize Q4 latency.' }], null, 2)
  );
  const [toolsJson, setToolsJson] = useState('');
  const [parseErr, setParseErr] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<
    (Omit<GuardrailSimulateResponse, 'allowed' | 'applied_action' | 'redacted'> & {
      allowed?: boolean;
      applied_action?: string;
      redacted?: boolean;
      usage_units?: number;
      latency_ms?: number;
    }) | null
  >(null);

  // Usage Dashboard filters
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [filterGuardrailId, setFilterGuardrailId] = useState('');
  const [filterTeamId, setFilterTeamId] = useState('');
  const [filterKeyId, setFilterKeyId] = useState('');

  const defsQuery = useQuery({
    queryKey: ['admin', 'guardrail-definitions', adminKey, activeOrgId, ''],
    queryFn: () => adminApi.listGuardrailDefinitions(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  const teamsQuery = useQuery({
    queryKey: ['admin', 'teams', adminKey, activeOrgId],
    queryFn: () => adminApi.listTeams(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  const keysQuery = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  const usageQuery = useQuery({
    queryKey: [
      'admin',
      'guardrail-usage',
      adminKey,
      activeOrgId,
      startDate,
      endDate,
      filterGuardrailId,
      filterTeamId,
      filterKeyId,
    ],
    queryFn: () =>
      adminApi.getGuardrailUsage(adminKey, activeOrgId, {
        ...(startDate ? { start_date: startDate } : {}),
        ...(endDate ? { end_date: endDate } : {}),
        ...(filterGuardrailId ? { guardrail_id: filterGuardrailId } : {}),
        ...(filterTeamId ? { team_id: filterTeamId } : {}),
        ...(filterKeyId ? { virtual_key_id: filterKeyId } : {}),
      }),
    enabled: !!adminKey && !!activeOrgId,
  });

  const runMutation = useMutation({
    mutationFn: async () => {
      setParseErr(null);
      const tags = tagsText
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      const chunkSz = Math.max(0, parseInt(streamChunkSize, 10) || 0);
      const parsedTools = toolsJson.trim() ? JSON.parse(toolsJson) : undefined;

      const base: Record<string, any> = {
        ...(guardrailName.trim() ? { guardrail_name: guardrailName.trim() } : {}),
        ...(tags.length > 0 ? { tags } : {}),
        ...(parsedTools ? { tools: parsedTools } : {}),
      };

      if (payloadType === 'texts') {
        const lines = textsInput
          .split('\n')
          .map((l) => l.trim())
          .filter(Boolean);
        base.texts = lines.length > 0 ? lines : [textsInput];
      } else if (payloadType === 'messages') {
        base.messages = JSON.parse(jsonPayload);
      } else {
        base.tool_calls = JSON.parse(jsonPayload);
      }

      if (endpointMode === 'apply') {
        if (!virtualKeyToken.trim()) {
          throw new Error('Provide a Virtual Key / Data Plane token to call POST /v1/guardrails/apply');
        }
        return adminApi.applyGuardrails(virtualKeyToken.trim(), {
          ...base,
          input_type: direction === 'output' ? 'response' : 'request',
          ...(modelName.trim() ? { model: modelName.trim() } : {}),
        });
      }

      return adminApi.simulateGuardrails(adminKey, activeOrgId, {
        ...base,
        direction,
        ...(chunkSz > 0 ? { stream_chunk_size: chunkSz } : {}),
      });
    },
    onSuccess: (res) => setRunResult(res),
    onError: (err: any) => setParseErr(err?.message || 'Execution failed'),
  });

  const loadSample = (kind: 'pii' | 'code_tool' | 'stream' | 'clean') => {
    setParseErr(null);
    if (kind === 'pii') {
      setPayloadType('texts');
      setDirection('input');
      setStreamChunkSize('0');
      setTextsInput('Customer Jane Doe SSN 000-55-9876 email jane@example.com');
    } else if (kind === 'code_tool') {
      setPayloadType('tool_calls');
      setDirection('input');
      setStreamChunkSize('0');
      setJsonPayload(
        JSON.stringify(
          [{ id: 'call_1', type: 'function', function: { name: 'bash', arguments: '{"cmd":"cat /etc/passwd"}' } }],
          null,
          2
        )
      );
    } else if (kind === 'stream') {
      setPayloadType('texts');
      setDirection('output');
      setStreamChunkSize('24');
      setTextsInput('Streaming chunk test: contact admin@example.com or use token sk-proj-abc1234567890xyz.');
    } else {
      setPayloadType('texts');
      setDirection('input');
      setStreamChunkSize('0');
      setTextsInput('Explain how GoRoute AI Gateway routes weighted model deployments.');
    }
  };

  const defs = defsQuery.data?.data || [];
  const teams = teamsQuery.data?.data || [];
  const keys = keysQuery.data?.data || [];
  const usage = usageQuery.data;
  const totals = usage?.totals;
  const totalCostMicros = usage?.total_cost_micros ?? totals?.total_cost_micros ?? 0;
  const allowedFlag = runResult ? (runResult.blocked !== undefined ? !runResult.blocked : runResult.allowed) : true;

  return (
    <div className="space-y-6">
      {/* Interactive Simulator & /v1/guardrails/apply Runner */}
      <div className="bg-surface-base border border-subtle rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-400" />
              Pipeline Simulator & `/v1/guardrails/apply` Tester
            </h3>
            <p className="text-[11px] text-zinc-400 mt-0.5">
              Evaluate named or effective tenant guardrails across texts, structured messages, tool calls, and sliding-window stream chunks.
            </p>
          </div>
          <div className="flex gap-1.5 text-[11px] font-mono">
            {([
              { id: 'simulate', label: 'Admin Dry-Run (/simulate)' },
              { id: 'apply', label: 'Data Plane (/v1/guardrails/apply)' },
            ] as const).map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => setEndpointMode(m.id)}
                className={`px-2.5 py-1 rounded border transition ${
                  endpointMode === m.id
                    ? 'bg-accent-primary/20 text-accent-primary border-accent-primary/40 font-semibold'
                    : 'bg-surface-elevated text-zinc-400 border-subtle hover:text-zinc-200'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">Direction</label>
            <select value={direction} onChange={(e) => setDirection(e.target.value as 'input' | 'output')} className={INPUT_CLS}>
              <option value="input">input (pre_call / request)</option>
              <option value="output">output (post_call / response)</option>
            </select>
          </div>
          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">Guardrail Name (optional)</label>
            <select value={guardrailName} onChange={(e) => setGuardrailName(e.target.value)} className={INPUT_CLS}>
              <option value="">All Effective Org Guardrails</option>
              {defs.map((d) => (
                <option key={d.id} value={d.name}>{d.name} ({d.provider})</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">Tags (comma-separated)</label>
            <input value={tagsText} onChange={(e) => setTagsText(e.target.value)} placeholder="e.g. prod, strict" className={INPUT_CLS} />
          </div>
          {endpointMode === 'simulate' ? (
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Stream Chunk Size (bytes, 0=off)</label>
              <input type="number" min={0} value={streamChunkSize} onChange={(e) => setStreamChunkSize(e.target.value)} className={INPUT_CLS} />
            </div>
          ) : (
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Model (optional)</label>
              <input value={modelName} onChange={(e) => setModelName(e.target.value)} placeholder="e.g. gpt-4o" className={INPUT_CLS} />
            </div>
          )}
        </div>

        {endpointMode === 'apply' && (
          <div>
            <label className="text-[11px] text-amber-300 font-mono block mb-1">Virtual Key / Data Plane Bearer Token *</label>
            <input
              type="password"
              value={virtualKeyToken}
              onChange={(e) => setVirtualKeyToken(e.target.value)}
              placeholder="gr-..."
              className={`${INPUT_CLS} font-mono`}
            />
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex gap-1.5 text-[11px] font-mono">
            {(['texts', 'messages', 'tool_calls'] as const).map((pt) => (
              <button
                key={pt}
                type="button"
                onClick={() => {
                  setPayloadType(pt);
                  if (pt === 'messages' && !jsonPayload.includes('"role"')) {
                    setJsonPayload(JSON.stringify([{ role: 'user', content: 'Test message' }], null, 2));
                  } else if (pt === 'tool_calls' && !jsonPayload.includes('"function"')) {
                    setJsonPayload(JSON.stringify([{ id: 'call_1', type: 'function', function: { name: 'bash', arguments: '{"cmd":"ls"}' } }], null, 2));
                  }
                }}
                className={`px-2.5 py-1 rounded border transition ${
                  payloadType === pt
                    ? 'bg-accent-primary/20 text-accent-primary border-accent-primary/40 font-semibold'
                    : 'bg-surface-elevated text-zinc-400 border-subtle'
                }`}
              >
                {pt}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
            <button type="button" onClick={() => loadSample('pii')} className="px-2 py-0.5 rounded bg-surface-elevated border border-subtle text-zinc-300">Sample: PII</button>
            <button type="button" onClick={() => loadSample('code_tool')} className="px-2 py-0.5 rounded bg-surface-elevated border border-subtle text-amber-300">Sample: Tool Call</button>
            <button type="button" onClick={() => loadSample('stream')} className="px-2 py-0.5 rounded bg-surface-elevated border border-subtle text-accent-primary">Sample: Stream</button>
            <button type="button" onClick={() => loadSample('clean')} className="px-2 py-0.5 rounded bg-surface-elevated border border-subtle text-zinc-400">Sample: Benign</button>
          </div>
        </div>

        {payloadType === 'texts' ? (
          <textarea
            rows={4}
            value={textsInput}
            onChange={(e) => setTextsInput(e.target.value)}
            placeholder="Enter one or more texts (one per line) to evaluate..."
            className={`${INPUT_CLS} font-mono`}
          />
        ) : (
          <textarea
            rows={5}
            value={jsonPayload}
            onChange={(e) => setJsonPayload(e.target.value)}
            className={`${INPUT_CLS} font-mono`}
          />
        )}

        <div>
          <label className="text-[11px] text-zinc-500 font-mono block mb-1">Tools Definitions (optional JSON array)</label>
          <textarea
            rows={2}
            value={toolsJson}
            onChange={(e) => setToolsJson(e.target.value)}
            placeholder='[{"type":"function","function":{"name":"lookup_order"}}]'
            className={`${INPUT_CLS} font-mono`}
          />
        </div>

        <div className="flex items-center justify-end">
          <button
            type="button"
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending}
            className={`${BTN_PRIMARY} flex items-center gap-1.5`}
          >
            <Zap className="w-3.5 h-3.5" />
            {runMutation.isPending
              ? 'Evaluating...'
              : endpointMode === 'apply'
              ? 'Run /v1/guardrails/apply'
              : 'Run Pipeline Simulation'}
          </button>
        </div>

        {parseErr && <ErrorAlert error={parseErr} title="Evaluation error" />}

        {runResult && (
          <div className="pt-4 border-t border-subtle space-y-3 text-xs font-mono">
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={allowedFlag ? 'success' : 'danger'}>
                {allowedFlag ? (
                  <span className="flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> ALLOWED</span>
                ) : (
                  <span className="flex items-center gap-1"><XCircle className="w-3 h-3" /> BLOCKED</span>
                )}
              </Badge>
              {runResult.decision && <span>decision: <strong className="text-zinc-100">{runResult.decision}</strong></span>}
              <span>action: <strong className="text-zinc-100">{runResult.action || runResult.applied_action}</strong></span>
              {runResult.usage_units !== undefined && <span>units: <strong className="text-zinc-100">{runResult.usage_units}</strong></span>}
              {runResult.latency_ms !== undefined && <span>latency: <strong className="text-zinc-100">{runResult.latency_ms}ms</strong></span>}
              {runResult.stream_chunks_evaluated !== undefined && (
                <span>chunks: <strong className="text-zinc-100">{runResult.stream_chunks_evaluated}</strong></span>
              )}
            </div>

            {runResult.applied_guardrails && runResult.applied_guardrails.length > 0 && (
              <div className="flex flex-wrap gap-1.5 items-center">
                <span className="text-[11px] text-zinc-400">Applied:</span>
                {runResult.applied_guardrails.map((g) => (
                  <Badge key={g} variant="info" size="sm">{g}</Badge>
                ))}
              </div>
            )}

            {runResult.error_message && (
              <div className="p-2 rounded bg-rose-950/30 border border-rose-500/30 text-rose-300">
                {runResult.error_message}
              </div>
            )}

            {runResult.violations && runResult.violations.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-[11px] text-amber-400 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5" /> Violations ({runResult.violations.length})
                </div>
                {runResult.violations.map((v, idx) => {
                  if (typeof v === 'string') {
                    return (
                      <div key={idx} className="p-2 rounded bg-rose-950/30 border border-rose-500/30 text-rose-300">
                        {v}
                      </div>
                    );
                  }
                  const gv = v as GuardrailViolation;
                  return (
                    <div key={idx} className="p-2.5 rounded bg-rose-950/30 border border-rose-500/30 text-rose-200 flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <span className="font-semibold text-zinc-100">{gv.guardrail_name}</span>
                        {gv.category && <span className="text-amber-300 ml-2">[{gv.category}]</span>}
                        {gv.rule && <span className="text-zinc-400 ml-2">({gv.rule})</span>}
                        <div className="text-rose-300 mt-0.5">{gv.message}</div>
                      </div>
                      <div className="flex gap-1.5">
                        {gv.severity && <Badge variant="warning" size="sm">{gv.severity}</Badge>}
                        {gv.score !== undefined && <Badge variant="neutral" size="sm">score:{gv.score}</Badge>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {(runResult.modified_texts?.length || runResult.redacted_prompt) && (
              <div>
                <div className="text-[11px] text-accent-primary mb-1">Modified / Redacted Output:</div>
                <pre className="p-2.5 bg-canvas border border-subtle rounded text-zinc-200 whitespace-pre-wrap">
                  {runResult.modified_texts?.length ? runResult.modified_texts.join('\n') : runResult.redacted_prompt}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Guardrail Usage & Micro-Dollar Cost Dashboard */}
      <div className="bg-surface-base border border-subtle rounded-lg p-5 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <Activity className="w-4 h-4 text-accent-primary" />
              Guardrail Usage & Micro-Dollar Cost Dashboard
            </h3>
            <p className="text-[11px] text-zinc-400 mt-0.5">
              Daily evaluations, blocks, redactions, flags, errors, and integer micro-dollar (`cost_micros / 1,000,000`) cost attribution.
            </p>
          </div>
          <button
            type="button"
            onClick={() => usageQuery.refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-elevated border border-subtle text-zinc-300 hover:text-white rounded text-xs font-mono"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        {/* Filters */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
          <div>
            <label className="text-[10px] text-zinc-500 font-mono block mb-1">Start Date</label>
            <input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} className={INPUT_CLS} />
          </div>
          <div>
            <label className="text-[10px] text-zinc-500 font-mono block mb-1">End Date</label>
            <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} className={INPUT_CLS} />
          </div>
          <div>
            <label className="text-[10px] text-zinc-500 font-mono block mb-1">Guardrail</label>
            <select value={filterGuardrailId} onChange={(e) => setFilterGuardrailId(e.target.value)} className={INPUT_CLS}>
              <option value="">All Guardrails</option>
              {defs.map((d) => (
                <option key={d.id} value={d.id}>{d.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[10px] text-zinc-500 font-mono block mb-1">Team</label>
            <select value={filterTeamId} onChange={(e) => setFilterTeamId(e.target.value)} className={INPUT_CLS}>
              <option value="">All Teams</option>
              {teams.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[10px] text-zinc-500 font-mono block mb-1">Virtual Key</label>
            <select value={filterKeyId} onChange={(e) => setFilterKeyId(e.target.value)} className={INPUT_CLS}>
              <option value="">All Keys</option>
              {keys.map((k) => (
                <option key={k.id} value={k.id}>{k.name}</option>
              ))}
            </select>
          </div>
        </div>

        {usageQuery.isError && (
          <ErrorAlert error={usageQuery.error} title="Failed to load guardrail usage" onRetry={() => usageQuery.refetch()} />
        )}

        {/* KPI Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            {
              label: 'Total Evaluations',
              val: (totals?.evaluations ?? 0).toLocaleString(),
              sub: `${(totals?.errors ?? 0).toLocaleString()} evaluation errors`,
              icon: <ShieldCheck className="w-4 h-4 text-accent-primary" />,
            },
            {
              label: 'Blocks & Redactions',
              val: `${(totals?.blocks ?? 0).toLocaleString()} / ${(totals?.redactions ?? 0).toLocaleString()}`,
              sub: `${(totals?.flags ?? 0).toLocaleString()} flagged (audit)`,
              icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
            },
            {
              label: 'Total Usage Units',
              val: (totals?.total_units ?? 0).toLocaleString(),
              sub: totals?.evaluations
                ? `avg ${Math.round((totals.latency_sum_ms || 0) / totals.evaluations)}ms latency`
                : 'No evaluations yet',
              icon: <Activity className="w-4 h-4 text-accent-glow" />,
            },
            {
              label: 'Guardrail Cost',
              val: formatMicroDollars(totalCostMicros),
              sub: `${totalCostMicros.toLocaleString()} µ$ integer ledger`,
              icon: <DollarSign className="w-4 h-4 text-emerald-400" />,
            },
          ].map((k) => (
            <div key={k.label} className="bg-surface-elevated/40 border border-subtle rounded-lg p-4">
              <div className="flex items-center justify-between text-zinc-400 mb-1">
                <span className="text-[11px] font-mono uppercase">{k.label}</span>
                {k.icon}
              </div>
              <div className="text-xl font-bold font-mono text-zinc-100">
                {usageQuery.isLoading ? '...' : k.val}
              </div>
              <div className="text-[11px] text-zinc-500 font-mono mt-1">{k.sub}</div>
            </div>
          ))}
        </div>

        {/* Top Triggered Guardrails */}
        <div className="space-y-2">
          <h4 className="text-xs font-mono text-zinc-300 uppercase">Top Triggered Guardrails</h4>
          {!usage?.top_triggered?.length ? (
            <div className="py-4 text-center text-xs font-mono text-zinc-500 border border-subtle rounded">
              No guardrail evaluations recorded in this window.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-subtle text-zinc-500 text-[11px] uppercase">
                    <th className="py-2 pr-3">Guardrail</th>
                    <th className="py-2 pr-3">Evals</th>
                    <th className="py-2 pr-3">Blocks</th>
                    <th className="py-2 pr-3">Redactions</th>
                    <th className="py-2 pr-3">Flags</th>
                    <th className="py-2 pr-3">Errors</th>
                    <th className="py-2 pr-3">Units</th>
                    <th className="py-2 text-right">Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle">
                  {usage.top_triggered.map((t) => (
                    <tr key={t.guardrail_id} className="text-zinc-300">
                      <td className="py-2 pr-3 font-semibold text-zinc-100">{t.guardrail_name || t.guardrail_id}</td>
                      <td className="py-2 pr-3">{t.evaluations.toLocaleString()}</td>
                      <td className="py-2 pr-3 text-rose-400">{t.blocks.toLocaleString()}</td>
                      <td className="py-2 pr-3 text-amber-300">{t.redactions.toLocaleString()}</td>
                      <td className="py-2 pr-3 text-zinc-300">{t.flags.toLocaleString()}</td>
                      <td className="py-2 pr-3 text-zinc-400">{t.errors.toLocaleString()}</td>
                      <td className="py-2 pr-3">{t.units.toLocaleString()}</td>
                      <td className="py-2 text-right text-emerald-400">{formatMicroDollars(t.cost_micros)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Daily Series */}
        {usage?.daily_series && usage.daily_series.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-mono text-zinc-300 uppercase">Daily Evaluation Rollups</h4>
            <div className="overflow-x-auto max-h-48 overflow-y-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-subtle text-zinc-500 text-[11px] uppercase">
                    <th className="py-2 pr-3">Date</th>
                    <th className="py-2 pr-3">Guardrail</th>
                    <th className="py-2 pr-3">Evals</th>
                    <th className="py-2 pr-3">Blocks</th>
                    <th className="py-2 pr-3">Redactions</th>
                    <th className="py-2 pr-3">Flags</th>
                    <th className="py-2 pr-3">Avg Latency</th>
                    <th className="py-2 pr-3">Units</th>
                    <th className="py-2 text-right">Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle">
                  {usage.daily_series.map((pt, i) => (
                    <tr key={`${pt.date}-${pt.guardrail_id}-${i}`} className="text-zinc-300">
                      <td className="py-2 pr-3">{pt.date}</td>
                      <td className="py-2 pr-3 text-zinc-100">{pt.guardrail_name || pt.guardrail_id}</td>
                      <td className="py-2 pr-3">{pt.evaluations.toLocaleString()}</td>
                      <td className="py-2 pr-3 text-rose-400">{pt.blocks.toLocaleString()}</td>
                      <td className="py-2 pr-3 text-amber-300">{pt.redactions.toLocaleString()}</td>
                      <td className="py-2 pr-3">{pt.flags.toLocaleString()}</td>
                      <td className="py-2 pr-3">{pt.evaluations > 0 ? `${Math.round(pt.latency_sum_ms / pt.evaluations)}ms` : '0ms'}</td>
                      <td className="py-2 pr-3">{pt.units.toLocaleString()}</td>
                      <td className="py-2 text-right text-emerald-400">{formatMicroDollars(pt.cost_micros)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Usage Units Breakdown */}
        {usage?.usage_units && usage.usage_units.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-mono text-zinc-300 uppercase">Usage Units Attribution</h4>
            <div className="overflow-x-auto max-h-48 overflow-y-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-subtle text-zinc-500 text-[11px] uppercase">
                    <th className="py-2 pr-3">Date</th>
                    <th className="py-2 pr-3">Guardrail</th>
                    <th className="py-2 pr-3">Tenant Scope</th>
                    <th className="py-2 pr-3">Unit</th>
                    <th className="py-2 pr-3">Units</th>
                    <th className="py-2 text-right">Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle">
                  {usage.usage_units.map((u, i) => (
                    <tr key={`${u.date}-${u.guardrail_id}-${u.usage_unit}-${i}`} className="text-zinc-300">
                      <td className="py-2 pr-3">{u.date}</td>
                      <td className="py-2 pr-3 text-zinc-100">{u.guardrail_id}</td>
                      <td className="py-2 pr-3 text-zinc-400">
                        {u.team_id || u.virtual_key_id ? `${u.team_id || '-'} / ${u.virtual_key_id || '-'}` : 'org'}
                      </td>
                      <td className="py-2 pr-3">{u.usage_unit}</td>
                      <td className="py-2 pr-3">{u.units.toLocaleString()}</td>
                      <td className="py-2 text-right text-emerald-400">{formatMicroDollars(u.cost_micros)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
