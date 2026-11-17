import React, { useMemo, useState } from 'react';
import { authApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { ErrorAlert } from '../components/common/ErrorAlert';
import { MONO_INPUT_CLS, BTN_PRIMARY } from '../components/common/Modal';
import { AlertTriangle, Key, RefreshCw, ShieldCheck } from 'lucide-react';

const TTL_OPTS = [
  ['1 hour', 3600],
  ['24 hours (default)', 86400],
  ['7 days', 604800],
  ['30 days (max)', 2592000],
] as const;
const LBL = 'block text-[11px] font-mono text-brand-muted mb-1';
const CARD = 'max-w-lg mx-auto my-12 p-8 bg-surface-base border border-border rounded-xl';

export const CLILoginView: React.FC<{ onDone: () => void }> = ({ onDone }) => {
  const { adminKey, operator, activeOrgId } = useAuth();
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const loginId = (params.get('login_id') || '').trim();
  const userCode = (params.get('user_code') || '').trim();

  const [orgId, setOrgId] = useState(operator?.org_id || activeOrgId || 'org_default');
  const [teamId, setTeamId] = useState(operator?.team_id || '');
  const [keyName, setKeyName] = useState('cli-login');
  const [ttlSeconds, setTtlSeconds] = useState(86400);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ org_id: string; key_prefix: string } | null>(null);

  const isPlatformAdmin = operator?.role === 'platform_admin';
  const isViewer = operator?.role === 'org_viewer';

  const onApprove = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginId || busy || isViewer) return;
    setError(null);
    setBusy(true);
    try {
      const res = await authApi.completeCLILogin(
        loginId,
        { org_id: orgId.trim() || undefined, team_id: teamId.trim() || undefined, key_name: keyName.trim() || undefined, ttl_seconds: ttlSeconds },
        adminKey || undefined
      );
      setResult(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to approve CLI login session.');
    } finally {
      setBusy(false);
    }
  };

  if (!loginId) {
    return (
      <div className={`${CARD} space-y-4`}>
        <h2 className="text-base font-bold text-brand-title font-mono">Approve CLI Login</h2>
        <ErrorAlert error="Missing login_id parameter. Re-run CLI login for a fresh verification URL." title="Invalid CLI Login Link" />
        <button type="button" onClick={onDone} className={`${BTN_PRIMARY} px-4 py-2 text-xs`}>Return to Control Plane</button>
      </div>
    );
  }

  return (
    <div className={`${CARD} shadow-2xl space-y-5`}>
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-accent-soft border border-accent-primary/25 flex items-center justify-center">
          <Key className="w-5 h-5 text-accent-primary" />
        </div>
        <div>
          <h2 className="text-base font-bold text-brand-title font-mono">Approve CLI Login</h2>
          <p className="text-xs text-brand-muted">Mint a short-lived virtual API key for your local CLI or SDK session.</p>
        </div>
      </div>

      <div className="p-4 rounded-lg bg-surface-elevated border border-border space-y-1.5 font-mono text-xs">
        {userCode && (
          <div className="flex justify-between">
            <span className="text-brand-muted">Verification Code</span>
            <span className="text-base font-bold tracking-widest text-accent-primary">{userCode}</span>
          </div>
        )}
        <div className="flex justify-between gap-4">
          <span className="text-brand-muted">Login Session</span>
          <span className="text-brand-title truncate">{loginId}</span>
        </div>
        {operator && (
          <div className="flex justify-between gap-4">
            <span className="text-brand-muted">Signed In As</span>
            <span className="text-brand-title">{operator.actor_id} ({operator.role})</span>
          </div>
        )}
      </div>

      {error && <ErrorAlert error={error} title="Approval Failed" />}

      {result ? (
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-accent-primary/30 bg-accent-soft text-xs space-y-1.5">
            <div className="flex items-center gap-2 text-accent-primary font-semibold font-mono">
              <ShieldCheck className="w-4 h-4" />
              <span>CLI Session Approved</span>
            </div>
            <p className="text-brand-body">
              Issued key <code className="font-mono text-brand-title">{result.key_prefix}...</code> for <code className="font-mono text-brand-title">{result.org_id}</code>. Return to your terminal.
            </p>
          </div>
          <button type="button" onClick={onDone} className={`${BTN_PRIMARY} w-full py-2 text-xs`}>Continue to Control Plane</button>
        </div>
      ) : isViewer ? (
        <div className="space-y-4">
          <div className="p-4 rounded-lg border status-warning text-xs flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>Read-only <code className="font-mono">org_viewer</code> operators cannot approve CLI key issuance.</span>
          </div>
          <button type="button" onClick={onDone} className={`${BTN_PRIMARY} w-full py-2 text-xs`}>Return to Control Plane</button>
        </div>
      ) : (
        <form onSubmit={onApprove} className="space-y-3">
          <div>
            <label className={LBL}>Organization</label>
            <input type="text" value={orgId} onChange={(e) => setOrgId(e.target.value)} readOnly={!isPlatformAdmin} className={MONO_INPUT_CLS} />
          </div>
          <div>
            <label className={LBL}>Team (Optional)</label>
            <input type="text" value={teamId} onChange={(e) => setTeamId(e.target.value)} placeholder="Optional team ID" className={MONO_INPUT_CLS} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={LBL}>Key Name</label>
              <input type="text" value={keyName} onChange={(e) => setKeyName(e.target.value)} className={MONO_INPUT_CLS} />
            </div>
            <div>
              <label className={LBL}>Key Lifetime</label>
              <select value={ttlSeconds} onChange={(e) => setTtlSeconds(Number(e.target.value))} className={MONO_INPUT_CLS}>
                {TTL_OPTS.map(([label, secs]) => <option key={secs} value={secs}>{label}</option>)}
              </select>
            </div>
          </div>
          <div className="flex gap-3 pt-1">
            <button type="submit" disabled={busy} className={`${BTN_PRIMARY} flex-1 py-2 flex items-center justify-center gap-2 text-xs`}>
              {busy && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>{busy ? 'Approving...' : 'Approve CLI Login'}</span>
            </button>
            <button type="button" onClick={onDone} className="px-4 py-2 rounded-lg border border-border bg-surface-elevated text-xs text-brand-body">Cancel</button>
          </div>
        </form>
      )}
    </div>
  );
};
