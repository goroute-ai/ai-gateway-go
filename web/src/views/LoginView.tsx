import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { authApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { ErrorAlert } from '../components/common/ErrorAlert';
import { Field, MONO_INPUT_CLS, BTN_PRIMARY } from '../components/common/Modal';
import { Key, Lock, RefreshCw, ShieldCheck } from 'lucide-react';

export const LoginView: React.FC = () => {
  const { loginWithPassword, unlockWithKey } = useAuth();
  const [tab, setTab] = useState<'operator' | 'break_glass'>('operator');
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [masterKey, setMasterKey] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const { data: ssoData, isLoading: ssoLoading } = useQuery({
    queryKey: ['auth', 'sso-providers'],
    queryFn: () => authApi.getSSOProviders(),
    staleTime: 60000,
    retry: false,
  });
  const providers = ssoData?.providers || [];

  const handleSSOLogin = (id: string) => {
    const p = window.location.pathname;
    const redir = p.startsWith('/ui') ? p : '/ui/';
    window.location.assign(`/auth/sso/${encodeURIComponent(id)}/login?redirect_after=${encodeURIComponent(redir)}`);
  };

  const runAuth = async (fn: () => Promise<void>, clear: () => void, fallback: string) => {
    if (busy) return;
    setAuthError(null);
    setBusy(true);
    try { await fn(); clear(); }
    catch (err: any) { setAuthError(err?.message || fallback); }
    finally { setBusy(false); }
  };

  const tabCls = (active: boolean) =>
    `py-1.5 px-2 rounded-md flex items-center justify-center gap-1.5 transition ${
      active ? 'bg-accent-soft text-accent-primary border border-accent-primary/30 font-semibold' : 'text-brand-muted hover:text-brand-title'
    }`;

  return (
    <div className="max-w-md mx-auto my-12 p-8 bg-surface-base border border-border rounded-xl shadow-2xl space-y-5">
      <div className="text-center space-y-3">
        <div className="w-16 h-16 mx-auto rounded-2xl bg-accent-soft border border-accent-primary/25 flex items-center justify-center p-2.5">
          <img src="/ui/logo-dark.png" alt="GoRoute AI Gateway" className="w-full h-full object-contain" />
        </div>
        <div>
          <h3 className="text-base font-bold text-brand-title font-mono">Control Plane Sign In</h3>
          <p className="text-xs text-brand-muted mt-1">Sign in with OIDC SSO, operator credentials, or a break-glass key.</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-1.5 p-1 bg-surface-elevated border border-border rounded-lg text-xs font-mono">
        <button type="button" onClick={() => { setTab('operator'); setAuthError(null); }} className={tabCls(tab === 'operator')}>
          <ShieldCheck className="w-3.5 h-3.5" /><span>SSO &amp; Password</span>
        </button>
        <button type="button" onClick={() => { setTab('break_glass'); setAuthError(null); }} className={tabCls(tab === 'break_glass')}>
          <Key className="w-3.5 h-3.5" /><span>Break-Glass Key</span>
        </button>
      </div>

      {authError && <ErrorAlert error={authError} title="Sign In Failed" />}

      {tab === 'operator' ? (
        <div className="space-y-4">
          {providers.length > 0 ? (
            <div className="space-y-2">
              {providers.map((p) => (
                <button key={p.id} type="button" onClick={() => handleSSOLogin(p.id)} className="w-full py-2 px-3 bg-surface-elevated hover:bg-surface-hover border border-border-strong text-brand-title rounded-lg text-xs font-medium flex items-center justify-between">
                  <span className="flex items-center gap-2"><ShieldCheck className="w-3.5 h-3.5 text-accent-primary" />Continue with {p.display_name || p.id}</span>
                  <span className="text-[10px] font-mono uppercase text-brand-muted">{p.type || 'oidc'}</span>
                </button>
              ))}
              <div className="text-center text-[10px] font-mono uppercase text-brand-muted pt-1">or password</div>
            </div>
          ) : !ssoLoading && (
            <div className="text-[11px] text-brand-muted font-mono bg-surface-elevated/60 border border-border rounded-lg px-3 py-2">
              No OIDC SSO providers configured.
            </div>
          )}

          <form onSubmit={(e) => { e.preventDefault(); if (identifier.trim() && password) void runAuth(() => loginWithPassword(identifier, password), () => setPassword(''), 'Invalid credentials.'); }} className="space-y-3">
            <Field label="Email or Username">
              <input type="text" autoComplete="username" required value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder="operator@example.com or admin" className={MONO_INPUT_CLS} autoFocus />
            </Field>
            <Field label="Password">
              <div className="relative">
                <Lock className="w-3.5 h-3.5 text-brand-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter password..." className={`${MONO_INPUT_CLS} pl-9`} />
              </div>
            </Field>
            <button type="submit" disabled={!identifier.trim() || !password || busy} className={`${BTN_PRIMARY} w-full py-2 flex items-center justify-center gap-2`}>
              {busy && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>{busy ? 'Signing In...' : 'Sign In'}</span>
            </button>
          </form>
        </div>
      ) : (
        <form onSubmit={(e) => { e.preventDefault(); if (masterKey.trim()) void runAuth(() => unlockWithKey(masterKey), () => setMasterKey(''), 'Invalid Master Admin Key.'); }} className="space-y-3">
          <p className="text-xs text-brand-muted">
            Emergency break-glass access using <code className="text-accent-primary font-mono">GATEWAY_MASTER_ADMIN_KEY</code>.
          </p>
          <div className="relative">
            <Key className="w-4 h-4 text-brand-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input type="password" value={masterKey} onChange={(e) => setMasterKey(e.target.value)} placeholder="Enter Master Admin Key..." className={`${MONO_INPUT_CLS} pl-9`} autoFocus />
          </div>
          <button type="submit" disabled={!masterKey.trim() || busy} className={`${BTN_PRIMARY} w-full py-2 flex items-center justify-center gap-2`}>
            {busy && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            <span>{busy ? 'Verifying Key...' : 'Unlock Break-Glass Session'}</span>
          </button>
        </form>
      )}
    </div>
  );
};
