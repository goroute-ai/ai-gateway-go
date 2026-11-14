import React, { useState, useEffect, Suspense, lazy } from 'react';
import { Header } from './components/layout/Header';
import { Sidebar, NavView } from './components/layout/Sidebar';
import { ErrorAlert } from './components/common/ErrorAlert';
import { useAuth } from './context/AuthContext';
import { Key, RefreshCw } from 'lucide-react';

const OverviewView = lazy(() => import('./views/OverviewView').then((m) => ({ default: m.OverviewView })));
const PlaygroundView = lazy(() => import('./views/PlaygroundView').then((m) => ({ default: m.PlaygroundView })));
const OrganizationsView = lazy(() => import('./views/OrganizationsView').then((m) => ({ default: m.OrganizationsView })));
const KeysView = lazy(() => import('./views/KeysView').then((m) => ({ default: m.KeysView })));
const CredentialsView = lazy(() => import('./views/CredentialsView').then((m) => ({ default: m.CredentialsView })));
const ModelsView = lazy(() => import('./views/ModelsView').then((m) => ({ default: m.ModelsView })));
const FinOpsView = lazy(() => import('./views/FinOpsView').then((m) => ({ default: m.FinOpsView })));
const GuardrailsView = lazy(() => import('./views/GuardrailsView').then((m) => ({ default: m.GuardrailsView })));
const AgenticView = lazy(() => import('./views/AgenticView').then((m) => ({ default: m.AgenticView })));

const VALID_VIEWS: ReadonlySet<NavView> = new Set([
  'overview',
  'playground',
  'organizations',
  'keys',
  'credentials',
  'models',
  'finops',
  'guardrails',
  'agentic',
]);

function parseViewFromPath(pathname: string): NavView {
  const stripped = pathname.replace(/^\/ui\/?/, '').split('/')[0] as NavView;
  return VALID_VIEWS.has(stripped) ? stripped : 'overview';
}

const ViewLoadingFallback = () => (
  <div className="flex items-center justify-center h-64 text-zinc-500 font-mono text-xs gap-2">
    <RefreshCw className="w-4 h-4 animate-spin text-accent-primary" />
    <span>Loading view components...</span>
  </div>
);

export const App: React.FC = () => {
  const [activeView, setActiveView] = useState<NavView>(() => parseViewFromPath(window.location.pathname));
  const { isUnlocked, unlockWithKey } = useAuth();
  const [tempKeyInput, setTempKeyInput] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [isUnlocking, setIsUnlocking] = useState(false);

  const navigateTo = (view: NavView) => {
    setActiveView(view);
    const targetPath = view === 'overview' ? '/ui/' : `/ui/${view}`;
    if (window.location.pathname !== targetPath) {
      window.history.pushState({ view }, '', targetPath);
    }
  };

  useEffect(() => {
    const onPopState = () => {
      setActiveView(parseViewFromPath(window.location.pathname));
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const handleUnlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tempKeyInput.trim() || isUnlocking) return;
    setUnlockError(null);
    setIsUnlocking(true);
    try {
      await unlockWithKey(tempKeyInput);
      setTempKeyInput('');
    } catch (err: any) {
      setUnlockError(err?.message || 'Authentication failed: invalid Master Admin Key.');
    } finally {
      setIsUnlocking(false);
    }
  };

  const renderActiveView = () => {
    switch (activeView) {
      case 'overview':
        return <OverviewView onNavigateToPlayground={() => navigateTo('playground')} />;
      case 'playground':
        return <PlaygroundView />;
      case 'organizations':
        return <OrganizationsView />;
      case 'keys':
        return <KeysView onNavigateToPlayground={() => navigateTo('playground')} />;
      case 'credentials':
        return <CredentialsView />;
      case 'models':
        return <ModelsView />;
      case 'finops':
        return <FinOpsView />;
      case 'guardrails':
        return <GuardrailsView />;
      case 'agentic':
        return <AgenticView />;
      default:
        return <OverviewView onNavigateToPlayground={() => navigateTo('playground')} />;
    }
  };

  return (
    <div className="min-h-screen bg-canvas text-[#d2d0dc] flex flex-col font-sans selection:bg-accent-primary/20 selection:text-accent-glow">
      <Header currentView={activeView} />

      <div className="flex flex-1">
        <Sidebar activeView={activeView} onSelectView={navigateTo} />

        <main className="flex-1 p-6 overflow-y-auto">
          {!isUnlocked ? (
            <div className="max-w-md mx-auto my-16 p-8 bg-surface-base border border-border rounded-xl shadow-2xl text-center space-y-5">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-[rgba(124,58,237,0.08)] border border-accent-primary/25 flex items-center justify-center p-2.5 shadow-[0_4px_20px_rgba(124,58,237,0.18)]">
                <img
                  src="./logo-dark.png"
                  alt="GoRoute AI Gateway"
                  className="w-full h-full object-contain"
                />
              </div>
              <div>
                <h3 className="text-base font-bold text-[#f5f3ff] font-mono tracking-tight">
                  Control Plane Locked
                </h3>
                <p className="text-xs text-[#9696a4] mt-1.5 leading-relaxed">
                  Enter your <code className="text-accent-primary font-mono bg-accent-soft px-1.5 py-0.5 rounded border border-accent-primary/20">GATEWAY_MASTER_ADMIN_KEY</code> to access administrative configuration, credentials, and telemetry.
                </p>
              </div>

              <form onSubmit={handleUnlockSubmit} className="space-y-3 pt-2">
                <div className="relative">
                  <Key className="w-4 h-4 text-[#9696a4] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="password"
                    value={tempKeyInput}
                    onChange={(e) => {
                      setTempKeyInput(e.target.value);
                      if (unlockError) setUnlockError(null);
                    }}
                    placeholder="Enter Master Admin Key..."
                    className="w-full pl-9 pr-3 py-2.5 text-xs bg-canvas border border-border rounded-lg text-[#f5f3ff] placeholder-[#9696a4] font-mono focus:outline-none focus:border-accent-primary"
                    autoFocus
                  />
                </div>

                {unlockError && (
                  <ErrorAlert error={unlockError} title="Unlock Failed" />
                )}

                <button
                  type="submit"
                  disabled={!tempKeyInput.trim() || isUnlocking}
                  className="w-full py-2.5 bg-accent-primary hover:bg-accent-dark text-black font-semibold rounded-lg text-xs font-mono transition shadow-lg shadow-accent-primary/20 disabled:opacity-40 flex items-center justify-center gap-2"
                >
                  {isUnlocking && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{isUnlocking ? 'Verifying Key...' : 'Unlock Session'}</span>
                </button>
              </form>

              <div className="text-[11px] text-[#9696a4] font-mono pt-3 border-t border-border">
                🛡️ Stored strictly in React memory state. Retained across in-app navigation; cleared on reload, tab close, or manual lock.
              </div>
            </div>
          ) : (
            <Suspense fallback={<ViewLoadingFallback />}>
              {renderActiveView()}
            </Suspense>
          )}
        </main>
      </div>
    </div>
  );
};
