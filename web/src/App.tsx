import React, { useState, Suspense, lazy } from 'react';
import { Header } from './components/layout/Header';
import { Sidebar, NavView } from './components/layout/Sidebar';
import { useAuth } from './context/AuthContext';
import { Lock, KeyRound, Loader2 } from 'lucide-react';

const OverviewView = lazy(() => import('./views/OverviewView').then((m) => ({ default: m.OverviewView })));
const PlaygroundView = lazy(() => import('./views/PlaygroundView').then((m) => ({ default: m.PlaygroundView })));
const KeysView = lazy(() => import('./views/KeysView').then((m) => ({ default: m.KeysView })));
const CredentialsView = lazy(() => import('./views/CredentialsView').then((m) => ({ default: m.CredentialsView })));
const ModelsView = lazy(() => import('./views/ModelsView').then((m) => ({ default: m.ModelsView })));
const FinOpsView = lazy(() => import('./views/FinOpsView').then((m) => ({ default: m.FinOpsView })));
const GuardrailsView = lazy(() => import('./views/GuardrailsView').then((m) => ({ default: m.GuardrailsView })));
const AgenticView = lazy(() => import('./views/AgenticView').then((m) => ({ default: m.AgenticView })));

const ViewLoadingFallback = () => (
  <div className="flex items-center justify-center h-64 text-zinc-500 font-mono text-xs gap-2">
    <Loader2 className="w-4 h-4 animate-spin text-accent-primary" />
    <span>Loading view components...</span>
  </div>
);

export const App: React.FC = () => {
  const [activeView, setActiveView] = useState<NavView>('overview');
  const { isUnlocked, setAdminKey } = useAuth();
  const [tempKeyInput, setTempKeyInput] = useState('');

  const renderActiveView = () => {
    switch (activeView) {
      case 'overview':
        return <OverviewView onNavigateToPlayground={() => setActiveView('playground')} />;
      case 'playground':
        return <PlaygroundView />;
      case 'keys':
        return <KeysView onNavigateToPlayground={() => setActiveView('playground')} />;
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
        return <OverviewView onNavigateToPlayground={() => setActiveView('playground')} />;
    }
  };

  return (
    <div className="min-h-screen bg-canvas text-zinc-100 flex flex-col font-sans selection:bg-accent-primary/20 selection:text-accent-glow">
      <Header currentView={activeView} />

      <div className="flex flex-1">
        <Sidebar activeView={activeView} onSelectView={setActiveView} />

        <main className="flex-1 p-6 overflow-y-auto">
          {!isUnlocked ? (
            <div className="max-w-md mx-auto my-16 p-6 bg-surface-base border border-subtle rounded-xl shadow-2xl text-center space-y-4">
              <div className="w-12 h-12 mx-auto rounded-full bg-accent-primary/10 border border-accent-primary/30 flex items-center justify-center text-accent-primary">
                <Lock className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-zinc-100 font-mono">Control Plane Locked</h3>
                <p className="text-xs text-zinc-400 mt-1">
                  Enter your <code className="text-accent-primary font-mono">GATEWAY_MASTER_ADMIN_KEY</code> to access administrative configuration, credentials, and telemetry.
                </p>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (tempKeyInput.trim()) {
                    setAdminKey(tempKeyInput.trim());
                    setTempKeyInput('');
                  }
                }}
                className="space-y-3 pt-2"
              >
                <div className="relative">
                  <KeyRound className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="password"
                    value={tempKeyInput}
                    onChange={(e) => setTempKeyInput(e.target.value)}
                    placeholder="Enter Master Admin Key..."
                    className="w-full pl-9 pr-3 py-2 text-xs bg-canvas border border-subtle rounded-lg text-zinc-200 placeholder-zinc-500 font-mono focus:outline-none focus:border-accent-primary"
                    autoFocus
                  />
                </div>

                <button
                  type="submit"
                  disabled={!tempKeyInput.trim()}
                  className="w-full py-2 bg-accent-primary hover:bg-accent-glow text-zinc-950 font-medium rounded-lg text-xs font-mono transition disabled:opacity-40"
                >
                  Unlock Session
                </button>
              </form>

              <div className="text-[11px] text-zinc-500 font-mono pt-2 border-t border-subtle">
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
