import React, { useState, useEffect, Suspense, lazy } from 'react';
import { Header } from './components/layout/Header';
import { Sidebar, NavView } from './components/layout/Sidebar';
import { useAuth } from './context/AuthContext';
import { AlertTriangle, RefreshCw } from 'lucide-react';

const LoginView = lazy(() => import('./views/LoginView').then((m) => ({ default: m.LoginView })));
const OverviewView = lazy(() => import('./views/OverviewView').then((m) => ({ default: m.OverviewView })));
const PlaygroundView = lazy(() => import('./views/PlaygroundView').then((m) => ({ default: m.PlaygroundView })));
const OrganizationsView = lazy(() => import('./views/OrganizationsView').then((m) => ({ default: m.OrganizationsView })));
const KeysView = lazy(() => import('./views/KeysView').then((m) => ({ default: m.KeysView })));
const CredentialsView = lazy(() => import('./views/CredentialsView').then((m) => ({ default: m.CredentialsView })));
const ModelsView = lazy(() => import('./views/ModelsView').then((m) => ({ default: m.ModelsView })));
const FinOpsView = lazy(() => import('./views/FinOpsView').then((m) => ({ default: m.FinOpsView })));
const GuardrailsView = lazy(() => import('./views/GuardrailsView').then((m) => ({ default: m.GuardrailsView })));
const AgenticView = lazy(() => import('./views/AgenticView').then((m) => ({ default: m.AgenticView })));
const ConfigView = lazy(() => import('./views/ConfigView').then((m) => ({ default: m.ConfigView })));

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
  'config',
]);

function parseViewFromPath(pathname: string): NavView {
  const stripped = pathname.replace(/^\/ui\/?/, '').split('/')[0] as NavView;
  return VALID_VIEWS.has(stripped) ? stripped : 'overview';
}

const ViewLoadingFallback = () => (
  <div className="flex items-center justify-center h-64 text-brand-muted font-mono text-xs gap-2">
    <RefreshCw className="w-4 h-4 animate-spin text-accent-primary" />
    <span>Loading view components...</span>
  </div>
);

export const App: React.FC = () => {
  const [activeView, setActiveView] = useState<NavView>(() => parseViewFromPath(window.location.pathname));
  const { isUnlocked, isBootstrapping, deprecatedKeyRevokeAt } = useAuth();

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
      case 'config':
        return <ConfigView />;
      default:
        return <OverviewView onNavigateToPlayground={() => navigateTo('playground')} />;
    }
  };

  return (
    <div className="min-h-screen bg-canvas text-brand-body flex flex-col font-sans selection:bg-accent-primary/20 selection:text-accent-glow">
      <Header currentView={activeView} />

      <div className="flex flex-1">
        <Sidebar activeView={activeView} onSelectView={navigateTo} />

        <main className="flex-1 p-6 overflow-y-auto">
          {isBootstrapping ? (
            <ViewLoadingFallback />
          ) : !isUnlocked ? (
            <Suspense fallback={<ViewLoadingFallback />}>
              <LoginView />
            </Suspense>
          ) : (
            <>
              {deprecatedKeyRevokeAt && (
                <div className="mb-4 p-3 rounded-lg border status-warning flex items-center gap-2 text-xs font-mono">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>
                    Authenticated with a deprecated virtual key in grace period.
                    {deprecatedKeyRevokeAt !== 'scheduled'
                      ? ` Revokes at ${new Date(deprecatedKeyRevokeAt).toLocaleString()}.`
                      : ''}
                  </span>
                </div>
              )}
              <Suspense fallback={<ViewLoadingFallback />}>
                {renderActiveView()}
              </Suspense>
            </>
          )}
        </main>
      </div>
    </div>
  );
};
