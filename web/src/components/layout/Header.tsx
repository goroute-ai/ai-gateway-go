import React from 'react';
import { Lock, Building2, Key, Sun, Moon, ShieldCheck } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { useQuery } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';

interface HeaderProps {
  currentView: string;
}

export const Header: React.FC<HeaderProps> = ({ currentView }) => {
  const {
    adminKey,
    authMode,
    operator,
    currentUser,
    isUnlocked,
    logout,
    activeOrgId,
    setActiveOrgId,
  } = useAuth();
  const { theme, toggleTheme } = useTheme();

  const { data: orgsData } = useQuery({
    queryKey: ['admin', 'orgs', adminKey, authMode],
    queryFn: () => adminApi.listOrgs(adminKey),
    enabled: isUnlocked,
    staleTime: 60000,
  });

  const identityLabel = currentUser?.email || operator?.actor_id || 'operator';

  return (
    <header className="h-16 border-b border-border bg-canvas/85 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-5">
        <div className="flex items-center gap-3">
          <img
            src="/ui/logo-dark.png"
            alt="GoRoute AI Gateway Logo"
            className="h-8 w-auto object-contain"
          />
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5 leading-none">
              <span className="font-bold text-sm tracking-tight text-brand-title">
                GoRoute
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-accent-soft text-accent-primary border border-accent-primary/25 font-semibold">
                AI Gateway
              </span>
            </div>
            <span className="text-[10px] font-mono text-brand-muted tracking-wider mt-0.5">Control Plane</span>
          </div>
        </div>

        <div className="h-5 w-[1px] bg-border hidden sm:block" />

        <div className="hidden sm:flex items-center gap-2 text-xs text-brand-muted">
          <span className="w-2 h-2 rounded-full bg-accent-primary animate-pulse" />
          <span className="capitalize text-brand-title font-medium">{currentView.replace('-', ' ')}</span>
        </div>
      </div>

      <div className="flex items-center gap-2.5">

          {isUnlocked && (
            <div className="flex items-center gap-1.5 bg-surface-elevated border border-border rounded-md px-2.5 py-1 text-xs">
              <Building2 className="w-3.5 h-3.5 text-brand-muted" />
              <select
                value={activeOrgId}
                onChange={(e) => setActiveOrgId(e.target.value)}
                className="bg-transparent text-brand-title focus:outline-none cursor-pointer text-xs font-medium"
              >
                {orgsData?.data && orgsData.data.length > 0 ? (
                  orgsData.data.map((org) => (
                    <option key={org.id} value={org.id} className="bg-surface-elevated text-brand-title">
                      {org.name} ({org.id})
                    </option>
                  ))
                ) : (
                  <option value="org_default" className="bg-surface-elevated text-brand-title">
                    org_default
                  </option>
                )}
              </select>
            </div>
          )}

          <button
            type="button"
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            className="w-8 h-8 rounded-lg border border-border bg-surface-base text-brand-muted hover:border-accent-primary hover:bg-accent-soft hover:text-accent-primary flex items-center justify-center transition-colors"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>

          {isUnlocked ? (
            <button
              onClick={() => void logout()}
              className="flex items-center gap-1.5 text-xs text-accent-primary hover:text-status-danger bg-accent-soft hover:bg-status-danger/10 border border-accent-primary/30 hover:border-status-danger/40 px-2.5 py-1 rounded-md transition-colors font-mono"
              title={`Signed in as ${identityLabel} (${operator?.role || 'admin'}). Click to sign out.`}
            >
              {authMode === 'session' ? <ShieldCheck className="w-3.5 h-3.5" /> : <Key className="w-3.5 h-3.5" />}
              <span className="hidden md:inline font-mono text-[11px]">
                {authMode === 'session' ? `${identityLabel} · Sign Out` : 'Break-Glass · Lock'}
              </span>
            </button>
          ) : (
            <span className="flex items-center gap-1.5 text-xs status-warning border px-2.5 py-1 rounded-md font-mono">
              <Lock className="w-3.5 h-3.5" />
              <span>Locked</span>
            </span>
          )}
        </div>
      </header>
  );
};
