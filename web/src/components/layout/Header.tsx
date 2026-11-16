import React, { useState } from 'react';
import { Lock, AlertTriangle, Building2, Key, Sun, Moon } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { Modal, INPUT_CLS, BTN_CANCEL } from '../common/Modal';
import { useQuery } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';

interface HeaderProps {
  currentView: string;
}

export const Header: React.FC<HeaderProps> = ({ currentView }) => {
  const { adminKey, unlockWithKey, isUnlocked, lock, activeOrgId, setActiveOrgId } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [showKeyModal, setShowKeyModal] = useState<boolean>(false);
  const [tempKey, setTempKey] = useState<string>('');
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [isUnlocking, setIsUnlocking] = useState<boolean>(false);

  // Fetch organizations if unlocked
  const { data: orgsData } = useQuery({
    queryKey: ['admin', 'orgs', adminKey],
    queryFn: () => adminApi.listOrgs(adminKey),
    enabled: isUnlocked,
    staleTime: 60000,
  });

  const handleSaveKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tempKey.trim() || isUnlocking) return;
    setUnlockError(null);
    setIsUnlocking(true);
    try {
      await unlockWithKey(tempKey);
      setTempKey('');
      setShowKeyModal(false);
    } catch (err: any) {
      setUnlockError(err?.message || 'Invalid Master Admin Key or control plane unreachable.');
    } finally {
      setIsUnlocking(false);
    }
  };

  return (
    <>
      <header className="h-16 border-b border-border bg-canvas/85 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-5">
          <div className="flex items-center gap-3">
            <img
              src="/ui/logo-dark.png"
              alt="GoRoute AI Gateway Logo"
              className="h-8 w-auto object-contain drop-shadow-[0_2px_8px_rgb(var(--rgb-accent-primary)/0.28)]"
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

        <div className="flex items-center gap-3">
          {/* Org Selector */}
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

          {/* Persistent Dark / Light Theme Switcher */}
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            className="w-8 h-8 rounded-lg border border-border bg-surface-base text-brand-muted hover:border-accent-primary hover:bg-accent-soft hover:text-accent-primary flex items-center justify-center transition-colors"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>

          {/* Master Admin Key Session Lock/Unlock Button */}
          {isUnlocked ? (
            <button
              onClick={lock}
              className="flex items-center gap-1.5 text-xs text-accent-primary hover:text-status-danger bg-accent-soft hover:bg-status-danger/10 border border-accent-primary/30 hover:border-status-danger/40 px-2.5 py-1 rounded-md transition-colors font-mono"
              title="Master Admin Key is held in browser memory only. Click to lock session immediately."
            >
              <Key className="w-3.5 h-3.5" />
              <span className="hidden md:inline font-mono text-[11px]">Session Unlocked</span>
            </button>
          ) : (
            <button
              onClick={() => setShowKeyModal(true)}
              className="flex items-center gap-1.5 text-xs status-warning border px-2.5 py-1 rounded-md hover:opacity-90 transition-opacity animate-pulse font-mono"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Unlock Admin Key</span>
            </button>
          )}
        </div>
      </header>

      {/* Admin Key Modal */}
      <Modal
        isOpen={showKeyModal}
        onClose={() => setShowKeyModal(false)}
        title="Authenticate Admin Session"
        description="Provide your Gateway Master Admin Key to access the Control Plane. This key is held strictly in browser memory and is never saved to storage or logs."
        maxWidth="md"
      >
        <form onSubmit={handleSaveKey} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1.5">
              Master Admin Key
            </label>
            <div className="relative">
              <Key className="w-4 h-4 text-brand-muted absolute left-3 top-2.5" />
              <input
                type="password"
                value={tempKey}
                onChange={(e) => setTempKey(e.target.value)}
                placeholder="Enter GATEWAY_MASTER_ADMIN_KEY"
                className={`${INPUT_CLS} pl-9 font-mono`}
                autoFocus
              />
            </div>
            <p className="text-[11px] text-brand-muted mt-2 flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5 text-status-warning shrink-0" />
              Key is discarded immediately when you close the tab or refresh.
            </p>
            {unlockError && (
              <p className="text-[11px] font-mono mt-2 status-danger border rounded px-2.5 py-1.5">
                {unlockError}
              </p>
            )}
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => {
                setUnlockError(null);
                setShowKeyModal(false);
              }}
              className={BTN_CANCEL}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!tempKey.trim() || isUnlocking}
              className="px-4 py-1.5 rounded-md text-xs font-semibold bg-accent-primary hover:bg-accent-dark text-accent-contrast transition-colors disabled:opacity-50"
            >
              {isUnlocking ? 'Verifying...' : 'Unlock Dashboard'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
};
