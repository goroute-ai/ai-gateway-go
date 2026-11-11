import React, { useState } from 'react';
import { Lock, Unlock, ShieldAlert, Zap, Building2, KeyRound } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { Modal } from '../common/Modal';
import { useQuery } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';

interface HeaderProps {
  currentView: string;
}

export const Header: React.FC<HeaderProps> = ({ currentView }) => {
  const { adminKey, setAdminKey, isUnlocked, lock, activeOrgId, setActiveOrgId } = useAuth();
  const [showKeyModal, setShowKeyModal] = useState<boolean>(!isUnlocked);
  const [tempKey, setTempKey] = useState<string>('');

  // Fetch organizations if unlocked
  const { data: orgsData } = useQuery({
    queryKey: ['admin', 'orgs', adminKey],
    queryFn: () => adminApi.listOrgs(adminKey),
    enabled: isUnlocked,
    staleTime: 60000,
  });

  const handleSaveKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (tempKey.trim()) {
      setAdminKey(tempKey.trim());
      setTempKey('');
      setShowKeyModal(false);
    }
  };

  return (
    <>
      <header className="h-14 border-b border-border-subtle bg-surface-base/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-accent-primary to-accent-secondary flex items-center justify-center shadow-lg shadow-accent-primary/20">
              <Zap className="w-4 h-4 text-black fill-black" />
            </div>
            <span className="font-semibold text-sm tracking-tight text-white flex items-center gap-1.5">
              GoRoute <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20">AI Gateway</span>
            </span>
          </div>

          <div className="h-4 w-[1px] bg-border-strong hidden sm:block" />

          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="capitalize text-slate-200 font-medium">{currentView.replace('-', ' ')}</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Org Selector */}
          {isUnlocked && (
            <div className="flex items-center gap-1.5 bg-surface-elevated/70 border border-border-subtle rounded-md px-2.5 py-1 text-xs">
              <Building2 className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={activeOrgId}
                onChange={(e) => setActiveOrgId(e.target.value)}
                className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
              >
                {orgsData?.data && orgsData.data.length > 0 ? (
                  orgsData.data.map((org) => (
                    <option key={org.id} value={org.id} className="bg-surface-elevated text-slate-200">
                      {org.name} ({org.id})
                    </option>
                  ))
                ) : (
                  <option value="org_default" className="bg-surface-elevated text-slate-200">
                    org_default
                  </option>
                )}
              </select>
            </div>
          )}

          {/* Master Admin Key Session Lock/Unlock Button */}
          {isUnlocked ? (
            <button
              onClick={lock}
              className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-rose-400 bg-emerald-950/40 hover:bg-rose-950/30 border border-emerald-500/30 hover:border-rose-500/30 px-2.5 py-1 rounded-md transition-colors"
              title="Master Admin Key is held in browser memory only. Click to lock session immediately."
            >
              <Unlock className="w-3.5 h-3.5" />
              <span className="hidden md:inline font-mono text-[11px]">Session Unlocked</span>
            </button>
          ) : (
            <button
              onClick={() => setShowKeyModal(true)}
              className="flex items-center gap-1.5 text-xs text-amber-400 bg-amber-950/40 border border-amber-500/30 px-2.5 py-1 rounded-md hover:bg-amber-900/30 transition-colors animate-pulse"
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
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Master Admin Key
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="password"
                value={tempKey}
                onChange={(e) => setTempKey(e.target.value)}
                placeholder="Enter GATEWAY_MASTER_ADMIN_KEY"
                className="w-full bg-black/60 border border-border-strong rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
                autoFocus
              />
            </div>
            <p className="text-[11px] text-slate-500 mt-2 flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-500 shrink-0" />
              Key is discarded immediately when you close the tab or refresh.
            </p>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowKeyModal(false)}
              className="px-3 py-1.5 rounded-md text-xs text-slate-400 hover:text-slate-200 hover:bg-surface-elevated transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!tempKey.trim()}
              className="px-4 py-1.5 rounded-md text-xs font-medium bg-accent-primary hover:bg-accent-glow text-black transition-colors disabled:opacity-50"
            >
              Unlock Dashboard
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
};
