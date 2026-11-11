import React from 'react';
import {
  Activity,
  MessageSquare,
  Key,
  ShieldCheck,
  Boxes,
  Coins,
  Shield,
  Bot,
} from 'lucide-react';

export type NavView =
  | 'overview'
  | 'playground'
  | 'keys'
  | 'credentials'
  | 'models'
  | 'finops'
  | 'guardrails'
  | 'agentic';

interface SidebarProps {
  activeView: NavView;
  onSelectView: (view: NavView) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeView, onSelectView }) => {
  const navItems = [
    { id: 'overview' as NavView, label: 'Overview', icon: Activity, badge: 'Live' },
    { id: 'playground' as NavView, label: 'Playground', icon: MessageSquare, badge: 'SSE' },
    { id: 'keys' as NavView, label: 'Virtual Keys', icon: Key },
    { id: 'credentials' as NavView, label: 'Credentials Vault', icon: ShieldCheck },
    { id: 'models' as NavView, label: 'Models & Routing', icon: Boxes },
    { id: 'finops' as NavView, label: 'FinOps & Spend', icon: Coins },
    { id: 'guardrails' as NavView, label: 'Guardrails', icon: Shield },
    { id: 'agentic' as NavView, label: 'Agentic Hub', icon: Bot, badge: 'MCP/A2A' },
  ];

  return (
    <aside className="w-56 border-r border-border-subtle bg-surface-base/90 flex flex-col shrink-0 min-h-[calc(100vh-3.5rem)] select-none">
      <div className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
          Control Plane
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectView(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 ${
                isActive
                  ? 'bg-accent-primary/10 text-accent-glow border border-accent-primary/20 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-surface-elevated/50 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-accent-primary' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[9px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                    isActive
                      ? 'bg-accent-primary/20 text-accent-glow border-accent-primary/30'
                      : 'bg-surface-elevated text-slate-400 border-border-subtle'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Footer Info */}
      <div className="p-3 border-t border-border-subtle/60 text-[11px] text-slate-500 flex items-center justify-between">
        <span className="font-mono text-[10px]">GoRoute v1.3.0</span>
        <span className="flex items-center gap-1 text-[10px] text-emerald-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          Pure Go
        </span>
      </div>
    </aside>
  );
};
