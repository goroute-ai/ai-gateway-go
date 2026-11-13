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
    <aside className="w-60 border-r border-border bg-surface-base flex flex-col shrink-0 min-h-[calc(100vh-4rem)] select-none">
      <div className="p-3 space-y-1.5 flex-1">
        <div className="px-3 py-2 text-[10px] font-mono font-semibold uppercase tracking-wider text-[#9696a4]">
          Control Plane
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectView(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-[0.55rem] text-xs font-medium transition-all duration-150 ${
                isActive
                  ? 'bg-[rgba(124,58,237,0.09)] text-accent-primary border border-accent-primary/30 font-semibold shadow-[0_2px_12px_rgba(124,58,237,0.1)]'
                  : 'text-[#9696a4] hover:text-[#f5f3ff] hover:bg-surface-elevated/80 border border-transparent hover:border-border'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-accent-primary' : 'text-[#9696a4]'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[9px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                    isActive
                      ? 'bg-accent-primary/20 text-accent-primary border-accent-primary/30 font-bold'
                      : 'bg-surface-elevated text-[#9696a4] border-border'
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
      <div className="p-3 border-t border-border text-[11px] text-[#9696a4] flex items-center justify-between font-mono">
        <span className="text-[10px]">GoRoute v1.5.0</span>
        <span className="flex items-center gap-1.5 text-[10px] text-accent-primary">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-primary animate-pulse" />
          Pure Go
        </span>
      </div>
    </aside>
  );
};
