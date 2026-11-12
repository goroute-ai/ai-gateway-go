import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'neutral' | 'primary' | 'success' | 'warning' | 'danger' | 'info' | 'provider';
  provider?: string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  provider,
  size = 'md',
}) => {
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2.5 py-0.5 text-xs font-medium';

  if (variant === 'provider' && provider) {
    const prov = provider.toLowerCase();
    let colorStyle = 'bg-surface-elevated text-slate-300 border-border-subtle';

    if (prov.includes('openai')) colorStyle = 'bg-[#0E3A2F] text-[#10A37F] border-[#10A37F]/30';
    else if (prov.includes('anthropic')) colorStyle = 'bg-[#382312] text-[#D97706] border-[#D97706]/30';
    else if (prov.includes('gemini') || prov.includes('google')) colorStyle = 'bg-[#1E2C4F] text-[#60A5FA] border-[#3B82F6]/30';
    else if (prov.includes('bedrock') || prov.includes('amazon')) colorStyle = 'bg-[#38240D] text-[#F59E0B] border-[#F59E0B]/30';
    else if (prov.includes('vertex')) colorStyle = 'bg-[#1A2F3D] text-[#38BDF8] border-[#0284C7]/30';
    else if (prov.includes('cohere')) colorStyle = 'bg-[#182E25] text-[#34D399] border-[#10B981]/30';
    else if (prov.includes('groq')) colorStyle = 'bg-[#381B15] text-[#FB7185] border-[#F43F5E]/30';
    else if (prov.includes('deepseek')) colorStyle = 'bg-[#1F244D] text-[#818CF8] border-[#6366F1]/30';
    else if (prov.includes('mistral')) colorStyle = 'bg-[#312519] text-[#F97316] border-[#F97316]/30';

    return (
      <span className={`inline-flex items-center rounded-md border font-mono ${sizeClasses} ${colorStyle}`}>
        {children}
      </span>
    );
  }

  const variantStyles = {
    default: 'bg-surface-elevated text-[#d2d0dc] border-border',
    neutral: 'bg-surface-elevated text-[#9696a4] border-border',
    primary: 'bg-[rgba(124,58,237,0.12)] text-accent-primary border-accent-primary/30 font-semibold',
    success: 'bg-emerald-950/60 text-emerald-400 border-emerald-500/30',
    warning: 'bg-amber-950/60 text-amber-400 border-amber-500/30',
    danger: 'bg-rose-950/60 text-rose-400 border-rose-500/30',
    info: 'bg-[rgba(124,58,237,0.12)] text-accent-glow border-accent-primary/30',
    provider: 'bg-surface-elevated text-[#d2d0dc] border-border',
  };

  return (
    <span className={`inline-flex items-center rounded-md border ${sizeClasses} ${variantStyles[variant]}`}>
      {children}
    </span>
  );
};
