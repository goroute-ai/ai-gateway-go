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
    let colorStyle = 'bg-surface-elevated text-brand-body border-border-subtle';

    if (prov.includes('openai')) colorStyle = 'status-success';
    else if (prov.includes('anthropic')) colorStyle = 'status-warning';
    else if (prov.includes('openrouter')) colorStyle = 'status-info';
    else if (prov.includes('groq')) colorStyle = 'status-danger';
    else if (prov.includes('ollama')) colorStyle = 'bg-accent-soft text-accent-primary border-accent-primary/30';
    else if (prov.includes('gemini')) colorStyle = 'bg-accent-soft text-accent-primary border-accent-primary/30';

    return (
      <span className={`inline-flex items-center rounded-md border font-mono ${sizeClasses} ${colorStyle}`}>
        {children}
      </span>
    );
  }

  const variantStyles = {
    default: 'bg-surface-elevated text-brand-body border-border',
    neutral: 'bg-surface-elevated text-brand-muted border-border',
    primary: 'bg-accent-soft text-accent-primary border-accent-primary/30 font-semibold',
    success: 'status-success',
    warning: 'status-warning',
    danger: 'status-danger',
    info: 'bg-accent-soft text-accent-glow border-accent-primary/30',
    provider: 'bg-surface-elevated text-brand-body border-border',
  };

  return (
    <span className={`inline-flex items-center rounded-md border ${sizeClasses} ${variantStyles[variant]}`}>
      {children}
    </span>
  );
};
