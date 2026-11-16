import React, { useEffect } from 'react';
import { X } from 'lucide-react';

export const INPUT_CLS =
  'w-full bg-surface-input border border-border-strong rounded-lg px-3 py-2 text-xs text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary';
export const BTN_PRIMARY =
  'px-4 py-1.5 rounded-md text-xs font-semibold bg-accent-primary hover:bg-accent-dark text-accent-contrast transition-colors disabled:opacity-50';
export const BTN_CANCEL =
  'px-3 py-1.5 rounded-md text-xs text-brand-muted hover:text-brand-title hover:bg-surface-elevated transition-colors';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  size?: 'sm' | 'md' | 'lg' | 'xl' | '2xl';
}

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  description,
  children,
  maxWidth,
  size,
}) => {
  const effectiveSize = size || maxWidth || 'md';
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const widthClasses = {
    sm: 'max-w-sm',
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-xl',
    '2xl': 'max-w-2xl',
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-md animate-in fade-in duration-150">
      <div
        className={`w-full ${widthClasses[effectiveSize]} bg-surface-base border border-border rounded-xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-150`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-elevated/60">
          <div>
            <h3 className="text-base font-semibold text-brand-title tracking-tight">{title}</h3>
            {description && <p className="text-xs text-brand-muted mt-0.5 leading-relaxed">{description}</p>}
          </div>
          <button
            onClick={onClose}
            className="text-brand-muted hover:text-brand-title p-1.5 rounded-md hover:bg-surface-elevated transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-6 max-h-[80vh] overflow-y-auto">{children}</div>
      </div>
    </div>
  );
};
