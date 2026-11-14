import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorAlertProps {
  error: unknown;
  title?: string;
  onRetry?: () => void;
}

export const isPlatformAdminForbidden = (err: unknown): boolean => {
  const e = err as { status?: number; code?: string; message?: string } | null;
  return (
    e?.status === 403 &&
    (e?.code === 'platform_admin_required' || /platform[ _]admin/i.test(e?.message || ''))
  );
};

export const ScopedRoleNotice: React.FC<{ subject?: string }> = ({ subject = 'this view' }) => (
  <div
    role="status"
    className="flex items-start gap-2.5 p-3.5 rounded-lg bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200"
  >
    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
    <div>
      <p className="font-semibold text-amber-300">Platform Admin Only — Scoped Operator View</p>
      <p className="text-amber-200/80 text-[11px] mt-0.5">
        Your active key is scoped to an organization, so global {subject} is restricted. Use a platform_admin key to inspect cross-tenant resources.
      </p>
    </div>
  </div>
);

export const ErrorAlert: React.FC<ErrorAlertProps> = ({
  error,
  title = 'Failed to load data',
  onRetry,
}) => {
  const message =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : 'An unexpected error occurred while querying the control plane.';

  return (
    <div
      role="alert"
      className="flex items-start justify-between gap-3 p-3.5 rounded-lg bg-rose-950/30 border border-rose-500/30 text-xs text-rose-200"
    >
      <div className="flex items-start gap-2.5 min-w-0">
        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
        <div className="min-w-0">
          <p className="font-semibold text-rose-300">{title}</p>
          <p className="text-rose-200/80 font-mono text-[11px] mt-0.5 break-words">{message}</p>
        </div>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="shrink-0 flex items-center gap-1 px-2.5 py-1 rounded border border-rose-500/30 bg-rose-950/50 hover:bg-rose-900/50 text-rose-200 font-mono text-[11px] transition-colors"
        >
          <RefreshCw className="w-3 h-3" />
          Retry
        </button>
      )}
    </div>
  );
};
