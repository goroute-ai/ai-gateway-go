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
    className="flex items-start gap-2.5 p-3.5 rounded-lg border text-xs status-warning"
  >
    <AlertTriangle className="w-4 h-4 text-status-warning shrink-0 mt-0.5" />
    <div>
      <p className="font-semibold text-status-warning">Platform Admin Only — Scoped Operator View</p>
      <p className="opacity-85 text-[11px] mt-0.5">
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
      className="flex items-start justify-between gap-3 p-3.5 rounded-lg border text-xs status-danger"
    >
      <div className="flex items-start gap-2.5 min-w-0">
        <AlertTriangle className="w-4 h-4 text-status-danger shrink-0 mt-0.5" />
        <div className="min-w-0">
          <p className="font-semibold text-status-danger">{title}</p>
          <p className="opacity-85 font-mono text-[11px] mt-0.5 break-words">{message}</p>
        </div>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="shrink-0 flex items-center gap-1 px-2.5 py-1 rounded border status-danger hover:opacity-85 font-mono text-[11px] transition-opacity"
        >
          <RefreshCw className="w-3 h-3" />
          Retry
        </button>
      )}
    </div>
  );
};
