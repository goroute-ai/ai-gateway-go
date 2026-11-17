import React, { useState, useEffect } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { FormModal, Field, INPUT_CLS, MONO_INPUT_CLS } from './Modal';
import { ErrorAlert } from './ErrorAlert';
import { microsToUsdInput, usdToMicros } from '../../utils/budget';
import type { VirtualKey } from '../../types';

export const TempBudgetModal: React.FC<{
  target: VirtualKey | null;
  onClose: () => void;
}> = ({ target, onClose }) => {
  const { adminKey, activeOrgId } = useAuth();
  const qc = useQueryClient();
  const [usd, setUsd] = useState('');
  const [mode, setMode] = useState<'ttl' | 'date'>('ttl');
  const [ttl, setTtl] = useState('3600');
  const [expiresAt, setExpiresAt] = useState('');

  const mut = useMutation({
    mutationFn: (body: Parameters<typeof adminApi.setKeyTempBudget>[2]) =>
      adminApi.setKeyTempBudget(adminKey, target!.id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
      onClose();
    },
  });

  useEffect(() => {
    if (target) {
      mut.reset();
      setUsd(microsToUsdInput(target.temp_budget_increase_micros));
      setMode('ttl');
      setTtl('3600');
      setExpiresAt('');
    }
  }, [target]);

  const submit = () => {
    if (!target) return;
    const micros = usdToMicros(usd) ?? 0;
    const body: Parameters<typeof adminApi.setKeyTempBudget>[2] = {
      org_id: activeOrgId,
      temp_budget_increase_micros: micros,
    };
    if (micros > 0) {
      if (mode === 'ttl') body.ttl_seconds = Math.max(1, parseInt(ttl, 10) || 3600);
      else if (expiresAt) {
        const d = new Date(expiresAt);
        if (!isNaN(d.getTime())) body.temp_budget_expires_at = d.toISOString();
      }
    }
    mut.mutate(body);
  };

  return (
    <FormModal
      open={!!target}
      onClose={onClose}
      title={`Temp Budget Boost: ${target?.name || ''}`}
      description="Temporarily raise max_budget_micros (0 clears boost)."
      onSubmit={submit}
      pending={mut.isPending}
      submitLabel="Apply Boost"
    >
      {mut.isError && <ErrorAlert error={mut.error} title="Failed to apply temporary budget" />}
      <Field label="Boost Amount (USD, 0 = clear)">
        <input required type="number" step="0.01" min="0" value={usd} onChange={(e) => setUsd(e.target.value)} className={MONO_INPUT_CLS} />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Expiry Mode">
          <select value={mode} onChange={(e) => setMode(e.target.value as 'ttl' | 'date')} className={INPUT_CLS}>
            <option value="ttl">TTL (seconds)</option>
            <option value="date">Exact timestamp</option>
          </select>
        </Field>
        {mode === 'ttl' ? (
          <Field label="TTL (seconds)"><input type="number" min="1" value={ttl} onChange={(e) => setTtl(e.target.value)} className={MONO_INPUT_CLS} /></Field>
        ) : (
          <Field label="Expires At"><input type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className={MONO_INPUT_CLS} /></Field>
        )}
      </div>
    </FormModal>
  );
};
