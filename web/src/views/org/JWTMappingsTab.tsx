import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { FormModal, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY } from '../../components/common/Modal';
import { ErrorAlert } from '../../components/common/ErrorAlert';
import { Plus, Trash2 } from 'lucide-react';

const cell = 'px-4 py-2.5';

export const JWTMappingsTab: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ issuer: '', claim_name: 'groups', claim_value: '', virtual_key_id: '' });

  const q = useQuery({
    queryKey: ['admin', 'jwt-mappings', adminKey, activeOrgId],
    queryFn: () => adminApi.listJWTMappings(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });
  const keysQ = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, { org_id: activeOrgId }),
    enabled: isUnlocked && !!activeOrgId,
  });

  const inv = () => qc.invalidateQueries({ queryKey: ['admin', 'jwt-mappings', adminKey] });
  const createMut = useMutation({
    mutationFn: () => adminApi.createJWTMapping(adminKey, { org_id: activeOrgId, ...f }),
    onSuccess: () => { inv(); setOpen(false); },
  });
  const delMut = useMutation({
    mutationFn: (id: string) => adminApi.deleteJWTMapping(adminKey, id),
    onSuccess: inv,
  });

  const mappings = q.data?.data || [];
  const keys = keysQ.data?.data || [];

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <p className="text-xs text-brand-muted">Map verified OIDC/JWT <code className="font-mono">(issuer, claim_name, claim_value)</code> tuples directly to scoped Virtual Keys.</p>
        <button onClick={() => { setF({ issuer: '', claim_name: 'groups', claim_value: '', virtual_key_id: keys[0]?.id || '' }); setOpen(true); }} className={`${BTN_PRIMARY} flex items-center gap-1`}>
          <Plus className="w-3.5 h-3.5" />New JWT Mapping
        </button>
      </div>
      {(q.error || delMut.error) && <ErrorAlert error={q.error || delMut.error} title="JWT Mappings error" />}
      <div className="bg-surface-base border border-border-subtle rounded-xl overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-surface-elevated border-b border-border-subtle text-brand-muted font-mono uppercase text-[10px]">
            <tr>{['Issuer', 'Claim', 'Value', 'Virtual Key ID', 'Actions'].map((h) => <th key={h} className={cell}>{h}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {mappings.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-brand-muted">No JWT key mappings configured for {activeOrgId}.</td></tr>
            ) : mappings.map((m) => (
              <tr key={m.id}>
                <td className={`${cell} font-mono text-brand-title`}>{m.issuer}</td>
                <td className={`${cell} font-mono text-accent-primary`}>{m.claim_name}</td>
                <td className={`${cell} font-mono`}>{m.claim_value}</td>
                <td className={`${cell} font-mono text-brand-muted`}>{m.virtual_key_id}</td>
                <td className={cell}>
                  <button onClick={() => { if (confirm('Delete JWT mapping?')) delMut.mutate(m.id); }} className="p-1 text-brand-muted" title="Delete"><Trash2 className="w-3.5 h-3.5" /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <FormModal open={open} onClose={() => setOpen(false)} title="Create JWT Key Mapping" pending={createMut.isPending} submitLabel="Create" onSubmit={() => createMut.mutate()}>
        {!!createMut.error && <ErrorAlert error={createMut.error} title="Create mapping failed" />}
        <input required value={f.issuer} onChange={(e) => setF({ ...f, issuer: e.target.value })} placeholder="OIDC Issuer URL (e.g. https://idp.example.com/realms/prod) *" className={MONO_INPUT_CLS} />
        <div className="grid grid-cols-2 gap-2">
          <input required value={f.claim_name} onChange={(e) => setF({ ...f, claim_name: e.target.value })} placeholder="Claim Name (e.g. groups, sub) *" className={MONO_INPUT_CLS} />
          <input required value={f.claim_value} onChange={(e) => setF({ ...f, claim_value: e.target.value })} placeholder="Claim Value *" className={MONO_INPUT_CLS} />
        </div>
        <select required value={f.virtual_key_id} onChange={(e) => setF({ ...f, virtual_key_id: e.target.value })} className={INPUT_CLS}>
          <option value="">Target Virtual Key *</option>
          {keys.map((k) => <option key={k.id} value={k.id}>{k.name} ({k.key_prefix})</option>)}
        </select>
      </FormModal>
    </div>
  );
};

export default JWTMappingsTab;
