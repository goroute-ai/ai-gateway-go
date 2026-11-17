import React from 'react';
import { Field, INPUT_CLS, MONO_INPUT_CLS } from './Modal';

export type AllowMode = 'inherit' | 'deny' | 'allowlist';
export type AllowState = { mode: AllowMode; text: string };

export const INHERIT_ALLOW: AllowState = { mode: 'inherit', text: '' };

export const parseCSVList = (s?: string): string[] =>
  (s || '').split(',').map((x) => x.trim()).filter(Boolean);

export const initAllowState = (v?: string[] | null): AllowState =>
  v == null
    ? INHERIT_ALLOW
    : v.length === 0
      ? { mode: 'deny', text: '' }
      : { mode: 'allowlist', text: v.join(', ') };

export const encodeAllowState = (s: AllowState, isEdit: boolean): string[] | null | undefined =>
  s.mode === 'inherit' ? (isEdit ? null : undefined) : s.mode === 'deny' ? [] : parseCSVList(s.text);

export const Allowlist3StateField: React.FC<{
  label: string;
  state: AllowState;
  onChange: (next: AllowState) => void;
  placeholder: string;
}> = ({ label, state, onChange, placeholder }) => (
  <Field label={label}>
    <div className="flex gap-2">
      <select
        value={state.mode}
        onChange={(e) => onChange({ ...state, mode: e.target.value as AllowMode })}
        className={`${INPUT_CLS} w-36 shrink-0`}
      >
        <option value="inherit">Inherit</option>
        <option value="deny">Deny All</option>
        <option value="allowlist">Allowlist</option>
      </select>
      {state.mode === 'allowlist' && (
        <input
          type="text"
          value={state.text}
          onChange={(e) => onChange({ ...state, text: e.target.value })}
          placeholder={placeholder}
          className={MONO_INPUT_CLS}
        />
      )}
    </div>
  </Field>
);
