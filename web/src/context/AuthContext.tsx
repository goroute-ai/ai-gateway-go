import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { adminApi, authApi } from '../api/admin';
import { setCsrfToken, setDeprecatedKeyHandler } from '../api/client';
import type { OperatorContext, User } from '../types';

export type AuthMode = 'none' | 'session' | 'master_key';

interface AuthContextType {
  adminKey: string;
  setAdminKey: (key: string) => void;
  unlockWithKey: (key: string) => Promise<void>;
  authMode: AuthMode;
  operator: OperatorContext | null;
  currentUser: User | null;
  csrfToken: string | null;
  deprecatedKeyRevokeAt: string | null;
  isBootstrapping: boolean;
  isUnlocked: boolean;
  lock: () => Promise<void>;
  logout: () => Promise<void>;
  activeOrgId: string;
  setActiveOrgId: (orgId: string) => void;
  capturedVirtualKey: string | null;
  setCapturedVirtualKey: (key: string | null) => void;
  lastIssuedKey: string | null;
  setLastIssuedKey: (key: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const queryClient = useQueryClient();
  const [adminKey, setAdminKey] = useState<string>('');
  const [authMode, setAuthMode] = useState<AuthMode>('none');
  const [operator, setOperator] = useState<OperatorContext | null>(null);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [csrfTokenState, setCsrfTokenState] = useState<string | null>(null);
  const [deprecatedKeyRevokeAt, setDeprecatedKeyRevokeAt] = useState<string | null>(null);
  const [isBootstrapping, setIsBootstrapping] = useState<boolean>(true);
  const [activeOrgId, setActiveOrgId] = useState<string>('org_default');
  const [capturedVirtualKey, setCapturedVirtualKey] = useState<string | null>(null);

  const isUnlocked = authMode === 'session' || adminKey.trim().length > 0;

  const syncCsrf = useCallback((token: string | null) => {
    setCsrfTokenState(token);
    setCsrfToken(token);
  }, []);

  const applyOrgs = useCallback((list?: Array<{ id: string }>, preferred?: string) => {
    if (list && list.length > 0) {
      if (preferred && list.some((o) => o.id === preferred)) setActiveOrgId(preferred);
      else if (!list.some((o) => o.id === activeOrgId)) setActiveOrgId(list[0].id);
    } else if (preferred) {
      setActiveOrgId(preferred);
    }
  }, [activeOrgId]);

  const syncOrgSelection = useCallback(async (key: string, preferredOrgId?: string) => {
    try {
      const orgs = await adminApi.listOrgs(key);
      applyOrgs(orgs?.data, preferredOrgId);
    } catch {
      if (preferredOrgId) setActiveOrgId(preferredOrgId);
    }
  }, [applyOrgs]);

  useEffect(() => {
    setDeprecatedKeyHandler((revokeAt) => {
      setDeprecatedKeyRevokeAt((prev) => revokeAt || prev || 'scheduled');
    });
    return () => setDeprecatedKeyHandler(null);
  }, []);

  // Bootstrap existing Control Plane cookie session via GET /auth/me on mount
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const me = await authApi.getMe();
        if (!active) return;
        const csrf = me.csrf_token || me.operator?.csrf_token || null;
        syncCsrf(csrf);
        setOperator(me.operator);
        setCurrentUser(me.user || null);
        setDeprecatedKeyRevokeAt(me.operator?.deprecated_key_revoke_at || null);
        setAuthMode(me.operator?.auth_method === 'session' ? 'session' : 'master_key');
        await syncOrgSelection('', me.operator?.org_id);
      } catch {
        if (!active) return;
        syncCsrf(null);
        setAuthMode('none');
      } finally {
        if (active) setIsBootstrapping(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [syncCsrf]);

  const unlockWithKey = async (rawKey: string): Promise<void> => {
    const trimmed = rawKey.trim();
    if (!trimmed) {
      setAdminKey('');
      throw new Error('Master Admin Key is required.');
    }
    try {
      const orgs = await adminApi.listOrgs(trimmed);
      let meOp: OperatorContext | null = null;
      try {
        const me = await authApi.getMe(trimmed);
        meOp = me.operator || null;
        setCurrentUser(me.user || null);
        if (me.operator?.deprecated_key_revoke_at) {
          setDeprecatedKeyRevokeAt(me.operator.deprecated_key_revoke_at);
        }
      } catch {
        setCurrentUser(null);
      }
      syncCsrf(null);
      setAdminKey(trimmed);
      setOperator(
        meOp || {
          actor_id: 'master_admin',
          role: 'platform_admin',
          auth_method: 'master_key',
        }
      );
      setAuthMode('master_key');
      queryClient.clear();
      applyOrgs(orgs?.data, meOp?.org_id);
    } catch (err) {
      setAdminKey('');
      setAuthMode('none');
      setOperator(null);
      queryClient.clear();
      throw err;
    }
  };

  const lock = async (): Promise<void> => {
    let endSessionURL: string | undefined;
    if (authMode === 'session') {
      try {
        const res = await authApi.logout();
        endSessionURL = res?.end_session_url;
      } catch {
        // Always clear local session state even if server session already expired
      }
    }
    setAdminKey('');
    setAuthMode('none');
    setOperator(null);
    setCurrentUser(null);
    syncCsrf(null);
    setDeprecatedKeyRevokeAt(null);
    setCapturedVirtualKey(null);
    queryClient.clear();
    if (endSessionURL) {
      window.location.assign(endSessionURL);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        adminKey,
        setAdminKey,
        unlockWithKey,
        authMode,
        operator,
        currentUser,
        csrfToken: csrfTokenState,
        deprecatedKeyRevokeAt,
        isBootstrapping,
        isUnlocked,
        lock,
        logout: lock,
        activeOrgId,
        setActiveOrgId,
        capturedVirtualKey,
        setCapturedVirtualKey,
        lastIssuedKey: capturedVirtualKey,
        setLastIssuedKey: setCapturedVirtualKey,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
