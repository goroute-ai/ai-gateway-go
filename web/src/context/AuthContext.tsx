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
  loginWithPassword: (identifier: string, password: string) => Promise<void>;
  updatePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  authMode: AuthMode;
  operator: OperatorContext | null;
  currentUser: User | null;
  csrfToken: string | null;
  passwordResetRequired: boolean;
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
  const [passwordResetRequired, setPasswordResetRequired] = useState<boolean>(false);
  const [deprecatedKeyRevokeAt, setDeprecatedKeyRevokeAt] = useState<string | null>(null);
  const [isBootstrapping, setIsBootstrapping] = useState<boolean>(true);
  const [activeOrgId, setActiveOrgId] = useState<string>('org_default');
  const [capturedVirtualKey, setCapturedVirtualKey] = useState<string | null>(null);

  const isUnlocked = authMode === 'session' || adminKey.trim().length > 0;

  const syncCsrf = useCallback((token: string | null) => {
    setCsrfTokenState(token);
    setCsrfToken(token);
  }, []);

  const syncOrgSelection = useCallback(async (key: string, preferredOrgId?: string) => {
    try {
      const orgs = await adminApi.listOrgs(key);
      if (orgs?.data && orgs.data.length > 0) {
        if (preferredOrgId && orgs.data.some((o) => o.id === preferredOrgId)) {
          setActiveOrgId(preferredOrgId);
        } else if (!orgs.data.some((o) => o.id === activeOrgId)) {
          setActiveOrgId(orgs.data[0].id);
        }
      } else if (preferredOrgId) {
        setActiveOrgId(preferredOrgId);
      }
    } catch {
      if (preferredOrgId) setActiveOrgId(preferredOrgId);
    }
  }, [activeOrgId]);

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
        setPasswordResetRequired(!!me.password_reset_required);
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

  const loginWithPassword = async (identifier: string, password: string): Promise<void> => {
    const trimmed = identifier.trim();
    if (!trimmed || !password) {
      throw new Error('Email/username and password are required.');
    }
    const res = await authApi.loginPassword({
      email: trimmed,
      username: trimmed,
      password,
    });
    setAdminKey('');
    syncCsrf(res.csrf_token || null);
    setOperator(res.operator);
    setCurrentUser(res.user || null);
    setPasswordResetRequired(!!res.password_reset_required);
    setDeprecatedKeyRevokeAt(res.operator?.deprecated_key_revoke_at || null);
    setAuthMode('session');
    queryClient.clear();
    await syncOrgSelection('', res.operator?.org_id);
  };

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
        setPasswordResetRequired(!!me.password_reset_required);
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
      if (orgs?.data && orgs.data.length > 0) {
        const preferred = meOp?.org_id;
        if (preferred && orgs.data.some((o) => o.id === preferred)) {
          setActiveOrgId(preferred);
        } else if (!orgs.data.some((o) => o.id === activeOrgId)) {
          setActiveOrgId(orgs.data[0].id);
        }
      }
    } catch (err) {
      setAdminKey('');
      setAuthMode('none');
      setOperator(null);
      queryClient.clear();
      throw err;
    }
  };

  const updatePassword = async (currentPassword: string, newPassword: string): Promise<void> => {
    await authApi.updatePassword(
      {
        ...(currentPassword ? { current_password: currentPassword } : {}),
        new_password: newPassword,
      },
      adminKey || undefined
    );
    setPasswordResetRequired(false);
    // Self-service password change revokes sessions on the server; clear local session state
    if (authMode === 'session') {
      syncCsrf(null);
      setAuthMode('none');
      setOperator(null);
      setCurrentUser(null);
      queryClient.clear();
    }
  };

  const lock = async (): Promise<void> => {
    if (authMode === 'session') {
      try {
        await authApi.logout();
      } catch {
        // Always clear local session state even if server session already expired
      }
    }
    setAdminKey('');
    setAuthMode('none');
    setOperator(null);
    setCurrentUser(null);
    syncCsrf(null);
    setPasswordResetRequired(false);
    setDeprecatedKeyRevokeAt(null);
    setCapturedVirtualKey(null);
    queryClient.clear();
  };

  return (
    <AuthContext.Provider
      value={{
        adminKey,
        setAdminKey,
        unlockWithKey,
        loginWithPassword,
        updatePassword,
        authMode,
        operator,
        currentUser,
        csrfToken: csrfTokenState,
        passwordResetRequired,
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
