import React, { createContext, useContext, useState, ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';

interface AuthContextType {
  adminKey: string;
  setAdminKey: (key: string) => void;
  unlockWithKey: (key: string) => Promise<void>;
  isUnlocked: boolean;
  lock: () => void;
  activeOrgId: string;
  setActiveOrgId: (orgId: string) => void;
  // Captured virtual key in memory (e.g. issued in current session)
  capturedVirtualKey: string | null;
  setCapturedVirtualKey: (key: string | null) => void;
  lastIssuedKey: string | null;
  setLastIssuedKey: (key: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const queryClient = useQueryClient();
  const [adminKey, setAdminKey] = useState<string>('');
  const [activeOrgId, setActiveOrgId] = useState<string>('org_default');
  const [capturedVirtualKey, setCapturedVirtualKey] = useState<string | null>(null);

  const isUnlocked = adminKey.trim().length > 0;

  const unlockWithKey = async (rawKey: string): Promise<void> => {
    const trimmed = rawKey.trim();
    if (!trimmed) {
      setAdminKey('');
      throw new Error('Master Admin Key is required.');
    }
    try {
      const orgs = await adminApi.listOrgs(trimmed);
      setAdminKey(trimmed);
      if (orgs?.data && orgs.data.length > 0) {
        const hasCurrent = orgs.data.some((o) => o.id === activeOrgId);
        if (!hasCurrent) {
          setActiveOrgId(orgs.data[0].id);
        }
      }
    } catch (err) {
      setAdminKey('');
      queryClient.clear();
      throw err;
    }
  };

  const lock = () => {
    setAdminKey('');
    setCapturedVirtualKey(null);
    queryClient.clear();
  };

  return (
    <AuthContext.Provider
      value={{
        adminKey,
        setAdminKey,
        unlockWithKey,
        isUnlocked,
        lock,
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
