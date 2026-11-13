import React, { createContext, useContext, useState, ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';

interface AuthContextType {
  adminKey: string;
  setAdminKey: (key: string) => void;
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
