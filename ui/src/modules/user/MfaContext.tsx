import React, { createContext, useContext, useState, useCallback, useEffect } from "react";
import MfaChallengeModal from "./components/MfaChallengeModal/MfaChallengeModal";
import axios from "axios";

interface MfaContextType {
  isMfaRequired: boolean;
  triggerMfaChallenge: (methods?: string[]) => void;
  completeMfaChallenge: () => void;
}

const MfaContext = createContext<MfaContextType | undefined>(undefined);

export const useMfa = () => {
  const context = useContext(MfaContext);
  if (!context) {
    throw new Error("useMfa must be used within an MfaProvider");
  }
  return context;
};

interface MfaProviderProps {
  children: React.ReactNode;
}

export const MfaProvider: React.FC<MfaProviderProps> = ({ children }) => {
  const [isMfaRequired, setIsMfaRequired] = useState(false);
  const [availableMethods, setAvailableMethods] = useState<string[]>([]);

  const triggerMfaChallenge = useCallback((methods: string[] = ["totp"]) => {
    setAvailableMethods(methods);
    setIsMfaRequired(true);
  }, []);

  const completeMfaChallenge = useCallback(() => {
    setIsMfaRequired(false);
    setAvailableMethods([]);
    window.location.reload();
  }, []);

  const handleCancel = useCallback(() => {
    setIsMfaRequired(false);
    setAvailableMethods([]);
  }, []);

  // Listen for MFA required events from axios interceptor
  useEffect(() => {
    const handleMfaRequired = async () => {
      if (isMfaRequired) return; // Already showing modal
      
      try {
        // Fetch available MFA methods
        const token = sessionStorage.getItem("token");
        const apiUrl = (window as any)._env_?.REACT_APP_TERRAKUBE_API_URL || "";
        // Remove /api/v1 suffix if present, MFA endpoint is at /mfa/v1
        const baseUrl = apiUrl.replace(/\/api\/v1\/?$/, "");
        const response = await axios.get(`${baseUrl}/mfa/v1/methods`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        triggerMfaChallenge(response.data?.methods || ["totp"]);
      } catch {
        // Fallback to TOTP if we can't fetch methods
        triggerMfaChallenge(["totp"]);
      }
    };

    window.addEventListener("mfa-required", handleMfaRequired);
    return () => window.removeEventListener("mfa-required", handleMfaRequired);
  }, [isMfaRequired, triggerMfaChallenge]);

  return (
    <MfaContext.Provider value={{ isMfaRequired, triggerMfaChallenge, completeMfaChallenge }}>
      {children}
      <MfaChallengeModal
        open={isMfaRequired}
        availableMethods={availableMethods}
        onSuccess={completeMfaChallenge}
        onCancel={handleCancel}
      />
    </MfaContext.Provider>
  );
};

export default MfaContext;
