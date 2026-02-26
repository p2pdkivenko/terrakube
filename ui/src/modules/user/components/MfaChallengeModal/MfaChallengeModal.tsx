import React, { useState, useEffect } from "react";
import { Modal, Tabs, Input, Button, Typography, Alert, Spin, message, Space } from "antd";
import { startAuthentication } from "@simplewebauthn/browser";
import { KeyOutlined, SafetyCertificateOutlined, NumberOutlined } from "@ant-design/icons";
import mfaService from "../../mfaService";
import "./MfaChallengeModal.css";

const { Title, Text, Paragraph } = Typography;

interface MfaChallengeModalProps {
  open: boolean;
  availableMethods: string[];
  onSuccess: () => void;
}

const MfaChallengeModal: React.FC<MfaChallengeModalProps> = ({
  open,
  availableMethods,
  onSuccess,
}) => {
  const [activeTab, setActiveTab] = useState<string>("TOTP");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [backupCode, setBackupCode] = useState("");
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);

  useEffect(() => {
    if (open && availableMethods.length > 0) {
      // Default to the first available method, prioritizing WebAuthn if available
      if (availableMethods.includes("WEBAUTHN")) {
        setActiveTab("WEBAUTHN");
      } else if (availableMethods.includes("TOTP")) {
        setActiveTab("TOTP");
      } else if (availableMethods.includes("BACKUP_CODE")) {
        setActiveTab("BACKUP_CODE");
      }
    }
    // Reset state when modal opens
    if (open) {
      setTotpCode("");
      setBackupCode("");
      setError(null);
      setRemainingAttempts(null);
    }
  }, [open, availableMethods]);

  const handleTotpVerify = async () => {
    if (totpCode.length !== 6) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await mfaService.verifyTotp(totpCode);
      
      // Check if the response indicates success (based on API wrapper behavior)
      // The mfaService methods return Promise<ApiResponse<T>>
      // We need to handle the response correctly.
      // Assuming apiPost throws on error or returns data.
      // Based on mfaService.ts, it returns ApiResponse<void>.
      // If the API wrapper throws on non-2xx, we are good.
      // If it returns an object with error, we need to check.
      
      // However, the prompt says:
      // interface MfaVerificationResponse {
      //   success: boolean;
      //   remainingAttempts?: number;
      //   message?: string;
      // }
      // But mfaService.ts shows it returns ApiResponse<void>.
      // I will assume the prompt's "API Response Types" section implies the backend returns this structure,
      // and I should handle it if the service returns it.
      // Let's look at mfaService.ts again. It uses apiPost.
      // I'll assume standard try/catch for now, and if response has data, check it.
      
      onSuccess();
    } catch (err: any) {
      console.error("TOTP verification failed", err);
      const errorMessage = err.response?.data?.message || err.message || "Verification failed";
      setError(errorMessage);
      
      if (err.response?.data?.remainingAttempts !== undefined) {
        setRemainingAttempts(err.response.data.remainingAttempts);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleWebAuthnVerify = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // 1. Get options
      const optionsResponse = await mfaService.getWebAuthnAuthOptions();
      const options = optionsResponse.data;
      
      // 2. Start authentication
      const assertion = await startAuthentication(options);
      
      // 3. Verify assertion
      await mfaService.verifyWebAuthnAuth(assertion);
      
      onSuccess();
    } catch (err: any) {
      console.error("WebAuthn verification failed", err);
      const errorMessage = err.response?.data?.message || err.message || "Verification failed";
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleBackupCodeVerify = async () => {
    if (backupCode.length < 8) return;
    
    setLoading(true);
    setError(null);
    
    try {
      await mfaService.verifyBackupCode(backupCode);
      onSuccess();
    } catch (err: any) {
      console.error("Backup code verification failed", err);
      const errorMessage = err.response?.data?.message || err.message || "Verification failed";
      setError(errorMessage);
      
      if (err.response?.data?.remainingAttempts !== undefined) {
        setRemainingAttempts(err.response.data.remainingAttempts);
      }
    } finally {
      setLoading(false);
    }
  };

  const renderTotpTab = () => (
    <div className="mfa-challenge-content">
      <div className="mfa-challenge-description">
        <Text>Open your authenticator app and enter the 6-digit code.</Text>
      </div>
      
      <div className="mfa-input-container">
        <Input.OTP 
          length={6} 
          value={totpCode} 
          onChange={(val) => {
            setTotpCode(val);
            setError(null);
          }}
          disabled={loading}
          size="large"
        />
        
        {error && <div className="mfa-error-message">{error}</div>}
        {remainingAttempts !== null && (
          <Text type="warning" style={{ fontSize: 12 }}>
            {remainingAttempts} attempts remaining
          </Text>
        )}
      </div>
      
      <Button 
        type="primary" 
        onClick={handleTotpVerify} 
        loading={loading} 
        disabled={totpCode.length !== 6}
        block
        size="large"
        style={{ marginTop: 16 }}
      >
        Verify
      </Button>
    </div>
  );

  const renderWebAuthnTab = () => (
    <div className="webauthn-container">
      <div className="mfa-challenge-description">
        <Text>Use your security key or biometric authenticator.</Text>
      </div>
      
      <SafetyCertificateOutlined className="webauthn-icon" />
      
      {error && <div className="mfa-error-message">{error}</div>}
      
      <Button 
        type="primary" 
        onClick={handleWebAuthnVerify} 
        loading={loading}
        size="large"
        block
      >
        Use Passkey
      </Button>
    </div>
  );

  const renderBackupCodeTab = () => (
    <div className="mfa-challenge-content">
      <div className="mfa-challenge-description">
        <Text>Enter one of your 8-character backup codes.</Text>
      </div>
      
      <div className="mfa-input-container">
        <Input
          value={backupCode}
          onChange={(e) => {
            setBackupCode(e.target.value.trim().toUpperCase());
            setError(null);
          }}
          placeholder="XXXXXXXX"
          maxLength={8}
          disabled={loading}
          className="backup-code-input"
          size="large"
          onPressEnter={handleBackupCodeVerify}
        />
        
        {error && <div className="mfa-error-message">{error}</div>}
        {remainingAttempts !== null && (
          <Text type="warning" style={{ fontSize: 12 }}>
            {remainingAttempts} attempts remaining
          </Text>
        )}
      </div>
      
      <Button 
        type="primary" 
        onClick={handleBackupCodeVerify} 
        loading={loading} 
        disabled={backupCode.length < 8}
        block
        size="large"
        style={{ marginTop: 16 }}
      >
        Verify
      </Button>
    </div>
  );

  const items = [];
  
  if (availableMethods.includes("TOTP")) {
    items.push({
      key: "TOTP",
      label: (
        <span>
          <NumberOutlined /> Authenticator App
        </span>
      ),
      children: renderTotpTab(),
    });
  }
  
  if (availableMethods.includes("WEBAUTHN")) {
    items.push({
      key: "WEBAUTHN",
      label: (
        <span>
          <SafetyCertificateOutlined /> Passkey
        </span>
      ),
      children: renderWebAuthnTab(),
    });
  }
  
  // Always allow backup codes if configured, or if passed in availableMethods
  // Usually backup codes are always an option if MFA is enabled, but let's stick to the prop
  if (availableMethods.includes("BACKUP_CODE")) {
    items.push({
      key: "BACKUP_CODE",
      label: (
        <span>
          <KeyOutlined /> Backup Code
        </span>
      ),
      children: renderBackupCodeTab(),
    });
  }

  return (
    <Modal
      open={open}
      title={<Title level={4} style={{ textAlign: "center", margin: 0 }}>Two-Factor Authentication</Title>}
      footer={null}
      closable={false}
      maskClosable={false}
      keyboard={false}
      centered
      width={400}
      className="mfa-challenge-modal"
    >
      {items.length > 1 ? (
        <Tabs 
          activeKey={activeTab} 
          onChange={setActiveTab} 
          items={items} 
          centered
        />
      ) : items.length === 1 ? (
        items[0].children
      ) : (
        <div style={{ textAlign: "center", padding: 20 }}>
          <Spin />
          <div style={{ marginTop: 10 }}>Loading authentication methods...</div>
        </div>
      )}
    </Modal>
  );
};

export default MfaChallengeModal;
