import React, { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ConfigProvider, Typography, Tabs, Input, Button, Card, Spin, theme } from "antd";
import { startAuthentication } from "@simplewebauthn/browser";
import { KeyOutlined, SafetyCertificateOutlined, NumberOutlined, LockOutlined } from "@ant-design/icons";
import {
  ColorSchemeOption,
  ThemeMode,
  defaultColorScheme,
  defaultThemeMode,
  getThemeConfig,
} from "../../config/themeConfig";
import mfaService from "./mfaService";
import logo from "../../domain/Login/logo.svg";
import "./MfaPage.css";

const { Title, Text } = Typography;

const MfaPage: React.FC = () => {
  const savedScheme = (localStorage.getItem("terrakube-color-scheme") as ColorSchemeOption) || defaultColorScheme;
  const savedThemeMode = (localStorage.getItem("terrakube-theme-mode") as ThemeMode) || defaultThemeMode;

  return (
    <ConfigProvider theme={getThemeConfig(savedScheme, savedThemeMode)}>
      <MfaPageContent />
    </ConfigProvider>
  );
};

const MfaPageContent: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { token: themeToken } = theme.useToken();

  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [availableMethods, setAvailableMethods] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<string>("TOTP");
  const [error, setError] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [backupCode, setBackupCode] = useState("");
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);

  const returnTo = searchParams.get("returnTo") || "/";

  // Fetch available MFA methods on mount
  useEffect(() => {
    const fetchMethods = async () => {
      try {
        const response = await mfaService.getMfaMethods();
        const methods = response.data?.methods || [];
        setAvailableMethods(methods);

        // Default to first available method, prioritizing WebAuthn
        if (methods.includes("WEBAUTHN")) {
          setActiveTab("WEBAUTHN");
        } else if (methods.includes("TOTP")) {
          setActiveTab("TOTP");
        } else if (methods.includes("BACKUP_CODE")) {
          setActiveTab("BACKUP_CODE");
        }
      } catch (err) {
        console.error("Failed to fetch MFA methods", err);
        // Fallback to TOTP
        setAvailableMethods(["TOTP"]);
      } finally {
        setLoading(false);
      }
    };
    fetchMethods();
  }, []);

  const handleSuccess = () => {
    // Redirect to original destination
    navigate(returnTo, { replace: true });
  };

  const handleTotpVerify = async () => {
    if (totpCode.length !== 6) return;

    setVerifying(true);
    setError(null);

    try {
      await mfaService.verifyTotp(totpCode);
      handleSuccess();
    } catch (err: any) {
      console.error("TOTP verification failed", err);
      const errorMessage = err.response?.data?.message || err.message || "Verification failed";
      setError(errorMessage);
      if (err.response?.data?.remainingAttempts !== undefined) {
        setRemainingAttempts(err.response.data.remainingAttempts);
      }
    } finally {
      setVerifying(false);
    }
  };

  const handleWebAuthnVerify = async () => {
    setVerifying(true);
    setError(null);

    try {
      const optionsResponse = await mfaService.getWebAuthnAuthOptions();
      const options = optionsResponse.data;
      const assertion = await startAuthentication(options);
      await mfaService.verifyWebAuthnAuth(assertion);
      handleSuccess();
    } catch (err: any) {
      console.error("WebAuthn verification failed", err);
      const errorMessage = err.response?.data?.message || err.message || "Verification failed";
      setError(errorMessage);
    } finally {
      setVerifying(false);
    }
  };

  const handleBackupCodeVerify = async () => {
    if (backupCode.length < 8) return;

    setVerifying(true);
    setError(null);

    try {
      await mfaService.verifyBackupCode(backupCode);
      handleSuccess();
    } catch (err: any) {
      console.error("Backup code verification failed", err);
      const errorMessage = err.response?.data?.message || err.message || "Verification failed";
      setError(errorMessage);
      if (err.response?.data?.remainingAttempts !== undefined) {
        setRemainingAttempts(err.response.data.remainingAttempts);
      }
    } finally {
      setVerifying(false);
    }
  };

  const renderTotpTab = () => (
    <form className="mfa-tab-content" onSubmit={(e) => { e.preventDefault(); handleTotpVerify(); }}>
      <Text type="secondary" className="mfa-description">
        Open your authenticator app and enter the 6-digit code.
      </Text>

      <div className="mfa-input-section">
        <Input
          id="totp-code"
          name="totp-code"
          autoComplete="one-time-code"
          inputMode="numeric"
          pattern="[0-9]*"
          value={totpCode}
          onChange={(e) => {
            const val = e.target.value.replace(/\D/g, "").slice(0, 6);
            setTotpCode(val);
            setError(null);
          }}
          placeholder="000000"
          maxLength={6}
          disabled={verifying}
          size="large"
          autoFocus
          className="totp-code-input"
        />

        {error && <div className="mfa-error">{error}</div>}
        {remainingAttempts !== null && (
          <Text type="warning" className="mfa-attempts">
            {remainingAttempts} attempts remaining
          </Text>
        )}
      </div>

      <Button
        type="primary"
        htmlType="submit"
        loading={verifying}
        disabled={totpCode.length !== 6}
        block
        size="large"
      >
        Verify
      </Button>
    </form>
  );

  const renderWebAuthnTab = () => (
    <div className="mfa-tab-content">
      <Text type="secondary" className="mfa-description">
        Use your security key or biometric authenticator.
      </Text>

      <div className="mfa-webauthn-icon">
        <SafetyCertificateOutlined />
      </div>

      {error && <div className="mfa-error">{error}</div>}

      <Button
        type="primary"
        onClick={handleWebAuthnVerify}
        loading={verifying}
        block
        size="large"
      >
        Use Passkey
      </Button>
    </div>
  );

  const renderBackupCodeTab = () => (
    <form className="mfa-tab-content" onSubmit={(e) => { e.preventDefault(); handleBackupCodeVerify(); }}>
      <Text type="secondary" className="mfa-description">
        Enter one of your 8-character backup codes.
      </Text>

      <div className="mfa-input-section">
        <Input
          id="backup-code"
          name="backup-code"
          autoComplete="off"
          value={backupCode}
          onChange={(e) => {
            setBackupCode(e.target.value.trim().toUpperCase());
            setError(null);
          }}
          placeholder="XXXXXXXX"
          maxLength={8}
          disabled={verifying}
          className="mfa-backup-input"
          size="large"
          autoFocus
        />

        {error && <div className="mfa-error">{error}</div>}
        {remainingAttempts !== null && (
          <Text type="warning" className="mfa-attempts">
            {remainingAttempts} attempts remaining
          </Text>
        )}
      </div>

      <Button
        type="primary"
        htmlType="submit"
        loading={verifying}
        disabled={backupCode.length < 8}
        block
        size="large"
      >
        Verify
      </Button>
    </form>
  );

  const tabItems = [];
  if (availableMethods.includes("TOTP")) {
    tabItems.push({
      key: "TOTP",
      label: (
        <span>
          <NumberOutlined /> Authenticator
        </span>
      ),
      children: renderTotpTab(),
    });
  }
  if (availableMethods.includes("WEBAUTHN")) {
    tabItems.push({
      key: "WEBAUTHN",
      label: (
        <span>
          <SafetyCertificateOutlined /> Passkey
        </span>
      ),
      children: renderWebAuthnTab(),
    });
  }
  if (availableMethods.includes("BACKUP_CODE")) {
    tabItems.push({
      key: "BACKUP_CODE",
      label: (
        <span>
          <KeyOutlined /> Backup
        </span>
      ),
      children: renderBackupCodeTab(),
    });
  }

  return (
    <div className="mfa-page-container" style={{ backgroundColor: themeToken.colorBgLayout }}>
      <Card className="mfa-page-card" style={{ backgroundColor: themeToken.colorBgContainer }}>
        <div className="mfa-page-header">
          <img src={logo} alt="Terrakube" className="mfa-page-logo" />
          <div className="mfa-page-icon">
            <LockOutlined />
          </div>
          <Title level={3}>Two-Factor Authentication</Title>
          <Text type="secondary">Verify your identity to continue</Text>
        </div>

        {loading ? (
          <div className="mfa-loading">
            <Spin size="large" />
            <Text type="secondary">Loading authentication methods...</Text>
          </div>
        ) : tabItems.length > 1 ? (
          <Tabs
            activeKey={activeTab}
            onChange={setActiveTab}
            items={tabItems}
            centered
            className="mfa-tabs"
          />
        ) : tabItems.length === 1 ? (
          tabItems[0].children
        ) : (
          <div className="mfa-error">
            No authentication methods available. Please contact your administrator.
          </div>
        )}
      </Card>
    </div>
  );
};

export default MfaPage;
