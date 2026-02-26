import { Modal, Flex, Typography, Button, Input, Alert, Space, Switch, message, Steps, Divider } from "antd";
import { useState, useEffect } from "react";
import { QRCodeSVG } from "qrcode.react";
import useApiRequest from "@/modules/api/useApiRequest";
import mfaService, { TotpSetupResponse } from "@/modules/user/mfaService";
import "./TotpSetupModal.css";

const { Text, Title, Paragraph } = Typography;

type Props = {
  visible: boolean;
  onCancel: () => void;
  onSuccess: () => void;
};

export default function TotpSetupModal({ visible, onCancel, onSuccess }: Props) {
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [setupData, setSetupData] = useState<TotpSetupResponse | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [secret, setSecret] = useState<string>("");

  // Setup API call
  const { loading: setupLoading, execute: doSetup, error: setupError } = useApiRequest({
    action: () => mfaService.setupTotp(),
    onReturn: (data) => {
      setSetupData(data);
      // Extract secret from URI if possible
      try {
        const url = new URL(data.secretUri);
        const secretParam = url.searchParams.get("secret");
        if (secretParam) {
          setSecret(secretParam);
        }
      } catch (e) {
        console.error("Failed to parse secret URI", e);
      }
    },
  });

  // Verify API call
  const { loading: verifyLoading, execute: doVerify, error: verifyError } = useApiRequest({
    action: () => mfaService.verifyTotp(code),
    onReturn: () => {
      setCurrentStep(1); // Move to backup codes step
      generateCodes();
    },
  });

  // Generate backup codes
  const { execute: generateCodes, loading: backupLoading } = useApiRequest({
    action: () => mfaService.generateBackupCodes(),
    onReturn: (data) => {
      setBackupCodes(data.codes);
    },
  });

  useEffect(() => {
    if (visible) {
      setCurrentStep(0);
      setCode("");
      setShowSecret(false);
      doSetup();
    }
  }, [visible]);

  const handleVerify = () => {
    if (code.length === 6) {
      doVerify();
    }
  };

  const handleCopySecret = () => {
    navigator.clipboard.writeText(secret);
    message.success("Secret copied to clipboard");
  };

  const handleCopyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join("\n"));
    message.success("Backup codes copied to clipboard");
  };

  const handleDownloadBackupCodes = () => {
    const element = document.createElement("a");
    const file = new Blob([backupCodes.join("\n")], { type: "text/plain" });
    element.href = URL.createObjectURL(file);
    element.download = "terrakube-backup-codes.txt";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleFinish = () => {
    onSuccess();
    onCancel();
  };

  const renderSetupStep = () => (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Alert
        message="Scan the QR code"
        description="Open your authenticator app (like Google Authenticator or Authy) and scan the QR code below."
        type="info"
        showIcon
      />
      
      {setupError && <Alert type="error" message="Failed to load QR code" description={setupError.message} />}

      <div className="qr-container">
        {setupData?.secretUri ? (
          <QRCodeSVG value={setupData.secretUri} size={200} level="H" />
        ) : (
          <div style={{ height: 200, width: 200, background: "#eee" }} />
        )}
        
        <div className="secret-container">
          <Space style={{ marginTop: 16 }}>
            <Text>Can't scan?</Text>
            <Switch 
              checkedChildren="Hide Secret" 
              unCheckedChildren="Show Secret" 
              checked={showSecret} 
              onChange={setShowSecret} 
            />
          </Space>
          
          {showSecret && secret && (
            <div style={{ marginTop: 12 }}>
              <Text type="secondary">Enter this code manually in your app:</Text>
              <Text className="secret-code" copyable>{secret}</Text>
            </div>
          )}
        </div>
      </div>

      <Divider>Verify Code</Divider>

      <div className="verify-input-container">
        <Space direction="vertical" align="center">
          <Text>Enter the 6-digit code from your app</Text>
          <Input.OTP length={6} value={code} onChange={setCode} />
          {verifyError && <Text type="danger">{verifyError.message || "Verification failed"}</Text>}
        </Space>
      </div>

      <Flex justify="end" gap="small">
        <Button onClick={onCancel}>Cancel</Button>
        <Button 
          type="primary" 
          onClick={handleVerify} 
          loading={verifyLoading} 
          disabled={code.length !== 6}
        >
          Verify & Enable
        </Button>
      </Flex>
    </Space>
  );

  const renderBackupStep = () => (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Alert
        message="Save your backup codes"
        description="If you lose access to your device, these codes are the only way to access your account. Save them in a secure place."
        type="warning"
        showIcon
      />

      <div className="backup-codes-grid">
        {backupCodes.map((code, index) => (
          <div key={index} className="backup-code">
            {code}
          </div>
        ))}
        {backupLoading && <Text>Generating codes...</Text>}
      </div>

      <Flex justify="center" gap="middle">
        <Button onClick={handleCopyBackupCodes}>Copy Codes</Button>
        <Button onClick={handleDownloadBackupCodes}>Download</Button>
      </Flex>

      <Flex justify="end" style={{ marginTop: 24 }}>
        <Button type="primary" onClick={handleFinish}>
          I have saved my codes
        </Button>
      </Flex>
    </Space>
  );

  return (
    <Modal
      className="totp-setup-modal"
      open={visible}
      title="Set up Two-Factor Authentication"
      onCancel={onCancel}
      footer={null}
      width={500}
      destroyOnClose
      maskClosable={false}
    >
      <Steps
        current={currentStep}
        items={[
          { title: "Scan Code" },
          { title: "Save Backup Codes" },
        ]}
        style={{ marginBottom: 24 }}
      />
      
      <div className="step-content">
        {currentStep === 0 ? renderSetupStep() : renderBackupStep()}
      </div>
    </Modal>
  );
}
