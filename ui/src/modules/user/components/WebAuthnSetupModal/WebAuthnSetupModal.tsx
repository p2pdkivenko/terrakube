import { Modal, Button, Typography, Alert, Space, message, Spin, Input } from "antd";
import { useState, useEffect } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/types";
import useApiRequest from "@/modules/api/useApiRequest";
import mfaService from "@/modules/user/mfaService";
import { KeyOutlined, LaptopOutlined, CheckCircleOutlined } from "@ant-design/icons";
import "./WebAuthnSetupModal.css";

const { Text, Title, Paragraph } = Typography;

type Props = {
  visible: boolean;
  onCancel: () => void;
  onSuccess: () => void;
};

type AuthenticatorType = "platform" | "cross-platform";

export default function WebAuthnSetupModal({ visible, onCancel, onSuccess }: Props) {
  const [step, setStep] = useState<"select" | "success">("select");
  const [selectedType, setSelectedType] = useState<AuthenticatorType | null>(null);
  const [registrationError, setRegistrationError] = useState<string | null>(null);
  const [credentialName, setCredentialName] = useState("");

  const { loading: registerLoading, execute: startRegisterFlow } = useApiRequest({
    action: async (type: AuthenticatorType) => {
      setRegistrationError(null);

      const optionsResponse = await mfaService.getWebAuthnRegisterOptions();
      const options = typeof optionsResponse.data === 'string'
        ? JSON.parse(optionsResponse.data) as PublicKeyCredentialCreationOptionsJSON
        : optionsResponse.data as unknown as PublicKeyCredentialCreationOptionsJSON;

      if (!options.authenticatorSelection) {
        options.authenticatorSelection = {};
      }
      options.authenticatorSelection.authenticatorAttachment = type;

      let attResp;
      try {
        attResp = await startRegistration({ optionsJSON: options });
      } catch (error: any) {
        if (error.name === "NotAllowedError") {
          throw new Error("Registration cancelled or timed out.");
        }
        throw error;
      }

      return await mfaService.verifyWebAuthnRegistration(attResp, credentialName.trim() || undefined);
    },
    onReturn: (data: any) => {
      if (data && data.success === false) {
        message.error(data.message || "Registration verification failed");
        return;
      }
      message.success("Authenticator registered successfully");
      setStep("success");
    },
    requestErrorInfo: {
      title: "Registration Failed",
      message: "Failed to register authenticator",
    },
  });

  useEffect(() => {
    if (visible) {
      setStep("select");
      setRegistrationError(null);
      setSelectedType(null);
      setCredentialName("");
      setRegistrationError(null);
      setSelectedType(null);
    }
  }, [visible]);

  const handleSelectType = (type: AuthenticatorType) => {
    setSelectedType(type);
    startRegisterFlow(type);
  };

  const handleFinish = () => {
    onSuccess();
    onCancel();
  };

  return (
    <Modal
      className="webauthn-setup-modal"
      open={visible}
      title="Register Authenticator"
      onCancel={onCancel}
      footer={null}
      width={600}
      destroyOnHidden
      mask={{ closable: !registerLoading }}
    >
      {step === "select" && (
        <Space orientation="vertical" style={{ width: "100%" }} size="large">
          <div style={{ marginBottom: 16 }}>
            <Text strong style={{ display: "block", marginBottom: 8 }}>Name</Text>
            <Input
              id="webauthn-credential-name"
              name="webauthn-credential-name"
placeholder="e.g. My YubiKey, Work Laptop"
value={credentialName}
onChange={(e) => setCredentialName(e.target.value)}
maxLength={50}
disabled={registerLoading}
/>
          </div>

          {registerLoading ? (
            <div style={{ textAlign: "center", padding: "60px 0" }}>
              <Spin size="large" description="Waiting for your interaction..." />
              <div style={{ marginTop: 16 }}>
                <Text type="secondary">Follow the instructions on your browser or device.</Text>
              </div>
            </div>
          ) : (
            <div className="webauthn-method-selection">
              <div
                className={`webauthn-method-card${!credentialName.trim() ? " disabled" : ""}`}
                onClick={() => credentialName.trim() && handleSelectType("platform")}
                style={{ opacity: credentialName.trim() ? 1 : 0.4, pointerEvents: credentialName.trim() ? "auto" : "none" }}
              >
                <LaptopOutlined className="webauthn-method-icon" />
                <div className="webauthn-method-title">Passkey (This Device)</div>
                <div className="webauthn-method-desc">Use Touch ID, Face ID, or Windows Hello</div>
              </div>

              <div
                className={`webauthn-method-card${!credentialName.trim() ? " disabled" : ""}`}
                onClick={() => credentialName.trim() && handleSelectType("cross-platform")}
                style={{ opacity: credentialName.trim() ? 1 : 0.4, pointerEvents: credentialName.trim() ? "auto" : "none" }}
              >
                <KeyOutlined className="webauthn-method-icon" style={{ color: "#52c41a" }} />
                <div className="webauthn-method-title">WebAuthn/Passkey (External)</div>
                <div className="webauthn-method-desc">Use a YubiKey or other USB/NFC key</div>
              </div>
            </div>
          )}
        </Space>
      )}

      {step === "success" && (
        <div style={{ textAlign: "center", padding: "40px 0" }}>
          <CheckCircleOutlined style={{ fontSize: 64, color: "#52c41a", marginBottom: 24 }} />
          <Title level={3}>Registration Complete!</Title>
          <Paragraph>
            Your new authenticator has been successfully registered.
          </Paragraph>
          <Space size="middle" style={{ marginTop: 24 }}>
            <Button onClick={() => setStep("select")}>Register Another</Button>
            <Button type="primary" onClick={handleFinish}>Done</Button>
          </Space>
        </div>
      )}
    </Modal>
  );
}
