import { Modal, Button, List, Typography, Alert, Space, Steps, message, Spin, Popconfirm, Tag } from "antd";
import { useState, useEffect } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/types";
import useApiRequest from "@/modules/api/useApiRequest";
import mfaService, { WebAuthnCredential } from "@/modules/user/mfaService";
import { KeyOutlined, LaptopOutlined, DeleteOutlined, PlusOutlined, CheckCircleOutlined } from "@ant-design/icons";
import { DateTime } from "luxon";
import "./WebAuthnSetupModal.css";

const { Text, Title, Paragraph } = Typography;

type Props = {
  visible: boolean;
  onCancel: () => void;
  onSuccess: () => void;
};

type AuthenticatorType = "platform" | "cross-platform";

export default function WebAuthnSetupModal({ visible, onCancel, onSuccess }: Props) {
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [credentials, setCredentials] = useState<WebAuthnCredential[]>([]);
  const [selectedType, setSelectedType] = useState<AuthenticatorType | null>(null);
  const [registrationError, setRegistrationError] = useState<string | null>(null);

  // List Credentials API
  const { loading: listLoading, execute: listCredentials } = useApiRequest({
    action: () => mfaService.listWebAuthnCredentials(),
    onReturn: (data) => {
      setCredentials(data);
    },
  });

  // Delete Credential API
  const { loading: deleteLoading, execute: deleteCredential } = useApiRequest({
    action: (id: string) => mfaService.deleteWebAuthnCredential(id),
    onReturn: () => {
      message.success("Credential deleted successfully");
      listCredentials();
    },
  });

  // Register API Flow
  const { loading: registerLoading, execute: startRegisterFlow } = useApiRequest({
    action: async (type: AuthenticatorType) => {
      setRegistrationError(null);
      
      // 1. Get options from server
      const optionsResponse = await mfaService.getWebAuthnRegisterOptions();
      const options = optionsResponse.data as unknown as PublicKeyCredentialCreationOptionsJSON;

      // 2. Add authenticator selection based on user choice
      if (!options.authenticatorSelection) {
        options.authenticatorSelection = {};
      }
      options.authenticatorSelection.authenticatorAttachment = type;
      
      // 3. Start registration in browser
      let attResp;
      try {
        attResp = await startRegistration(options);
      } catch (error: any) {
        if (error.name === "NotAllowedError") {
          throw new Error("Registration cancelled or timed out.");
        }
        throw error;
      }

      // 4. Verify with server
      return await mfaService.verifyWebAuthnRegistration(attResp);
    },
    onReturn: () => {
      message.success("Authenticator registered successfully");
      setCurrentStep(2); // Success step
      listCredentials();
    },
    requestErrorInfo: {
      title: "Registration Failed",
      message: "Failed to register authenticator",
    },
  });

  useEffect(() => {
    if (visible) {
      setCurrentStep(0);
      setRegistrationError(null);
      setSelectedType(null);
      listCredentials();
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

  const handleBackToList = () => {
    setCurrentStep(0);
    setSelectedType(null);
    setRegistrationError(null);
  };

  const renderCredentialsList = () => (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Text type="secondary">
          Manage your passkeys and security keys.
        </Text>
        <Button 
          type="primary" 
          icon={<PlusOutlined />} 
          onClick={() => setCurrentStep(1)}
        >
          Add Method
        </Button>
      </div>

      {listLoading ? (
        <div style={{ textAlign: "center", padding: "40px" }}>
          <Spin size="large" />
        </div>
      ) : (
        <List
          className="webauthn-credentials-list"
          itemLayout="horizontal"
          dataSource={credentials}
          locale={{ emptyText: "No authenticators registered yet." }}
          renderItem={(item) => (
            <List.Item
              actions={[
                <Popconfirm
                  title="Delete authenticator"
                  description="Are you sure you want to delete this authenticator?"
                  onConfirm={() => deleteCredential(item.id)}
                  okText="Yes"
                  cancelText="No"
                  key="delete"
                >
                  <Button type="text" danger icon={<DeleteOutlined />} loading={deleteLoading} />
                </Popconfirm>
              ]}
            >
              <List.Item.Meta
                avatar={
                  item.type === "PLATFORM" ? 
                    <LaptopOutlined style={{ fontSize: 24, color: "#1890ff" }} /> : 
                    <KeyOutlined style={{ fontSize: 24, color: "#52c41a" }} />
                }
                title={
                  <Space>
                    <Text strong>{item.name || "Unnamed Authenticator"}</Text>
                    <Tag color={item.type === "PLATFORM" ? "blue" : "green"}>
                      {item.type === "PLATFORM" ? "Passkey" : "Security Key"}
                    </Tag>
                  </Space>
                }
                description={`Added on ${DateTime.fromISO(item.createdAt).toFormat("MMM d, yyyy")}`}
              />
            </List.Item>
          )}
        />
      )}
    </Space>
  );

  const renderSelectionStep = () => (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <Alert
        message="Choose Authenticator Type"
        description="Select the type of authenticator you want to register."
        type="info"
        showIcon
      />

      {registerLoading ? (
        <div style={{ textAlign: "center", padding: "60px 0" }}>
          <Spin size="large" tip="Waiting for your interaction..." />
          <div style={{ marginTop: 16 }}>
            <Text type="secondary">Follow the instructions on your browser or device.</Text>
          </div>
        </div>
      ) : (
        <div className="webauthn-method-selection">
          <div 
            className="webauthn-method-card"
            onClick={() => handleSelectType("platform")}
          >
            <LaptopOutlined className="webauthn-method-icon" />
            <div className="webauthn-method-title">Passkey (This Device)</div>
            <div className="webauthn-method-desc">Use Touch ID, Face ID, or Windows Hello</div>
          </div>

          <div 
            className="webauthn-method-card"
            onClick={() => handleSelectType("cross-platform")}
          >
            <KeyOutlined className="webauthn-method-icon" style={{ color: "#52c41a" }} />
            <div className="webauthn-method-title">Security Key (External)</div>
            <div className="webauthn-method-desc">Use a YubiKey or other USB/NFC key</div>
          </div>
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 16 }}>
        <Button onClick={handleBackToList} disabled={registerLoading}>Cancel</Button>
      </div>
    </Space>
  );

  const renderSuccessStep = () => (
    <div style={{ textAlign: "center", padding: "40px 0" }}>
      <CheckCircleOutlined style={{ fontSize: 64, color: "#52c41a", marginBottom: 24 }} />
      <Title level={3}>Registration Complete!</Title>
      <Paragraph>
        Your new authenticator has been successfully registered and can now be used for multi-factor authentication.
      </Paragraph>
      <Space size="middle" style={{ marginTop: 24 }}>
        <Button onClick={handleBackToList}>Register Another</Button>
        <Button type="primary" onClick={handleFinish}>Done</Button>
      </Space>
    </div>
  );

  return (
    <Modal
      className="webauthn-setup-modal"
      open={visible}
      title="Manage WebAuthn Credentials"
      onCancel={onCancel}
      footer={null}
      width={600}
      destroyOnClose
      maskClosable={!registerLoading}
    >
      {currentStep > 0 && (
        <Steps
          current={currentStep}
          items={[
            { title: "Manage" },
            { title: "Select Type" },
            { title: "Complete" },
          ]}
          className="webauthn-setup-steps"
          style={{ marginBottom: 24 }}
        />
      )}
      
      <div className="step-content">
        {currentStep === 0 && renderCredentialsList()}
        {currentStep === 1 && renderSelectionStep()}
        {currentStep === 2 && renderSuccessStep()}
      </div>
    </Modal>
  );
}
