import { Alert, Button, Card, Flex, Spin, Typography, Tag, Space, Popconfirm, message, Divider, Modal, Input, Form } from "antd";
import { useEffect, useState } from "react";
import { SafetyCertificateOutlined, MobileOutlined, KeyOutlined, LockOutlined } from "@ant-design/icons";
import useApiRequest from "@/modules/api/useApiRequest";
import mfaService, { MfaStatus, MfaMethod } from "@/modules/user/mfaService";
import TotpSetupModal from "@/modules/user/components/TotpSetupModal/TotpSetupModal";
import WebAuthnSetupModal from "@/modules/user/components/WebAuthnSetupModal/WebAuthnSetupModal";
import "./MfaSection.css";

const { Title, Text, Paragraph } = Typography;

export const MfaSection = () => {
  const [messageApi, contextHolder] = message.useMessage();
const [mfaStatus, setMfaStatus] = useState<MfaStatus | null>(null);
  const [removingId, setRemovingId] = useState<string | null>(null);
const [totpModalOpen, setTotpModalOpen] = useState(false);
  const [webauthnModalOpen, setWebauthnModalOpen] = useState(false);
  const [renameModalOpen, setRenameModalOpen] = useState(false);
  const [methodToRename, setMethodToRename] = useState<MfaMethod | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [renameForm] = Form.useForm();
  const { loading, execute: loadStatus, error } = useApiRequest({
    action: () => mfaService.getMfaStatus(),
    onReturn: (data: any) => {
      // Handle both direct data and ApiResponse wrapper
      setMfaStatus(data.data || data);
    },
  });

  const fetchMfaStatus = () => {
    loadStatus();
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const handleRemoveMethod = async (method: MfaMethod) => {
    setRemovingId(method.id);
    try {
      if (method.type === "TOTP") {
        await mfaService.deleteTotp();
      } else {
        await mfaService.deleteWebAuthnCredential(method.id);
      }
      messageApi.success(`${getMethodLabel(method.type)} removed successfully`);
      fetchMfaStatus();
    } catch (e: any) {
      messageApi.error(e?.message || "Failed to remove method");
    } finally {
      setRemovingId(null);
    }
  };
  const handleRenameMethod = async (values: { name: string }) => {
    if (!methodToRename) return;
    
    setRenaming(true);
    try {
      if (methodToRename.type === "WEBAUTHN") {
        await mfaService.renameWebAuthnCredential(methodToRename.id, values.name);
      } else {
        await mfaService.renameTotp(methodToRename.id, values.name);
      }
      messageApi.success("Method renamed successfully");
      setRenameModalOpen(false);
      setMethodToRename(null);
      renameForm.resetFields();
      fetchMfaStatus();
    } catch (e: any) {
      messageApi.error(e?.message || "Failed to rename method");
    } finally {
      setRenaming(false);
    }
  };

  const openRenameModal = (method: MfaMethod) => {
    setMethodToRename(method);
    renameForm.setFieldsValue({ name: method.name || getMethodLabel(method.type) });
    setRenameModalOpen(true);
  };
  const getMethodIcon = (type: "TOTP" | "WEBAUTHN") => {
    return type === "TOTP" ? <MobileOutlined /> : <KeyOutlined />;
  };

  const getMethodLabel = (type: "TOTP" | "WEBAUTHN") => {
    return type === "TOTP" ? "Authenticator App" : "WebAuthn/Passkey";
  };

  if (loading && !mfaStatus) {
    return (
      <Flex justify="center" align="center" style={{ height: "200px" }}>
        <Spin size="large" />
      </Flex>
    );
  }

  if (error) {
    return (
      <div className="mfa-section">
        <Alert
          title="Error loading MFA status"
          description={error.message || "Please try again later."}
          type="error"
          showIcon
        />
      </div>
    );
  }

  return (
    <div className="mfa-container">
      {contextHolder}
      <div className="mfa-header">
        <Title level={3}>Multi-Factor Authentication</Title>
        <Paragraph type="secondary">
          Add an extra layer of security to your account by requiring more than just a password to log in.
        </Paragraph>
      </div>

      <div className={`mfa-status-banner ${mfaStatus?.mfaEnabled ? "enabled" : "disabled"}`}>
        {mfaStatus?.mfaEnabled ? <SafetyCertificateOutlined /> : <LockOutlined />}
        <span>Status: {mfaStatus?.mfaEnabled ? "Enabled" : "Disabled"}</span>
      </div>

      {mfaStatus?.mfaEnabled && (
        <div className="mfa-card">
          <div className="mfa-card-header">Enabled Methods</div>
          <div className="mfa-card-body">
            {mfaStatus.methods.map((item: MfaMethod) => (
              <div key={item.id} className="mfa-method-item">
                <div className="mfa-method-content">
                  <div className="mfa-icon-wrapper">
                    {getMethodIcon(item.type)}
                  </div>
                  <div className="mfa-method-info">
                    <div className="mfa-method-title">{item.name || getMethodLabel(item.type)}</div>
                    <div className="mfa-method-description">
                      Added on {new Date(item.createdAt).toLocaleDateString()}
                    </div>
                  </div>
                </div>
                  <div className="mfa-method-actions">
                    <Space size="small">
                      <Button type="primary" onClick={() => openRenameModal(item)}>Rename</Button>
                      <Popconfirm
                        title="Remove this method?"
                        description="You won't be able to use it for MFA verification."
                        onConfirm={() => handleRemoveMethod(item)}
                        okText="Remove"
                        okButtonProps={{ danger: true }}
                      >
                        <Button
                          type="primary"
                          danger
                          loading={removingId === item.id}
                        >
                          Remove
                        </Button>
                      </Popconfirm>
                    </Space>
                  </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mfa-card">
        <div className="mfa-card-header">Add Method</div>
        <div className="mfa-card-body">
          <div className="mfa-method-item">
            <div className="mfa-method-content">
              <div className="mfa-icon-wrapper">
                <MobileOutlined />
              </div>
              <div className="mfa-method-info">
                <div className="mfa-method-title">Authenticator App</div>
                <div className="mfa-method-description">
                  Use an app like Google Authenticator or Authy
                </div>
              </div>
            </div>
            <Button type="primary" onClick={() => setTotpModalOpen(true)}>Set up</Button>
          </div>

          <div className="mfa-method-item">
            <div className="mfa-method-content">
              <div className="mfa-icon-wrapper">
                <KeyOutlined />
              </div>
              <div className="mfa-method-info">
                <div className="mfa-method-title">WebAuthn/Passkey</div>
                <div className="mfa-method-description">
                  Use a hardware key like YubiKey or TouchID
                </div>
              </div>
            </div>
            <Button type="primary" onClick={() => setWebauthnModalOpen(true)}>Set up</Button>
          </div>
        </div>
      </div>
      <TotpSetupModal
        visible={totpModalOpen}
        onCancel={() => setTotpModalOpen(false)}
        onSuccess={() => {
          setTotpModalOpen(false);
          fetchMfaStatus();
        }}
      />
      <WebAuthnSetupModal
        visible={webauthnModalOpen}
        onCancel={() => setWebauthnModalOpen(false)}
        onSuccess={() => {
          setWebauthnModalOpen(false);
          fetchMfaStatus();
        }}
      />
      <Modal
        title="Rename Method"
        open={renameModalOpen}
        onCancel={() => {
          setRenameModalOpen(false);
          setMethodToRename(null);
          renameForm.resetFields();
        }}
        onOk={() => renameForm.submit()}
        confirmLoading={renaming}
      >
        <Form
          form={renameForm}
          layout="vertical"
          onFinish={handleRenameMethod}
        >
          <Form.Item
            name="name"
            label="Method Name"
            rules={[
              { required: true, message: "Please enter a name" },
              { max: 50, message: "Name cannot exceed 50 characters" }
            ]}
          >
            <Input id="mfa-rename-method" name="mfa-rename-method" placeholder="e.g. My YubiKey" autoFocus />
          </Form.Item>
        </Form>
      </Modal>
    </div>
);
};
