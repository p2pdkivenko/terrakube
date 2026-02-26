import { Alert, Button, Card, Flex, Spin, Typography, Tag, Space, List } from "antd";
import { useEffect, useState } from "react";
import { SafetyCertificateOutlined, MobileOutlined, KeyOutlined, LockOutlined } from "@ant-design/icons";
import useApiRequest from "@/modules/api/useApiRequest";
import mfaService, { MfaStatus, MfaMethod } from "@/modules/user/mfaService";
import TotpSetupModal from "@/modules/user/components/TotpSetupModal/TotpSetupModal";
import WebAuthnSetupModal from "@/modules/user/components/WebAuthnSetupModal/WebAuthnSetupModal";
import BackupCodesModal from "@/modules/user/components/BackupCodesModal/BackupCodesModal";
import "./MfaSection.css";

const { Title, Text, Paragraph } = Typography;

export const MfaSection = () => {
  const [mfaStatus, setMfaStatus] = useState<MfaStatus | null>(null);
  const [totpModalOpen, setTotpModalOpen] = useState(false);
  const [webauthnModalOpen, setWebauthnModalOpen] = useState(false);
  const [backupCodesModalOpen, setBackupCodesModalOpen] = useState(false);

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

  const getMethodIcon = (type: "TOTP" | "WEBAUTHN") => {
    return type === "TOTP" ? <MobileOutlined /> : <KeyOutlined />;
  };

  const getMethodLabel = (type: "TOTP" | "WEBAUTHN") => {
    return type === "TOTP" ? "Authenticator App" : "Security Key / Passkey";
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
          message="Error loading MFA status"
          description={error.message || "Please try again later."}
          type="error"
          showIcon
        />
      </div>
    );
  }

  return (
    <div className="mfa-section">
      <Space direction="vertical" size="large" style={{ width: "100%" }}>
        <div>
          <Title level={3}>Multi-Factor Authentication</Title>
          <Paragraph type="secondary">
            Add an extra layer of security to your account by requiring more than just a password to log in.
          </Paragraph>
          
          <Flex align="center" gap="small" className="mfa-status-badge">
            <Text strong>Status:</Text>
            {mfaStatus?.mfaEnabled ? (
              <Tag color="success" icon={<SafetyCertificateOutlined />}>Enabled</Tag>
            ) : (
              <Tag color="default" icon={<LockOutlined />}>Disabled</Tag>
            )}
          </Flex>
        </div>

        {mfaStatus?.mfaEnabled && (
          <Card title="Enabled Methods" size="small">
            <List
              itemLayout="horizontal"
              dataSource={mfaStatus.methods}
              renderItem={(item: MfaMethod) => (
                <List.Item
                  actions={[<Button type="link" danger>Remove</Button>]}
                >
                  <List.Item.Meta
                    avatar={<div className="method-icon">{getMethodIcon(item.type)}</div>}
                    title={item.name || getMethodLabel(item.type)}
                    description={`Added on ${new Date(item.createdAt).toLocaleDateString()}`}
                  />
                </List.Item>
              )}
            />
          </Card>
        )}

        <Card title="Add Method" size="small">
          <Space direction="vertical" style={{ width: "100%" }}>
            <Flex justify="space-between" align="center">
              <Space>
                <MobileOutlined style={{ fontSize: '20px' }} />
                <div>
                  <Text strong>Authenticator App</Text>
                  <div style={{ fontSize: '12px', color: '#888' }}>Use an app like Google Authenticator or Authy</div>
                </div>
              </Space>
              <Button onClick={() => setTotpModalOpen(true)}>Set up</Button>
            </Flex>
            
            <Flex justify="space-between" align="center" style={{ marginTop: 16 }}>
              <Space>
                <KeyOutlined style={{ fontSize: '20px' }} />
                <div>
                  <Text strong>Security Key</Text>
                  <div style={{ fontSize: '12px', color: '#888' }}>Use a hardware key like YubiKey or TouchID</div>
                </div>
              </Space>
              <Button onClick={() => setWebauthnModalOpen(true)}>Set up</Button>
            </Flex>
          </Space>
        </Card>

        {mfaStatus?.mfaEnabled && (
          <Alert
            message="Backup Codes"
            description={
              <Flex justify="space-between" align="center">
                <Text>
                  You have {mfaStatus.backupCodesRemaining} backup codes remaining. 
                  Keep these safe to access your account if you lose your device.
                </Text>
                <Button size="small" onClick={() => setBackupCodesModalOpen(true)}>View Codes</Button>
              </Flex>
            }
            type="warning"
            showIcon
            className="backup-codes-alert"
          />
        )}
      </Space>
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
      <BackupCodesModal
        visible={backupCodesModalOpen}
        onCancel={() => setBackupCodesModalOpen(false)}
      />
    </div>
  );
};
