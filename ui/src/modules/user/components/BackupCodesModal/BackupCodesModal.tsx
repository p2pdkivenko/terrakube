import { Modal, Button, Alert, Checkbox, Typography, Space, message, Popconfirm } from "antd";
import { useState, useEffect } from "react";
import useApiRequest from "@/modules/api/useApiRequest";
import mfaService, { BackupCode } from "@/modules/user/mfaService";
import "./BackupCodesModal.css";

const { Text } = Typography;

type Props = {
  visible: boolean;
  onCancel: () => void;
};

export default function BackupCodesModal({ visible, onCancel }: Props) {
  const [codes, setCodes] = useState<BackupCode[]>([]);
  const [confirmed, setConfirmed] = useState(false);

  // Fetch codes
  const { loading, execute: fetchCodes } = useApiRequest({
    action: () => mfaService.getBackupCodes(),
    onReturn: (data) => setCodes(data),
  });

  // Regenerate codes
  const { loading: regenerating, execute: regenerateCodes } = useApiRequest({
    action: () => mfaService.generateBackupCodes(),
    onReturn: (data) => {
      // data.codes is string[]
      // We need to map it to BackupCode[]
      setCodes(data.codes.map(c => ({ code: c, used: false })));
      setConfirmed(false); // Reset confirmation
      message.success("New backup codes generated");
    },
  });

  useEffect(() => {
    if (visible) {
      fetchCodes();
      setConfirmed(false);
    }
  }, [visible]);

  const handleCopy = () => {
    const codeText = codes.map(c => c.code).join("\n");
    navigator.clipboard.writeText(codeText);
    message.success("Codes copied to clipboard");
  };

  const handleDownload = () => {
    const codeText = codes.map(c => c.code).join("\n");
    const element = document.createElement("a");
    const file = new Blob([codeText], { type: "text/plain" });
    element.href = URL.createObjectURL(file);
    element.download = "terrakube-backup-codes.txt";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const remainingCount = codes.filter(c => !c.used).length;

  return (
    <Modal
      className="backup-codes-modal"
      open={visible}
      title="Backup Codes"
      onCancel={onCancel}
      footer={[
        <Button key="close" onClick={onCancel} disabled={!confirmed}>
          Close
        </Button>
      ]}
      width={500}
      destroyOnHidden
      mask={{ closable: false }}
      closable={false}
    >
      <Alert
        title="Save your backup codes"
        description="If you lose access to your device, these codes are the only way to access your account. Save them in a secure place."
        type="warning"
        showIcon
        className="warning-container"
      />

      <div className="backup-codes-grid">
        {loading ? <Text>Loading...</Text> : codes.map((c, i) => (
          <div key={i} className={`backup-code ${c.used ? "used" : ""}`}>
            {c.code}
          </div>
        ))}
      </div>

      <div style={{ textAlign: "center", marginBottom: 16 }}>
        <Text type="secondary">{remainingCount} of {codes.length} codes remaining</Text>
      </div>

      <Space style={{ width: '100%', justifyContent: 'center', marginBottom: 24 }}>
        <Button onClick={handleCopy}>Copy All</Button>
        <Button onClick={handleDownload}>Download</Button>
        <Popconfirm
          title="Regenerate Backup Codes"
          description="Are you sure? This will invalidate your current backup codes."
          onConfirm={regenerateCodes}
          okText="Yes, Regenerate"
          cancelText="Cancel"
          okButtonProps={{ danger: true }}
        >
          <Button danger loading={regenerating}>Regenerate</Button>
        </Popconfirm>
      </Space>

      <Checkbox checked={confirmed} onChange={e => setConfirmed(e.target.checked)}>
        I have saved these codes in a secure location
      </Checkbox>
    </Modal>
  );
}
