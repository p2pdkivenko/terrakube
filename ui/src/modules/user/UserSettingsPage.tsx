import { Breadcrumb, Layout, Tabs, theme } from "antd";
import { useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Tokens } from "./components/PatSection/PatSection";
import { ThemeSection } from "./components/ThemeSection/ThemeSection";
import { MfaSection } from "./components/MfaSection/MfaSection";
import "./UserSettingsPage.css";
const { Content } = Layout;

export const UserSettingsPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const currentTab = location.pathname.includes("/settings/theme") ? "2" : location.pathname.includes("/settings/security") ? "3" : "1";
  const {
    token: { colorBgContainer },
  } = theme.useToken();

  useEffect(() => {
    // Update URL when component mounts to match the current tab
if (currentTab === "2" && !location.pathname.includes("/settings/theme")) {
      navigate("/settings/theme", { replace: true });
    } else if (currentTab === "3" && !location.pathname.includes("/settings/security")) {
      navigate("/settings/security", { replace: true });
} else if (currentTab === "1" && !location.pathname.includes("/settings/tokens")) {
navigate("/settings/tokens", { replace: true });
}
  }, []);

  const handleTabChange = (key: string) => {
if (key === "2") {
      navigate("/settings/theme");
    } else if (key === "3") {
      navigate("/settings/security");
} else {
navigate("/settings/tokens");
}
  };

  return (
    <Content className="user-settings-page">
      <Breadcrumb
        style={{ margin: "16px 0" }}
        items={[
          {
            title: "Settings",
          },
          {
            title: currentTab === "2" ? "Theme" : currentTab === "3" ? "Security" : "Tokens",
          },
        ]}
      />
      <div className="tabs" style={{ background: colorBgContainer }}>
        <Tabs
          tabPosition="left"
          activeKey={currentTab}
          onChange={handleTabChange}
          items={[
            {
              label: "Tokens (PAT)",
              key: "1",
              children: <Tokens />,
            },
            {
              label: "Theme",
              key: "2",
children: <ThemeSection />,
            },
            {
              label: "Security",
              key: "3",
              children: <MfaSection />,
            },
          ]}
        />
      </div>
    </Content>
  );
};
