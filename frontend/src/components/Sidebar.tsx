import React, { useState, useEffect } from 'react';
import { Layout, Menu, Button, Tooltip } from 'antd';
import { Link, useLocation } from 'react-router-dom';
import {
  DashboardOutlined,
  FileTextOutlined,
  OrderedListOutlined,
  AlertOutlined,
  LineChartOutlined,
  BarChartOutlined,
  DatabaseOutlined,
  SettingOutlined,
  SafetyOutlined,
  CodeOutlined,
  LogoutOutlined,
  UserOutlined
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { api } from '../utils/api';

const { Sider } = Layout;

interface SidebarProps {
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ onLogout }) => {
  const location = useLocation();
  const currentPath = location.pathname;
  const { t } = useTranslation();
  const [currentUser, setCurrentUser] = useState<string>('');

  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      api.get('/me')
        .then(res => {
          if (res.data.success && res.data.user) {
            setCurrentUser(res.data.user.username);
          }
        })
        .catch(() => {});
    }
  }, []);

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: <Link to="/">{t('menu.dashboard')}</Link>,
    },
    {
      key: '/log-parser',
      icon: <FileTextOutlined />,
      label: <Link to="/log-parser">{t('menu.logParser')}</Link>,
    },
    {
      key: '/logs',
      icon: <OrderedListOutlined />,
      label: <Link to="/logs">{t('menu.logsList')}</Link>,
    },
    {
      key: '/log-analysis',
      icon: <BarChartOutlined />,
      label: <Link to="/log-analysis">{t('menu.logAnalysis')}</Link>,
    },
    {
      key: '/threat-intel',
      icon: <AlertOutlined />,
      label: <Link to="/threat-intel">{t('menu.threatIntel')}</Link>,
    },
    {
      key: '/prediction',
      icon: <LineChartOutlined />,
      label: <Link to="/prediction">{t('menu.prediction')}</Link>,
    },
    {
      key: '/alerts',
      icon: <SafetyOutlined />,
      label: <Link to="/alerts">{t('menu.alerts')}</Link>,
    },
    {
      key: '/rules',
      icon: <CodeOutlined />,
      label: <Link to="/rules">规则管理</Link>,
    },
    {
      key: '/data-sources',
      icon: <DatabaseOutlined />,
      label: <Link to="/data-sources">{t('menu.dataSources')}</Link>,
    },
    {
      key: '/data-source-logs',
      icon: <FileTextOutlined />,
      label: <Link to="/data-source-logs">{t('menu.dataSourceLogs')}</Link>,
    },
    {
      key: '/system-config',
      icon: <SettingOutlined />,
      label: <Link to="/system-config">{t('menu.systemConfig')}</Link>,
    },
  ];

  return (
    <Sider 
      width={220} 
      style={{ 
        background: '#001529',
        boxShadow: '2px 0 8px rgba(0, 0, 0, 0.15)',
        transition: 'all 0.3s ease'
      }}
      breakpoint="lg"
      collapsedWidth="80"
      onBreakpoint={(broken) => {
        console.log(broken);
      }}
      onCollapse={(collapsed, type) => {
        console.log(collapsed, type);
      }}
    >
      <div 
        style={{
          height: '64px', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center', 
          color: 'white', 
          fontSize: '16px', 
          fontWeight: 'bold',
          padding: '0 16px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
        }}
      >
        Network Attack Analyzer
      </div>
      <Menu
        mode="inline"
        selectedKeys={[currentPath]}
        items={menuItems}
        style={{ 
          height: 'calc(100vh - 160px)', 
          borderRight: 0, 
          backgroundColor: '#001529',
          paddingTop: '16px'
        }}
        theme="dark"
        inlineCollapsed={false}
      />
      <div style={{ 
        padding: '12px 20px', 
        borderTop: '1px solid rgba(255, 255, 255, 0.08)',
        background: 'rgba(255, 255, 255, 0.02)'
      }}>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          marginBottom: 10,
          color: 'rgba(255, 255, 255, 0.45)',
          fontSize: '12px'
        }}>
          <UserOutlined style={{ marginRight: 6 }} />
          <Tooltip title={currentUser || '未知用户'} placement="topLeft">
            <span style={{ 
              overflow: 'hidden', 
              textOverflow: 'ellipsis', 
              whiteSpace: 'nowrap',
              maxWidth: 140
            }}>
              {currentUser || '未知用户'}
            </span>
          </Tooltip>
        </div>
        <Button
          type="text"
          danger
          block
          icon={<LogoutOutlined />}
          onClick={onLogout}
          style={{ 
            color: 'rgba(255, 255, 255, 0.85)',
            height: '36px',
            fontSize: '13px'
          }}
        >
          退出登录
        </Button>
      </div>
    </Sider>
  );
};

export default Sidebar;
