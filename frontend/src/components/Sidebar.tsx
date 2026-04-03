import React from 'react';
import { Layout, Menu } from 'antd';
import { Link, useLocation } from 'react-router-dom';
import {
  DashboardOutlined,
  FileTextOutlined,
  OrderedListOutlined,
  AlertOutlined,
  LineChartOutlined,
  DatabaseOutlined,
  SettingOutlined,
  SafetyOutlined
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

const { Sider } = Layout;

const Sidebar: React.FC = () => {
  const location = useLocation();
  const currentPath = location.pathname;
  const { t } = useTranslation();

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
      key: '/data-sources',
      icon: <DatabaseOutlined />,
      label: <Link to="/data-sources">{t('menu.dataSources')}</Link>,
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
          height: 'calc(100vh - 64px)', 
          borderRight: 0, 
          backgroundColor: '#001529',
          paddingTop: '16px'
        }}
        theme="dark"
        inlineCollapsed={false}
      />
    </Sider>
  );
};

export default Sidebar;
