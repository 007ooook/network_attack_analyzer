import React from 'react';
import './index.css';
import { Layout } from 'antd';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

// 导入页面组件
import Dashboard from './pages/Dashboard';
import LogParser from './pages/LogParser';
import LogsList from './pages/LogsList';
import ThreatIntel from './pages/ThreatIntel';
import Prediction from './pages/Prediction';
import SystemConfig from './pages/SystemConfig';
import DataSourceManager from './pages/DataSourceManager';
import Alerts from './pages/Alerts';

// 导入组件
import Sidebar from './components/Sidebar';
import LanguageSwitcher from './components/LanguageSwitcher';

const { Content } = Layout;

const App: React.FC = () => {
  return (
    <Router>
      <Layout style={{ minHeight: '100vh' }}>
        <Sidebar />
        <Layout style={{ flex: 1 }}>
          <Content style={{ padding: '20px', background: '#f0f2f5' }}>
            <div style={{ position: 'absolute', top: '20px', right: '20px', zIndex: 10 }}>
              <LanguageSwitcher />
            </div>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/log-parser" element={<LogParser />} />
              <Route path="/logs" element={<LogsList />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/prediction" element={<Prediction />} />
              <Route path="/data-sources" element={<DataSourceManager />} />
              <Route path="/system-config" element={<SystemConfig />} />
              <Route path="/alerts" element={<Alerts />} />
            </Routes>
          </Content>
        </Layout>
      </Layout>
    </Router>
  );
};

export default App;
