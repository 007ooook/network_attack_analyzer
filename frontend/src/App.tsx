import React, { useState, useEffect } from 'react';
import './index.css';
import { Layout } from 'antd';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Dashboard from './pages/Dashboard';
import LogParser from './pages/LogParser';
import LogsList from './pages/LogsList';
import LogAnalysis from './pages/LogAnalysis';
import ThreatIntel from './pages/ThreatIntel';
import Prediction from './pages/Prediction';
import SystemConfig from './pages/SystemConfig';
import DataSourceManager from './pages/DataSourceManager';
import DataSourceLogs from './pages/DataSourceLogs';
import Alerts from './pages/Alerts';
import RulesManager from './pages/RulesManager';
import Login from './pages/Login';

import Sidebar from './components/Sidebar';
import LanguageSwitcher from './components/LanguageSwitcher';
import { api } from './utils/api';

const { Content } = Layout;

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      api.get('/me')
        .then(res => {
          if (res.data.success) {
            setIsAuthenticated(true);
          } else {
            localStorage.removeItem('auth_token');
          }
          setIsLoading(false);
        })
        .catch(() => {
          localStorage.removeItem('auth_token');
          setIsLoading(false);
        });
    } else {
      setIsLoading(false);
    }
  }, []);

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      api.post('/logout', { token });
    }
    localStorage.removeItem('auth_token');
    setIsAuthenticated(false);
  };

  if (isLoading) {
    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>加载中...</div>;
  }

  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <Router>
      <Layout style={{ minHeight: '100vh' }}>
        <Sidebar onLogout={handleLogout} />
        <Layout style={{ flex: 1 }}>
          <Content style={{ padding: '20px', background: '#f0f2f5' }}>
            <div style={{ position: 'absolute', top: '20px', right: '20px', zIndex: 10 }}>
              <LanguageSwitcher />
            </div>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/log-parser" element={<LogParser />} />
              <Route path="/logs" element={<LogsList />} />
              <Route path="/log-analysis" element={<LogAnalysis />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/prediction" element={<Prediction />} />
              <Route path="/data-sources" element={<DataSourceManager />} />
              <Route path="/data-source-logs" element={<DataSourceLogs />} />
              <Route path="/system-config" element={<SystemConfig />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/rules" element={<RulesManager />} />
            </Routes>
          </Content>
        </Layout>
      </Layout>
    </Router>
  );
};

export default App;
