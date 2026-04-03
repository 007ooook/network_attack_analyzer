import React, { useEffect, useState, useRef } from 'react';
import { Card, Form, Input, Button, message, Select, Switch, Divider, Typography, Spin } from 'antd';
import { useTranslation } from 'react-i18next';
import { SyncOutlined } from '@ant-design/icons';

const { Option } = Select;
const { Title } = Typography;

const API_BASE_URL = 'http://localhost:8006/api';

const SystemConfig: React.FC = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [systemHealth, setSystemHealth] = useState<any>(null);
  const { t } = useTranslation();
  const healthTimerRef = useRef<number | null>(null);

  // 加载系统配置
  const loadConfig = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/config`);
      if (response.ok) {
        const data = await response.json();
        form.setFieldsValue(data.config);
      } else {
        // 使用默认配置
        form.setFieldsValue({
          api_url: 'http://localhost:8003/api',
          log_retention_days: 30,
          max_log_size: 100,
          enable_email_alert: true,
          email_recipients: 'admin@example.com',
          alert_threshold: 0.7,
          model_version: '1.0.0',
          enable_rate_limiting: true,
          rate_limit: 1000,
          enable_ip_blocking: true,
          block_duration: 3600,
          enable_ssl: false,
          ssl_cert_path: '',
          ssl_key_path: '',
          enable_cors: true,
          allowed_origins: '*',
          api_key: ''
        });
      }
    } catch (error) {
      console.error('Error loading config:', error);
      message.error(t('common.error'));
      // 使用默认配置
        form.setFieldsValue({
          api_url: 'http://localhost:8003/api',
          log_retention_days: 30,
          max_log_size: 100,
          enable_email_alert: true,
          email_recipients: 'admin@example.com',
          alert_threshold: 0.7,
          model_version: '1.0.0',
          enable_rate_limiting: true,
          rate_limit: 1000,
          enable_ip_blocking: true,
          block_duration: 3600,
          enable_ssl: false,
          ssl_cert_path: '',
          ssl_key_path: '',
          enable_cors: true,
          allowed_origins: '*',
          api_key: ''
        });
    } finally {
      setLoading(false);
    }
  };

  // 加载系统健康状态
  const loadSystemHealth = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/system-health`);
      if (response.ok) {
        const data = await response.json();
        setSystemHealth(data);
      } else {
        // 响应失败时使用默认值
        setSystemHealth({
          cpu_usage: 0,
          memory_usage: 0,
          disk_usage: 0,
          db_size: 0,
          log_count: 0
        });
      }
    } catch (error) {
      console.error('Error loading system health:', error);
      // 错误时使用默认值
      setSystemHealth({
        cpu_usage: 0,
        memory_usage: 0,
        disk_usage: 0,
        db_size: 0,
        log_count: 0
      });
    }
  };

  // 初始化加载数据
  useEffect(() => {
    loadConfig();
    loadSystemHealth();
    
    // 设置定时刷新，每3秒更新一次系统健康状态
    healthTimerRef.current = setInterval(() => {
      loadSystemHealth();
    }, 3000) as unknown as number;
    
    // 组件卸载时清除定时器
    return () => {
      if (healthTimerRef.current) {
        clearInterval(healthTimerRef.current);
        healthTimerRef.current = null;
      }
    };
  }, []);

  // 保存API配置
  const handleSaveApiConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['api_url', 'enable_cors', 'allowed_origins']);
      const response = await fetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      });
      if (response.ok) {
        message.success(t('systemConfig.saveSuccess'));
      } else {
        message.error(t('systemConfig.saveError'));
      }
    } catch (error) {
      console.error('Error updating API config:', error);
      message.error(t('systemConfig.saveError'));
    } finally {
      setLoading(false);
    }
  };

  // 保存日志配置
  const handleSaveLogConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['log_retention_days', 'max_log_size']);
      const response = await fetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      });
      if (response.ok) {
        message.success(t('systemConfig.saveSuccess'));
      } else {
        message.error(t('systemConfig.saveError'));
      }
    } catch (error) {
      console.error('Error updating log config:', error);
      message.error(t('systemConfig.saveError'));
    } finally {
      setLoading(false);
    }
  };

  // 保存告警配置
  const handleSaveAlertConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['enable_email_alert', 'email_recipients', 'alert_threshold']);
      const response = await fetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      });
      if (response.ok) {
        message.success(t('systemConfig.saveSuccess'));
      } else {
        message.error(t('systemConfig.saveError'));
      }
    } catch (error) {
      console.error('Error updating alert config:', error);
      message.error(t('systemConfig.saveError'));
    } finally {
      setLoading(false);
    }
  };

  // 保存安全配置
  const handleSaveSecurityConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['enable_rate_limiting', 'rate_limit', 'enable_ip_blocking', 'block_duration', 'enable_ssl', 'ssl_cert_path', 'ssl_key_path']);
      const response = await fetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      });
      if (response.ok) {
        message.success(t('systemConfig.saveSuccess'));
      } else {
        message.error(t('systemConfig.saveError'));
      }
    } catch (error) {
      console.error('Error updating security config:', error);
      message.error(t('systemConfig.saveError'));
    } finally {
      setLoading(false);
    }
  };

  // 保存AI模型配置
  const handleSaveAiConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['model_version']);
      const response = await fetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      });
      if (response.ok) {
        message.success(t('systemConfig.saveSuccess'));
      } else {
        message.error(t('systemConfig.saveError'));
      }
    } catch (error) {
      console.error('Error updating AI config:', error);
      message.error(t('systemConfig.saveError'));
    } finally {
      setLoading(false);
    }
  };

  // 测试威胁情报API配置
  const handleTestThreatIntelConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['api_key']);
      
      // 使用第一个IP进行测试
      message.loading({ content: '正在测试API连接...', key: 'test-api', duration: 0 });
      
      const response = await fetch(`${API_BASE_URL}/test-threat-intel`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ api_key: values.api_key })
      });
      
      const data = await response.json();
      
      if (response.ok && data.success) {
        message.success(`API测试成功: ${data.message}`);
      } else {
        message.error(`API测试失败: ${data.error || '未知错误'}`);
      }
    } catch (error: any) {
      console.error('Error testing threat intel config:', error);
      message.error(`API测试失败: ${error.message || '网络错误'}`);
    } finally {
      setLoading(false);
    }
  };

  // 保存威胁情报配置
  const handleSaveThreatIntelConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['api_key']);
      const response = await fetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      });
      if (response.ok) {
        message.success(t('systemConfig.saveSuccess'));
      } else {
        message.error(t('systemConfig.saveError'));
      }
    } catch (error) {
      console.error('Error updating threat intel config:', error);
      message.error(t('systemConfig.saveError'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <Card title={t('systemConfig.title')} style={{ marginBottom: '24px' }}>
        <Spin spinning={loading}>
          <Form form={form} layout="vertical">
            <Title level={5}>{t('systemConfig.apiConfig')}</Title>
            <Form.Item name="api_url" label={t('systemConfig.apiUrl')} rules={[{ required: true, message: t('systemConfig.apiUrlPlaceholder') }]}>
              <Input placeholder={t('systemConfig.apiUrlPlaceholder')} />
            </Form.Item>
            <Form.Item name="enable_cors" label={t('systemConfig.enableCORS')}>
              <Switch />
            </Form.Item>
            <Form.Item name="allowed_origins" label={t('systemConfig.allowedOrigins')} rules={[{ required: true, message: t('systemConfig.allowedOriginsPlaceholder') }]}>
              <Input placeholder={t('systemConfig.allowedOriginsPlaceholder')} />
            </Form.Item>
            
            <Form.Item>
              <Button type="primary" onClick={handleSaveApiConfig} loading={loading}>
                {t('common.save')}
              </Button>
            </Form.Item>
            
            <Divider />
            <Title level={5}>{t('systemConfig.logConfig')}</Title>
            <Form.Item name="log_retention_days" label={t('systemConfig.retentionDays')} rules={[{ required: true, message: t('systemConfig.retentionDaysPlaceholder') }]}>
              <Input type="number" min={1} max={365} placeholder={t('systemConfig.retentionDaysPlaceholder')} />
            </Form.Item>
            <Form.Item name="max_log_size" label={t('systemConfig.maxLogSize')} rules={[{ required: true, message: t('systemConfig.maxLogSizePlaceholder') }]}>
              <Input type="number" min={1} max={1000} placeholder={t('systemConfig.maxLogSizePlaceholder')} />
            </Form.Item>
            
            <Form.Item>
              <Button type="primary" onClick={handleSaveLogConfig} loading={loading}>
                {t('common.save')}
              </Button>
            </Form.Item>
            
            <Divider />
            <Title level={5}>{t('systemConfig.alertConfig')}</Title>
            <Form.Item name="enable_email_alert" label={t('systemConfig.enableEmailAlert')}>
              <Switch />
            </Form.Item>
            <Form.Item name="email_recipients" label={t('systemConfig.emailRecipients')} rules={[{ required: true, message: t('systemConfig.emailRecipientsPlaceholder') }]}>
              <Input placeholder={t('systemConfig.emailRecipientsPlaceholder')} />
            </Form.Item>
            <Form.Item name="alert_threshold" label={t('systemConfig.alertThreshold')} rules={[{ required: true, message: t('systemConfig.alertThresholdPlaceholder') }]}>
              <Input type="number" min={0} max={1} step={0.1} placeholder={t('systemConfig.alertThresholdPlaceholder')} />
            </Form.Item>
            
            <Form.Item>
              <Button type="primary" onClick={handleSaveAlertConfig} loading={loading}>
                {t('common.save')}
              </Button>
            </Form.Item>
            
            <Divider />
            <Title level={5}>{t('systemConfig.securityConfig')}</Title>
            <Form.Item name="enable_rate_limiting" label={t('systemConfig.enableRateLimiting')}>
              <Switch />
            </Form.Item>
            <Form.Item name="rate_limit" label={t('systemConfig.rateLimit')} rules={[{ required: true, message: t('systemConfig.rateLimitPlaceholder') }]}>
              <Input type="number" min={100} max={10000} placeholder={t('systemConfig.rateLimitPlaceholder')} />
            </Form.Item>
            <Form.Item name="enable_ip_blocking" label={t('systemConfig.enableIpBlocking')}>
              <Switch />
            </Form.Item>
            <Form.Item name="block_duration" label={t('systemConfig.blockDuration')} rules={[{ required: true, message: t('systemConfig.blockDurationPlaceholder') }]}>
              <Input type="number" min={60} max={86400} placeholder={t('systemConfig.blockDurationPlaceholder')} />
            </Form.Item>
            <Form.Item name="enable_ssl" label={t('systemConfig.enableSsl')}>
              <Switch />
            </Form.Item>
            <Form.Item name="ssl_cert_path" label={t('systemConfig.sslCertPath')}>
              <Input placeholder={t('systemConfig.sslCertPathPlaceholder')} />
            </Form.Item>
            <Form.Item name="ssl_key_path" label={t('systemConfig.sslKeyPath')}>
              <Input placeholder={t('systemConfig.sslKeyPathPlaceholder')} />
            </Form.Item>
            
            <Form.Item>
              <Button type="primary" onClick={handleSaveSecurityConfig} loading={loading}>
                {t('common.save')}
              </Button>
            </Form.Item>
            
            <Divider />
            <Title level={5}>{t('systemConfig.aiModelConfig')}</Title>
            <Form.Item name="model_version" label={t('systemConfig.modelVersion')} rules={[{ required: true, message: t('systemConfig.selectModelVersion') }]}>
              <Select placeholder={t('systemConfig.selectModelVersion')}>
                <Option value="1.0.0">1.0.0</Option>
                <Option value="1.1.0">1.1.0</Option>
                <Option value="2.0.0">2.0.0</Option>
              </Select>
            </Form.Item>
            
            <Form.Item>
              <Button type="primary" onClick={handleSaveAiConfig} loading={loading}>
                {t('common.save')}
              </Button>
            </Form.Item>
            
            <Divider />
            <Title level={5}>{t('systemConfig.threatIntelConfig')}</Title>
            <Form.Item name="api_key" label={t('systemConfig.apiKey')} rules={[{ required: true, message: t('systemConfig.apiKeyPlaceholder') }]}>
              <Input.Password placeholder={t('systemConfig.apiKeyPlaceholder')} />
            </Form.Item>
            
            <Form.Item>
              <Button type="primary" onClick={handleTestThreatIntelConfig} loading={loading} icon={<SyncOutlined />}>
                {t('systemConfig.testApi')}
              </Button>
              <span style={{ marginLeft: '8px' }}></span>
              <Button type="primary" onClick={handleSaveThreatIntelConfig} loading={loading}>
                {t('common.save')}
              </Button>
            </Form.Item>
          </Form>
        </Spin>
      </Card>

      <Card title={
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          {t('systemConfig.systemHealth')}
          <span style={{ fontSize: '14px', color: '#1890ff' }}>
            ⚡ {t('systemHealth.realTimeMonitoring')}
          </span>
        </div>
      }>
        {systemHealth ? (
          <div className="card-grid">
            <div className="stat-card">
              <div className="stat-card-title">{t('systemHealth.cpuUsage')}</div>
              <div className="stat-card-value" style={{ 
                color: systemHealth.cpu_usage > 80 ? '#ff4d4f' : systemHealth.cpu_usage > 50 ? '#faad14' : '#1890ff' 
              }}>
                {systemHealth.cpu_usage}%
              </div>
              <div className="progress-bar" style={{ 
                background: systemHealth.cpu_usage > 80 ? '#ffccc7' : systemHealth.cpu_usage > 50 ? '#ffe58f' : '#bae7ff' 
              }}>
                <div className="progress-fill" style={{ 
                  width: `${systemHealth.cpu_usage}%`,
                  background: systemHealth.cpu_usage > 80 ? '#ff4d4f' : systemHealth.cpu_usage > 50 ? '#faad14' : '#1890ff' 
                }}></div>
              </div>
              <div className="stat-card-desc">{t('systemHealth.cpuUtilization')}</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-title">{t('systemHealth.memoryUsage')}</div>
              <div className="stat-card-value" style={{ 
                color: systemHealth.memory_usage > 80 ? '#ff4d4f' : systemHealth.memory_usage > 50 ? '#faad14' : '#1890ff' 
              }}>
                {systemHealth.memory_usage}%
              </div>
              <div className="progress-bar" style={{ 
                background: systemHealth.memory_usage > 80 ? '#ffccc7' : systemHealth.memory_usage > 50 ? '#ffe58f' : '#bae7ff' 
              }}>
                <div className="progress-fill" style={{ 
                  width: `${systemHealth.memory_usage}%`,
                  background: systemHealth.memory_usage > 80 ? '#ff4d4f' : systemHealth.memory_usage > 50 ? '#faad14' : '#1890ff' 
                }}></div>
              </div>
              <div className="stat-card-desc">{t('systemHealth.memoryUtilization')}</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-title">{t('systemHealth.diskUsage')}</div>
              <div className="stat-card-value" style={{ 
                color: systemHealth.disk_usage > 80 ? '#ff4d4f' : systemHealth.disk_usage > 50 ? '#faad14' : '#1890ff' 
              }}>
                {systemHealth.disk_usage}%
              </div>
              <div className="progress-bar" style={{ 
                background: systemHealth.disk_usage > 80 ? '#ffccc7' : systemHealth.disk_usage > 50 ? '#ffe58f' : '#bae7ff' 
              }}>
                <div className="progress-fill" style={{ 
                  width: `${systemHealth.disk_usage}%`,
                  background: systemHealth.disk_usage > 80 ? '#ff4d4f' : systemHealth.disk_usage > 50 ? '#faad14' : '#1890ff' 
                }}></div>
              </div>
              <div className="stat-card-desc">{t('systemHealth.diskUtilization')}</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-title">{t('systemHealth.databaseSize')}</div>
              <div className="stat-card-value">{systemHealth.db_size} MB</div>
              <div className="stat-card-desc">{t('systemHealth.databaseStorage')}</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-title">{t('systemHealth.logCount')}</div>
              <div className="stat-card-value">{systemHealth.log_count}</div>
              <div className="stat-card-desc">{t('systemHealth.totalLogs')}</div>
            </div>
          </div>
        ) : (
          <div className="loading-container">
            <Spin />
          </div>
        )}
      </Card>
    </div>
  );
};

export default SystemConfig;