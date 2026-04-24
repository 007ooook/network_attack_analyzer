import React, { useEffect, useState, useRef } from 'react';
import { Card, Form, Input, Button, message, Select, Switch, Divider, Typography, Spin, Popconfirm, Space, Row, Col, Statistic, Progress, Tag } from 'antd';
import { useTranslation } from 'react-i18next';
import { SyncOutlined, DeleteOutlined, SaveOutlined, DashboardOutlined, CloudServerOutlined, DatabaseOutlined, FileTextOutlined, CheckCircleOutlined, SafetyOutlined, LockOutlined } from '@ant-design/icons';
import { api } from '../utils/api';

const { Option } = Select;
const { Title } = Typography;

const SystemConfig: React.FC = () => {
  const [form] = Form.useForm();
  const [securityForm] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [systemHealth, setSystemHealth] = useState<any>({
    cpu_usage: 0,
    memory_usage: 0,
    disk_usage: 0,
    db_size: 0,
    log_count: 0
  });
  const { t } = useTranslation();
  const healthTimerRef = useRef<number | null>(null);

  const DEFAULT_CONFIG = {
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
  };

  const loadConfig = async () => {
    try {
      setLoading(true);
      const { data } = await api.get('/config');
      form.setFieldsValue(data.config || DEFAULT_CONFIG);
    } catch (error) {
      console.error('Error loading config:', error);
      message.error(t('common.error'));
      form.setFieldsValue(DEFAULT_CONFIG);
    } finally {
      setLoading(false);
    }
  };

  const loadSystemHealth = async () => {
    try {
      const { data } = await api.get('/system-health');
      setSystemHealth(data);
    } catch (error) {
      console.error('Error loading system health:', error);
      setSystemHealth({ cpu_usage: 0, memory_usage: 0, disk_usage: 0, db_size: 0, log_count: 0 });
    }
  };

  const loadSecurityConfig = async () => {
    try {
      const { data } = await api.get('/security-config');
      if (data.success) {
        securityForm.setFieldsValue(data.config);
      }
    } catch (error) {
      console.error('Error loading security config:', error);
    }
  };

  const handleSaveAccountSecurityConfig = async () => {
    try {
      setLoading(true);
      const values = await securityForm.validateFields();
      const { data } = await api.post('/security-config', values);
      if (data.success) {
        message.success('账号安全配置已保存');
      } else {
        message.error(data.error || '保存失败');
      }
    } catch (error) {
      console.error('Error saving security config:', error);
      message.error('保存失败');
    } finally {
      setLoading(false);
    }
  };

  // 初始化加载数据
  useEffect(() => {
    loadConfig();
    loadSystemHealth();
    loadSecurityConfig();
    
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

  const handleResetConfig = async (section: string) => {
    try {
      setLoading(true);
      const { data } = await api.post('/config/reset', { section });
      if (data.success) {
        message.success(`${section}配置已重置为默认值`);
        loadConfig();
      } else {
        message.error(data.error || '重置失败');
      }
    } catch (error) {
      console.error('Error resetting config:', error);
      message.error('重置失败');
    } finally {
      setLoading(false);
    }
  };

  const postConfig = async (fields: string[], successMsg: string) => {
    try {
      setLoading(true);
      const values = await form.validateFields(fields);
      await api.post('/config', values);
      message.success(successMsg);
    } catch (error) {
      console.error('Error updating config:', error);
      message.error(t('systemConfig.saveError'));
    } finally {
      setLoading(false);
    }
  };

  const handleSaveApiConfig = () => postConfig(['api_url', 'enable_cors', 'allowed_origins'], t('systemConfig.saveSuccess'));
  const handleSaveLogConfig = () => postConfig(['log_retention_days', 'max_log_size'], t('systemConfig.saveSuccess'));
  const handleSaveAlertConfig = () => postConfig(['enable_email_alert', 'email_recipients', 'alert_threshold'], t('systemConfig.saveSuccess'));
  const handleSaveSecurityConfig = () => postConfig(['enable_rate_limiting', 'rate_limit', 'enable_ip_blocking', 'block_duration', 'enable_ssl', 'ssl_cert_path', 'ssl_key_path'], t('systemConfig.saveSuccess'));
  const handleSaveAiConfig = () => postConfig(['model_version'], t('systemConfig.saveSuccess'));
  const handleSaveThreatIntelConfig = () => postConfig(['api_key'], t('systemConfig.saveSuccess'));

  const handleTestThreatIntelConfig = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields(['api_key']);
      message.loading({ content: '正在测试API连接...', key: 'test-api', duration: 0 });
      const { data } = await api.post('/test-threat-intel', { api_key: values.api_key });
      if (data.success) {
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
              <Space>
                <Button type="primary" onClick={handleSaveApiConfig} loading={loading} icon={<SaveOutlined />}>
                  {t('common.save')}
                </Button>
                <Popconfirm title="确定要重置API配置为默认值吗？" onConfirm={() => handleResetConfig('api')} okText="确定" cancelText="取消">
                  <Button type="primary" icon={<DeleteOutlined />}>重置配置</Button>
                </Popconfirm>
              </Space>
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
              <Space>
                <Button type="primary" onClick={handleSaveLogConfig} loading={loading} icon={<SaveOutlined />}>
                  {t('common.save')}
                </Button>
                <Popconfirm title="确定要重置日志配置为默认值吗？" onConfirm={() => handleResetConfig('log')} okText="确定" cancelText="取消">
                  <Button type="primary" icon={<DeleteOutlined />}>重置配置</Button>
                </Popconfirm>
              </Space>
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
              <Space>
                <Button type="primary" onClick={handleSaveAlertConfig} loading={loading} icon={<SaveOutlined />}>
                  {t('common.save')}
                </Button>
                <Popconfirm title="确定要重置告警配置为默认值吗？" onConfirm={() => handleResetConfig('alert')} okText="确定" cancelText="取消">
                  <Button type="primary" icon={<DeleteOutlined />}>重置配置</Button>
                </Popconfirm>
              </Space>
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
              <Space>
                <Button type="primary" onClick={handleSaveSecurityConfig} loading={loading} icon={<SaveOutlined />}>
                  {t('common.save')}
                </Button>
                <Popconfirm title="确定要重置安全配置为默认值吗？" onConfirm={() => handleResetConfig('security')} okText="确定" cancelText="取消">
                  <Button type="primary" icon={<DeleteOutlined />}>重置配置</Button>
                </Popconfirm>
              </Space>
            </Form.Item>
            
            <Divider />
            <Title level={5}><SafetyOutlined style={{ marginRight: 8, color: '#1890ff' }} />账号安全配置</Title>
            <Card size="small" style={{ background: '#fafafa', marginBottom: 16 }}>
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12, color: '#333' }}>
                  <LockOutlined style={{ marginRight: 6, color: '#1890ff' }} />密码复杂度要求
                </div>
                <Row gutter={[16, 16]}>
                  <Col span={12}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="password_min_length" label="密码最小长度" rules={[{ required: true, message: '请输入密码最小长度' }]}>
                        <Input type="number" min={4} max={32} placeholder="8" />
                      </Form.Item>
                    </Form>
                  </Col>
                  <Col span={12}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="password_history_count" label="密码历史数量" rules={[{ required: true, message: '请输入密码历史数量' }]}>
                        <Input type="number" min={0} max={10} placeholder="3" />
                      </Form.Item>
                    </Form>
                  </Col>
                </Row>
                <Row gutter={[16, 16]}>
                  <Col span={6}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="password_require_uppercase" label="要求大写字母" valuePropName="checked">
                        <Switch checkedChildren="是" unCheckedChildren="否" />
                      </Form.Item>
                    </Form>
                  </Col>
                  <Col span={6}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="password_require_lowercase" label="要求小写字母" valuePropName="checked">
                        <Switch checkedChildren="是" unCheckedChildren="否" />
                      </Form.Item>
                    </Form>
                  </Col>
                  <Col span={6}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="password_require_digit" label="要求数字" valuePropName="checked">
                        <Switch checkedChildren="是" unCheckedChildren="否" />
                      </Form.Item>
                    </Form>
                  </Col>
                  <Col span={6}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="password_require_special" label="要求特殊字符" valuePropName="checked">
                        <Switch checkedChildren="是" unCheckedChildren="否" />
                      </Form.Item>
                    </Form>
                  </Col>
                </Row>
              </div>
            </Card>
            <Card size="small" style={{ background: '#fafafa', marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12, color: '#333' }}>
                  <SafetyOutlined style={{ marginRight: 6, color: '#1890ff' }} />登录安全策略
                </div>
                <Row gutter={[16, 16]}>
                  <Col span={8}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="max_login_attempts" label="最大登录尝试次数" rules={[{ required: true, message: '请输入最大登录尝试次数' }]}>
                        <Input type="number" min={1} max={20} placeholder="5" />
                      </Form.Item>
                    </Form>
                  </Col>
                  <Col span={8}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="lockout_duration" label="锁定时长（秒）" rules={[{ required: true, message: '请输入锁定时长' }]}>
                        <Input type="number" min={60} max={86400} placeholder="900" />
                      </Form.Item>
                    </Form>
                  </Col>
                  <Col span={8}>
                    <Form form={securityForm} layout="vertical">
                      <Form.Item name="session_timeout" label="会话超时（秒）" rules={[{ required: true, message: '请输入会话超时时间' }]}>
                        <Input type="number" min={300} max={86400} placeholder="3600" />
                      </Form.Item>
                    </Form>
                  </Col>
                </Row>
              </div>
            </Card>
            
            <Form.Item>
              <Space>
                <Button type="primary" onClick={handleSaveAccountSecurityConfig} loading={loading} icon={<SaveOutlined />}>
                  {t('common.save')}
                </Button>
              </Space>
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
              <Space>
                <Button type="primary" onClick={handleSaveAiConfig} loading={loading} icon={<SaveOutlined />}>
                  {t('common.save')}
                </Button>
                <Popconfirm title="确定要重置AI模型配置为默认值吗？" onConfirm={() => handleResetConfig('ai')} okText="确定" cancelText="取消">
                  <Button type="primary" icon={<DeleteOutlined />}>重置配置</Button>
                </Popconfirm>
              </Space>
            </Form.Item>
            
            <Divider />
            <Title level={5}>{t('systemConfig.threatIntelConfig')}</Title>
            <Form.Item name="api_key" label={t('systemConfig.apiKey')} rules={[{ required: true, message: t('systemConfig.apiKeyPlaceholder') }]}>
              <Input.Password placeholder={t('systemConfig.apiKeyPlaceholder')} />
            </Form.Item>
            
            <Form.Item>
              <Space>
                <Button type="primary" onClick={handleTestThreatIntelConfig} loading={loading} icon={<SyncOutlined />}>
                  {t('systemConfig.testApi')}
                </Button>
                <Button type="primary" onClick={handleSaveThreatIntelConfig} loading={loading} icon={<SaveOutlined />}>
                  {t('common.save')}
                </Button>
                <Popconfirm title="确定要重置威胁情报配置为默认值吗？" onConfirm={() => handleResetConfig('threat_intel')} okText="确定" cancelText="取消">
                  <Button type="primary" icon={<DeleteOutlined />}>重置配置</Button>
                </Popconfirm>
              </Space>
            </Form.Item>
          </Form>
        </Spin>
      </Card>

      <Card 
        title={t('systemConfig.systemHealth')} 
        extra={
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Tag icon={<CheckCircleOutlined />} color="success">运行中</Tag>
            <Button type="primary" onClick={loadSystemHealth} icon={<SyncOutlined />} size="small">
              刷新
            </Button>
          </div>
        }
      >
        <Row gutter={[24, 24]}>
          <Col xs={24} sm={8}>
            <div style={{ padding: '16px 0' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 14, color: '#666' }}>
                  <DashboardOutlined style={{ marginRight: 8, color: '#1890ff' }} />
                  {t('systemHealth.cpuUsage')}
                </span>
                <span style={{ fontSize: 24, fontWeight: 600, color: systemHealth.cpu_usage > 80 ? '#ff4d4f' : systemHealth.cpu_usage > 50 ? '#faad14' : '#52c41a' }}>
                  {systemHealth.cpu_usage}%
                </span>
              </div>
              <Progress percent={systemHealth.cpu_usage} showInfo={false} strokeColor={{ '0%': '#1890ff', '100%': systemHealth.cpu_usage > 80 ? '#ff4d4f' : '#52c41a' }} />
            </div>
          </Col>
          <Col xs={24} sm={8}>
            <div style={{ padding: '16px 0' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 14, color: '#666' }}>
                  <CloudServerOutlined style={{ marginRight: 8, color: '#722ed1' }} />
                  {t('systemHealth.memoryUsage')}
                </span>
                <span style={{ fontSize: 24, fontWeight: 600, color: systemHealth.memory_usage > 80 ? '#ff4d4f' : systemHealth.memory_usage > 50 ? '#faad14' : '#52c41a' }}>
                  {systemHealth.memory_usage}%
                </span>
              </div>
              <Progress percent={systemHealth.memory_usage} showInfo={false} strokeColor={{ '0%': '#722ed1', '100%': systemHealth.memory_usage > 80 ? '#ff4d4f' : '#52c41a' }} />
            </div>
          </Col>
          <Col xs={24} sm={8}>
            <div style={{ padding: '16px 0' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 14, color: '#666' }}>
                  <DatabaseOutlined style={{ marginRight: 8, color: '#13c2c2' }} />
                  {t('systemHealth.diskUsage')}
                </span>
                <span style={{ fontSize: 24, fontWeight: 600, color: systemHealth.disk_usage > 80 ? '#ff4d4f' : systemHealth.disk_usage > 50 ? '#faad14' : '#52c41a' }}>
                  {systemHealth.disk_usage}%
                </span>
              </div>
              <Progress percent={systemHealth.disk_usage} showInfo={false} strokeColor={{ '0%': '#13c2c2', '100%': systemHealth.disk_usage > 80 ? '#ff4d4f' : '#52c41a' }} />
            </div>
          </Col>
        </Row>
        <Divider style={{ margin: '12px 0' }} />
        <Row gutter={[24, 16]}>
          <Col xs={12} sm={8}>
            <Statistic
              title={t('systemHealth.databaseSize')}
              value={systemHealth.db_size}
              suffix="MB"
              prefix={<DatabaseOutlined />}
              valueStyle={{ fontSize: 20 }}
            />
          </Col>
          <Col xs={12} sm={8}>
            <Statistic
              title={t('systemHealth.logCount')}
              value={systemHealth.log_count}
              prefix={<FileTextOutlined />}
              valueStyle={{ fontSize: 20 }}
            />
          </Col>
          <Col xs={24} sm={8}>
            <div style={{ textAlign: 'center' }}>
              <Tag color="processing" style={{ fontSize: 12, padding: '4px 8px' }}>
                3秒自动刷新
              </Tag>
            </div>
          </Col>
        </Row>
      </Card>
    </div>
  );
};

export default SystemConfig;