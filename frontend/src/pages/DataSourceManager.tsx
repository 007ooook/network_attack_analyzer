import React, { useState, useEffect } from 'react';
import { api } from '../utils/api';
import { useTranslation } from 'react-i18next';
import { 
  PlusOutlined, 
  CaretRightOutlined, 
  BorderOutlined, 
  SettingOutlined, 
  DeleteOutlined, 
  SyncOutlined, 
  FileTextOutlined, 
  GlobalOutlined, 
  DatabaseOutlined, 
  AlertOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  DashboardOutlined,
  ApiOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import { Button, Table, Tag, Modal, Form, Input, Select, Switch, Card, message, Space, Tooltip } from 'antd';

interface DataSource {
  id: number;
  name: string;
  source_type: string;
  enabled: boolean;
  status: string;
  created_at: string;
  updated_at: string;
  last_error: string;
  last_connected_at: string;
  last_log_received: string;
  last_source_ip: string;
  total_logs_received: number;
  total_logs_processed: number;
  // 实时统计
  recent_logs_5m?: number;
  threat_count?: number;
  // Syslog配置
  syslog_host?: string;
  syslog_port?: number;
  syslog_protocol?: string;
  // 文件配置
  file_path?: string;
  file_format?: string;
  file_encoding?: string;
  file_poll_interval?: number;
  // API配置
  api_url?: string;
  api_method?: string;
  api_headers?: string;
  api_auth_type?: string;
  api_poll_interval?: number;
  // Webhook配置
  webhook_secret?: string;
  webhook_verify_signature?: boolean;
  // 通用配置
  log_format?: string;
  log_pattern?: string;
  field_mapping?: string;
  filters?: string;
}

const { Option } = Select;

const DataSourceManager: React.FC = () => {
  const { t } = useTranslation();
  const [dataSources, setDataSources] = useState<DataSource[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [editingSource, setEditingSource] = useState<DataSource | null>(null);
  const [form] = Form.useForm();
  const [sourceType, setSourceType] = useState('syslog');

  useEffect(() => {
    fetchDataSources();
    
    // 启动实时轮询
    const interval = setInterval(() => {
      fetchDataSources();
    }, 5000); // 每5秒刷新一次
    
    return () => clearInterval(interval);
  }, []);

  const fetchDataSources = async () => {
    try {
      setLoading(true);
      const { data } = await api.get('/data-sources');
      if (data.sources) {
        setDataSources(data.sources);
      }
    } catch (error) {
      console.error('Error fetching data sources:', error);
      message.error(t('dataSource.fetchError'));
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (values: any) => {
    try {
      const { data } = await api.post('/data-sources', values);
      if (data.success) {
        message.success(t('dataSource.createSuccess'));
        setModalVisible(false);
        form.resetFields();
        fetchDataSources();
      } else {
        message.error(data.error || t('dataSource.createError'));
      }
    } catch (error) {
      console.error('Error creating data source:', error);
      message.error(t('dataSource.createError'));
    }
  };

  const handleUpdate = async (values: any) => {
    if (!editingSource) return;
    
    try {
      const { data } = await api.post(`/data-sources/${editingSource.id}`, values);
      if (data.success) {
        message.success(t('dataSource.updateSuccess'));
        setModalVisible(false);
        setEditingSource(null);
        form.resetFields();
        fetchDataSources();
      } else {
        message.error(data.error || t('dataSource.updateError'));
      }
    } catch (error) {
      console.error('Error updating data source:', error);
      message.error(t('dataSource.updateError'));
    }
  };

  const handleDelete = async (id: number) => {
    Modal.confirm({
      title: t('dataSource.confirmDelete'),
      onOk: async () => {
        try {
          await api.delete(`/data-sources/${id}`);
          message.success(t('dataSource.deleteSuccess'));
          fetchDataSources();
        } catch (error) {
          console.error('Error deleting data source:', error);
          message.error(t('dataSource.deleteError'));
        }
      }
    });
  };

  const handleStart = async (id: number) => {
    try {
      const { data } = await api.post(`/data-sources/${id}/start`);
      if (data.success) {
        message.success(t('dataSource.startSuccess'));
        fetchDataSources();
      } else {
        message.error(data.error || t('dataSource.startError'));
      }
    } catch (error) {
      console.error('Error starting data source:', error);
      message.error(t('dataSource.startError'));
    }
  };

  const handleStop = async (id: number) => {
    try {
      const { data } = await api.post(`/data-sources/${id}/stop`);
      if (data.success) {
        message.success(t('dataSource.stopSuccess'));
        fetchDataSources();
      } else {
        message.error(data.error || t('dataSource.stopError'));
      }
    } catch (error) {
      console.error('Error stopping data source:', error);
      message.error(t('dataSource.stopError'));
    }
  };

  const handleTest = async (id: number) => {
    try {
      const { data } = await api.post(`/data-sources/${id}/test`);
      if (data.success) {
        message.success(data.message);
      } else {
        message.error(data.message);
      }
    } catch (error) {
      console.error('Error testing data source:', error);
      message.error(t('dataSource.testError'));
    }
  };

  const handleRestart = async (id: number) => {
    try {
      const stopData = (await api.post(`/data-sources/${id}/stop`)).data;
      
      if (!stopData.success) {
        message.error(stopData.error || t('dataSource.stopError'));
        return;
      }
      
      const startData = (await api.post(`/data-sources/${id}/start`)).data;
      
      if (startData.success) {
        message.success(t('dataSource.restartSuccess'));
        fetchDataSources();
      } else {
        message.error(startData.error || t('dataSource.startError'));
      }
    } catch (error) {
      console.error('Error restarting data source:', error);
      message.error(t('dataSource.restartError'));
    }
  };

  const openEditModal = async (source: DataSource) => {
    try {
      setLoading(true);
      const { data } = await api.get(`/data-sources/${source.id}`);
      if (data.source) {
        const fullSource = data.source;
        setEditingSource(fullSource);
        setSourceType(fullSource.source_type);
        form.setFieldsValue({
          name: fullSource.name,
          source_type: fullSource.source_type,
          enabled: fullSource.enabled,
          syslog_host: fullSource.syslog_host,
          syslog_port: fullSource.syslog_port,
          syslog_protocol: fullSource.syslog_protocol,
          file_path: fullSource.file_path,
          file_format: fullSource.file_format,
          file_encoding: fullSource.file_encoding,
          file_poll_interval: fullSource.file_poll_interval,
          api_url: fullSource.api_url,
          api_method: fullSource.api_method,
          api_auth_type: fullSource.api_auth_type,
          api_poll_interval: fullSource.api_poll_interval,
          log_format: fullSource.log_format,
          log_pattern: fullSource.log_pattern
        });
        setModalVisible(true);
      }
    } catch (error) {
      console.error('Error fetching data source details:', error);
      message.error(t('dataSource.fetchError'));
    } finally {
      setLoading(false);
    }
  };

  const openCreateModal = () => {
    setEditingSource(null);
    setSourceType('syslog');
    form.resetFields();
    form.setFieldsValue({
      source_type: 'syslog',
      enabled: true,
      syslog_host: '0.0.0.0',
      syslog_port: 1514,
      syslog_protocol: 'udp',
      file_format: 'auto',
      file_encoding: 'utf-8',
      file_poll_interval: 5,
      api_method: 'GET',
      api_auth_type: 'none',
      api_poll_interval: 60,
      log_format: 'auto'
    });
    setModalVisible(true);
  };

  const getSourceTypeIcon = (type: string) => {
    switch (type) {
      case 'syslog':
        return <DatabaseOutlined />;
      case 'file':
        return <FileTextOutlined />;
      case 'api':
        return <ApiOutlined />;
      case 'webhook':
        return <GlobalOutlined />;
      default:
        return <DashboardOutlined />;
    }
  };

  const getStatusTag = (status: string) => {
    switch (status) {
      case 'active':
        return <Tag key="active" icon={<CheckCircleOutlined />} color="success">{t('dataSource.status.active')}</Tag>;
      case 'inactive':
        return <Tag key="inactive" icon={<CloseCircleOutlined />} color="default">{t('dataSource.status.inactive')}</Tag>;
      case 'error':
        return <Tag key="error" icon={<AlertOutlined />} color="error">{t('dataSource.status.error')}</Tag>;
      case 'connecting':
        return <Tag key="connecting" icon={<SyncOutlined spin />} color="warning">{t('dataSource.status.connecting')}</Tag>;
      default:
        return <Tag key="default">{status}</Tag>;
    }
  };

  const columns = [
    {
      title: t('dataSource.table.name'),
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: DataSource) => (
        <Space>
          <span style={{ fontSize: 18, color: '#1890ff' }}>{getSourceTypeIcon(record.source_type)}</span>
          <div>
            <div style={{ fontWeight: 500 }}>{text}</div>
            <div style={{ fontSize: 12, color: '#999' }}>{t('dataSource.table.id')}: {record.id}</div>
          </div>
        </Space>
      )
    },
    {
      title: t('dataSource.table.type'),
      dataIndex: 'source_type',
      key: 'source_type',
      render: (type: string) => (
        <Tag key={`type-${type}`} color="blue">{t(`dataSource.types.${type}`)}</Tag>
      )
    },
    {
      title: t('dataSource.table.status'),
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => getStatusTag(status)
    },
    {
      title: t('dataSource.table.logs'),
      key: 'logs',
      render: (record: DataSource) => (
        <div style={{ fontSize: 13 }}>
          <div style={{ fontWeight: 500 }}>
            <span style={{ color: '#1890ff' }}>{record.total_logs_received.toLocaleString()}</span> 
            {t('dataSource.logs.total')}
          </div>
          <div>
            <span style={{ color: '#52c41a' }}>{record.recent_logs_5m?.toLocaleString() || 0}</span> 
            {t('dataSource.logs.recent5m')}
          </div>
          {record.threat_count && record.threat_count > 0 && (
            <div style={{ color: '#ff4d4f', fontWeight: 500 }}>
              <span style={{ color: '#ff4d4f' }}>{record.threat_count}</span> 
              {t('dataSource.logs.threats')}
            </div>
          )}
        </div>
      )
    },
    {
      title: t('dataSource.table.lastConnected'),
      dataIndex: 'last_connected_at',
      key: 'last_connected_at',
      render: (text: string) => text ? new Date(text).toLocaleString() : t('dataSource.never')
    },
    {
      title: t('dataSource.table.lastLogReceived'),
      dataIndex: 'last_log_received',
      key: 'last_log_received',
      render: (text: string) => {
        if (!text) return t('dataSource.never');
        const now = new Date();
        const lastLogTime = new Date(text);
        const diffMs = now.getTime() - lastLogTime.getTime();
        const diffMins = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        
        if (diffMins < 1) return t('dataSource.justNow');
        if (diffMins < 60) return `${diffMins} ${t('dataSource.minutesAgo')}`;
        if (diffHours < 24) return `${diffHours} ${t('dataSource.hoursAgo')}`;
        if (diffDays < 7) return `${diffDays} ${t('dataSource.daysAgo')}`;
        return lastLogTime.toLocaleString();
      }
    },
    {
      title: t('dataSource.table.lastSourceIP'),
      dataIndex: 'last_source_ip',
      key: 'last_source_ip',
      render: (text: string) => {
        if (!text) return t('dataSource.unknown');
        return (
          <Tag color="blue" style={{ borderRadius: '12px', padding: '0 12px' }}>
            {text}
          </Tag>
        );
      }
    },
    {
      title: t('dataSource.table.actions'),
      key: 'actions',
      render: (record: DataSource) => (
        <Space>
          {record.status === 'active' ? (
            <Tooltip title={t('dataSource.actions.stop')}>
              <Button 
                icon={<BorderOutlined />} 
                onClick={() => handleStop(record.id)}
                size="small"
              />
            </Tooltip>
          ) : (
            <Tooltip title={t('dataSource.actions.start')}>
              <Button 
                icon={<CaretRightOutlined />} 
                type="primary"
                onClick={() => handleStart(record.id)}
                size="small"
                disabled={!record.enabled}
              />
            </Tooltip>
          )}
          <Tooltip title={t('dataSource.actions.restart')}>
            <Button 
              icon={<ReloadOutlined />} 
              onClick={() => handleRestart(record.id)}
              size="small"
              disabled={!record.enabled}
            />
          </Tooltip>
          <Tooltip title={t('dataSource.actions.test')}>
            <Button 
              icon={<DashboardOutlined />} 
              onClick={() => handleTest(record.id)}
              size="small"
            />
          </Tooltip>
          <Tooltip title={t('dataSource.actions.edit')}>
            <Button 
              icon={<SettingOutlined />} 
              onClick={() => openEditModal(record)}
              size="small"
            />
          </Tooltip>
          <Tooltip title={t('dataSource.actions.delete')}>
            <Button 
              icon={<DeleteOutlined />} 
              danger
              onClick={() => handleDelete(record.id)}
              size="small"
            />
          </Tooltip>
        </Space>
      )
    }
  ];



  return (
    <div style={{ padding: 24 }}>
      <Card 
        title={<h2 style={{ margin: 0 }}>{t('dataSource.title')}</h2>}
        extra={
          <Button 
            type="primary" 
            icon={<PlusOutlined />}
            onClick={openCreateModal}
          >
            {t('dataSource.addNew')}
          </Button>
        }
      >
        <Table 
          columns={columns} 
          dataSource={dataSources}
          rowKey="id"
          loading={loading}
          locale={{ emptyText: t('dataSource.noSources') }}
        />
      </Card>

      <Modal
        title={editingSource ? t('dataSource.modal.edit') : t('dataSource.modal.create')}
        open={modalVisible}
        onCancel={() => {
          setModalVisible(false);
          setEditingSource(null);
          form.resetFields();
        }}
        onOk={() => form.submit()}
        width={700}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={editingSource ? handleUpdate : handleCreate}
        >
          <Form.Item
            name="name"
            label={t('dataSource.form.name')}
            rules={[{ required: true, message: t('dataSource.form.nameRequired') }]}
          >
            <Input placeholder={t('dataSource.form.namePlaceholder')} />
          </Form.Item>

          <Form.Item
            name="source_type"
            label={t('dataSource.form.type')}
            rules={[{ required: true }]}
          >
            <Select 
              onChange={(value) => setSourceType(value)}
            >
              <Option value="syslog">{t('dataSource.types.syslog')}</Option>
              <Option value="file">{t('dataSource.form.types.file')}</Option>
              <Option value="api">{t('dataSource.types.api')}</Option>
              <Option value="webhook">{t('dataSource.types.webhook')}</Option>
              <Option value="kafka">Kafka</Option>
              <Option value="redis">Redis</Option>
              <Option value="elk">ELK Stack</Option>
              <Option value="splunk">Splunk</Option>
              <Option value="graylog">Graylog</Option>
            </Select>
          </Form.Item>

          <Form.Item
            name="enabled"
            valuePropName="checked"
          >
            <Switch checkedChildren={t('common.yes')} unCheckedChildren={t('common.no')} />
          </Form.Item>

          {sourceType === 'syslog' && (
            <>
              <Form.Item label={t('dataSource.form.syslog.title')} style={{ marginBottom: 8 }}>
                <div style={{ borderBottom: '1px solid #f0f0f0', marginBottom: 16 }} />
              </Form.Item>
              <Form.Item
                name="syslog_host"
                label={t('dataSource.form.syslog.host')}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="syslog_port"
                label={t('dataSource.form.syslog.port')}
                rules={[
                  { required: true, message: t('dataSource.form.syslog.portRequired') },
                  {
                    validator: (_, value) => {
                      const port = Number(value);
                      if (isNaN(port) || port < 1 || port > 65535) {
                        return Promise.reject(new Error(t('dataSource.form.syslog.portRange')));
                      }
                      return Promise.resolve();
                    }
                  }
                ]}
              >
                <Input type="number" />
              </Form.Item>
              <Form.Item
                name="syslog_protocol"
                label={t('dataSource.form.syslog.protocol')}
              >
                <Select>
                  <Option value="udp">{t('dataSource.form.syslog.protocols.udp')}</Option>
                  <Option value="tcp">{t('dataSource.form.syslog.protocols.tcp')}</Option>
                </Select>
              </Form.Item>
            </>
          )}

          {sourceType === 'file' && (
            <>
              <Form.Item label={t('dataSource.form.file.title')} style={{ marginBottom: 8 }}>
                <div style={{ borderBottom: '1px solid #f0f0f0', marginBottom: 16 }} />
              </Form.Item>
              <Form.Item
                name="file_path"
                label={t('dataSource.form.file.path')}
                rules={[{ required: true }]}
              >
                <Input placeholder={t('dataSource.form.file.pathPlaceholder')} />
              </Form.Item>
              <Form.Item
                name="file_format"
                label={t('dataSource.form.file.format')}
              >
                <Select>
                  <Option value="auto">{t('dataSource.form.file.formats.auto')}</Option>
                  <Option value="apache">{t('dataSource.form.general.formats.apache')}</Option>
                  <Option value="nginx">{t('dataSource.form.general.formats.nginx')}</Option>
                  <Option value="syslog">{t('dataSource.form.general.formats.syslog')}</Option>
                  <Option value="json">{t('dataSource.form.general.formats.json')}</Option>
                </Select>
              </Form.Item>
              <Form.Item
                name="file_encoding"
                label={t('dataSource.form.file.encoding')}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="file_poll_interval"
                label={t('dataSource.form.file.interval')}
              >
                <Input type="number" suffix={t('dataSource.form.file.intervalSuffix')} />
              </Form.Item>
            </>
          )}

          {sourceType === 'api' && (
            <>
              <Form.Item label={t('dataSource.form.api.title')} style={{ marginBottom: 8 }}>
                <div style={{ borderBottom: '1px solid #f0f0f0', marginBottom: 16 }} />
              </Form.Item>
              <Form.Item
                name="api_url"
                label={t('dataSource.form.api.url')}
                rules={[{ required: true }]}
              >
                <Input placeholder={t('dataSource.form.api.urlPlaceholder')} />
              </Form.Item>
              <Form.Item
                name="api_method"
                label={t('dataSource.form.api.method')}
              >
                <Select>
                  <Option value="GET">{t('dataSource.form.api.methods.GET')}</Option>
                  <Option value="POST">{t('dataSource.form.api.methods.POST')}</Option>
                </Select>
              </Form.Item>
              <Form.Item
                name="api_auth_type"
                label={t('dataSource.form.api.authType')}
              >
                <Select>
                  <Option value="none">{t('dataSource.form.api.authTypes.none')}</Option>
                  <Option value="basic">{t('dataSource.form.api.authTypes.basic')}</Option>
                  <Option value="bearer">{t('dataSource.form.api.authTypes.bearer')}</Option>
                  <Option value="apikey">{t('dataSource.form.api.authTypes.apikey')}</Option>
                </Select>
              </Form.Item>
              <Form.Item
                name="api_poll_interval"
                label={t('dataSource.form.api.interval')}
              >
                <Input type="number" suffix={t('dataSource.form.api.intervalSuffix')} />
              </Form.Item>
            </>
          )}

          {sourceType === 'webhook' && (
            <>
              <Form.Item label={t('dataSource.form.webhook.title')} style={{ marginBottom: 8 }}>
                <div style={{ borderBottom: '1px solid #f0f0f0', marginBottom: 16 }} />
              </Form.Item>
              <div style={{ background: '#f6ffed', padding: 16, borderRadius: 4, marginBottom: 16 }}>
                <p style={{ marginBottom: 8 }}>{t('dataSource.form.webhook.description')}</p>
                <code style={{ background: '#1f1f1f', color: '#52c41a', padding: '8px 12px', borderRadius: 4, display: 'block' }}>
                  POST http://localhost:65534/api/webhook-logs
                </code>
                <p style={{ marginTop: 8, marginBottom: 0 }}>
                  {t('dataSource.form.webhook.header')}: <code>X-Data-Source: webhook</code>
                </p>
              </div>
            </>
          )}

          <Form.Item label={t('dataSource.form.general.title')} style={{ marginBottom: 8 }}>
            <div style={{ borderBottom: '1px solid #f0f0f0', marginBottom: 16 }} />
          </Form.Item>
          <Form.Item
            name="log_format"
            label={t('dataSource.form.general.logFormat')}
          >
            <Select>
              <Option value="auto">{t('dataSource.form.general.formats.auto')}</Option>
              <Option value="apache">{t('dataSource.form.general.formats.apache')}</Option>
              <Option value="nginx">{t('dataSource.form.general.formats.nginx')}</Option>
              <Option value="syslog">{t('dataSource.form.general.formats.syslog')}</Option>
              <Option value="json">{t('dataSource.form.general.formats.json')}</Option>
              <Option value="csv">CSV</Option>
              <Option value="custom">{t('dataSource.form.general.formats.custom')}</Option>
            </Select>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default DataSourceManager;
