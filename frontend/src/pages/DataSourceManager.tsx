import React, { useState, useEffect } from 'react';
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
import { Button, Table, Tag, Modal, Form, Input, Select, Switch, Card, Tabs, message, Space, Tooltip } from 'antd';

const API_BASE_URL = 'http://localhost:8006/api';

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
  total_logs_received: number;
  total_logs_processed: number;
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
  const [activeTab, setActiveTab] = useState('list');
  const [sourceLogs] = useState<any[]>([]);
  const [form] = Form.useForm();
  const [sourceType, setSourceType] = useState('syslog');

  useEffect(() => {
    fetchDataSources();
  }, []);

  const fetchDataSources = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/data-sources`);
      const data = await response.json();
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
      const response = await fetch(`${API_BASE_URL}/data-sources`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      const data = await response.json();
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
      const response = await fetch(`${API_BASE_URL}/data-sources/${editingSource.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      const data = await response.json();
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
          await fetch(`${API_BASE_URL}/data-sources/${id}`, {
            method: 'DELETE'
          });
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
      const response = await fetch(`${API_BASE_URL}/data-sources/${id}/start`, {
        method: 'POST'
      });
      const data = await response.json();
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
      const response = await fetch(`${API_BASE_URL}/data-sources/${id}/stop`, {
        method: 'POST'
      });
      const data = await response.json();
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
      const response = await fetch(`${API_BASE_URL}/data-sources/${id}/test`, {
        method: 'POST'
      });
      const data = await response.json();
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
      // 先停止数据源
      const stopResponse = await fetch(`${API_BASE_URL}/data-sources/${id}/stop`, {
        method: 'POST'
      });
      const stopData = await stopResponse.json();
      
      if (!stopData.success) {
        message.error(stopData.error || t('dataSource.stopError'));
        return;
      }
      
      // 然后启动数据源
      const startResponse = await fetch(`${API_BASE_URL}/data-sources/${id}/start`, {
        method: 'POST'
      });
      const startData = await startResponse.json();
      
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

  const openEditModal = (source: DataSource) => {
    setEditingSource(source);
    setSourceType(source.source_type);
    form.setFieldsValue({
      name: source.name,
      source_type: source.source_type,
      enabled: source.enabled,
      syslog_host: source.syslog_host,
      syslog_port: source.syslog_port,
      syslog_protocol: source.syslog_protocol,
      file_path: source.file_path,
      file_format: source.file_format,
      file_encoding: source.file_encoding,
      file_poll_interval: source.file_poll_interval,
      api_url: source.api_url,
      api_method: source.api_method,
      api_auth_type: source.api_auth_type,
      api_poll_interval: source.api_poll_interval,
      log_format: source.log_format,
      log_pattern: source.log_pattern
    });
    setModalVisible(true);
  };

  const openCreateModal = () => {
    setEditingSource(null);
    setSourceType('syslog');
    form.resetFields();
    form.setFieldsValue({
      source_type: 'syslog',
      enabled: true,
      syslog_host: '0.0.0.0',
      syslog_port: 514,
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
          <div>{record.total_logs_received.toLocaleString()} received</div>
          <div>{record.total_logs_processed.toLocaleString()} processed</div>
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

  const logColumns = [
    {
      title: t('dataSource.logs.sourceId'),
      dataIndex: 'source_id',
      key: 'source_id'
    },
    {
      title: t('dataSource.logs.rawLog'),
      dataIndex: 'raw_log',
      key: 'raw_log',
      ellipsis: true
    },
    {
      title: t('dataSource.logs.receivedAt'),
      dataIndex: 'received_at',
      key: 'received_at',
      render: (text: string) => new Date(text).toLocaleString()
    },
    {
      title: t('dataSource.logs.status'),
      dataIndex: 'processed',
      key: 'processed',
      render: (processed: boolean) => processed ? (
        <Tag key="processed" color="success">{t('dataSource.logs.processed')}</Tag>
      ) : (
        <Tag key="pending" color="warning">{t('dataSource.logs.pending')}</Tag>
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
        <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
          {
            key: 'list',
            label: t('dataSource.tab.sources'),
            children: (
              <Table 
                columns={columns} 
                dataSource={dataSources}
                rowKey="id"
                loading={loading}
                locale={{ emptyText: t('dataSource.noSources') }}
              />
            ),
          },
          {
            key: 'logs',
            label: t('dataSource.tab.logs'),
            children: (
              <Table 
                columns={logColumns} 
                dataSource={sourceLogs}
                rowKey="id"
                locale={{ emptyText: t('dataSource.logs.noLogs') }}
              />
            ),
          },
        ]} />
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
              disabled={!!editingSource}
              onChange={(value) => setSourceType(value)}
            >
              <Option value="syslog">{t('dataSource.types.syslog')}</Option>
              <Option value="file">{t('dataSource.form.types.file')}</Option>
              <Option value="api">{t('dataSource.types.api')}</Option>
              <Option value="webhook">{t('dataSource.types.webhook')}</Option>
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
                  POST {API_BASE_URL}/webhook-logs
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
              <Option value="custom">{t('dataSource.form.general.formats.custom')}</Option>
            </Select>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default DataSourceManager;
