import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Card,
  Table,
  Badge,
  Tabs,
  Select,
  Button,
  Row,
  Col,
  Space,
  Tag,
  Alert,
  Empty,
  message
} from 'antd';
import {
  SafetyOutlined,
  ReloadOutlined,
  SettingOutlined,
  WarningOutlined
} from '@ant-design/icons';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8006/api';

const { Option } = Select;

interface AlertItem {
  id: number;
  alert_type: string;
  source_ip: string;
  target_ip: string | null;
  attack_type: string;
  severity: string;
  confidence: number;
  description: string;
  signature: string;
  is_duplicate: boolean;
  is_aggregated: boolean;
  count: number;
  priority_score: number;
  first_seen: string;
  last_seen: string;
  unique_source_ips: string;
  created_at: string;
}

export default function Alerts() {
  const { t } = useTranslation();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    if (!initialized) {
      setInitialized(true);
      loadAlerts();
    }
  }, []);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = new URLSearchParams();
      if (filterSeverity !== 'all') {
        params.append('severity', filterSeverity);
      }
      
      const response = await axios.get(`${API_BASE_URL}/alerts?${params.toString()}`);
      const data = response.data;
      
      if (data.error) {
        throw new Error(data.error);
      }
      
      setAlerts(data.alerts || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts');
      message.error(t('common.error'));
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return '#ff4d4f';
      case 'High':
        return '#ff7a45';
      case 'Medium':
        return '#ffc53d';
      case 'Low':
        return '#1890ff';
      case 'Info':
        return '#8c8c8c';
      default:
        return '#8c8c8c';
    }
  };

  const formatDateTime = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const alertColumns = [
    {
      title: t('alerts.id', 'ID'),
      dataIndex: 'id',
      key: 'id',
      width: 80,
    },
    {
      title: t('alerts.severity', '严重程度'),
      dataIndex: 'severity',
      key: 'severity',
      width: 120,
      render: (severity: string) => (
        <Badge 
          color={getSeverityBadgeColor(severity)}
          text={severity}
        />
      ),
    },
    {
      title: t('alerts.attackType', '攻击类型'),
      dataIndex: 'attack_type',
      key: 'attack_type',
      width: 150,
    },
    {
      title: t('alerts.sourceIP', '源IP'),
      dataIndex: 'source_ip',
      key: 'source_ip',
      width: 140,
      render: (ip: string) => <code style={{ fontSize: '12px' }}>{ip}</code>,
    },
    {
      title: t('alerts.confidence', '置信度'),
      dataIndex: 'confidence',
      key: 'confidence',
      width: 80,
      render: (confidence: number) => (
        <span>{Math.round(confidence * 100)}%</span>
      ),
    },
    {
      title: t('alerts.description', '描述'),
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: t('alerts.status', '状态'),
      key: 'status',
      width: 140,
      render: (_: any, record: AlertItem) => (
        <Space size="small">
          {record.is_duplicate && (
            <Tag key="duplicate" color="default">{t('alerts.duplicate', '重复')}</Tag>
          )}
          {record.is_aggregated && (
            <Tag key="aggregated" color="blue">{t('alerts.aggregated', '聚合')} ({record.count})</Tag>
          )}
        </Space>
      ),
    },
    {
      title: t('alerts.createdAt', '创建时间'),
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date: string) => (
        <span style={{ fontSize: '12px', color: '#8c8c8c' }}>
          {formatDateTime(date)}
        </span>
      ),
    },
  ];

  return (
    <div style={{ padding: '24px' }}>
      <Row justify="space-between" align="middle" style={{ marginBottom: '24px' }}>
        <Col>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <SafetyOutlined style={{ fontSize: '28px' }} />
            {t('alerts.title', '告警管理')}
          </h1>
          <p style={{ color: '#8c8c8c', marginTop: '8px' }}>
            {t('alerts.subtitle', '实时监控和管理安全告警')}
          </p>
        </Col>
        <Col>
          <Space>
            <Button 
              icon={<ReloadOutlined />} 
              onClick={loadAlerts}
            >
              {t('common.refresh', '刷新')}
            </Button>
            <Button icon={<SettingOutlined />}>
              {t('alerts.settings', '设置')}
            </Button>
          </Space>
        </Col>
      </Row>

      {error && (
        <Alert
          message={t('common.error', '错误')}
          description={error}
          type="error"
          showIcon
          style={{ marginBottom: '24px' }}
        />
      )}

      <Tabs 
        defaultActiveKey="alerts"
        items={[
          {
            key: 'alerts',
            label: (
              <span>
                <WarningOutlined />
                {t('alerts.alerts', '告警列表')}
              </span>
            ),
            children: (
              <Card>
                <Row gutter={[16, 16]} style={{ marginBottom: '16px' }}>
                  <Col span={8}>
                    <label style={{ display: 'block', marginBottom: '8px' }}>
                      {t('alerts.severity', '严重程度')}
                    </label>
                    <Select
                      style={{ width: '100%' }}
                      value={filterSeverity}
                      onChange={setFilterSeverity}
                    >
                      <Option value="all">{t('alerts.all', '全部')}</Option>
                      <Option value="Critical">{t('alerts.critical', '严重')}</Option>
                      <Option value="High">{t('alerts.high', '高')}</Option>
                      <Option value="Medium">{t('alerts.medium', '中')}</Option>
                      <Option value="Low">{t('alerts.low', '低')}</Option>
                      <Option value="Info">{t('alerts.info', '信息')}</Option>
                    </Select>
                  </Col>
                </Row>

                <Table
                  columns={alertColumns}
                  dataSource={alerts}
                  rowKey="id"
                  loading={loading}
                  pagination={{
                    pageSize: 20,
                    showSizeChanger: true,
                    showTotal: (total) => `${t('alerts.total', '总计')} ${total} ${t('alerts.items', '条')}`,
                  }}
                  locale={{
                    emptyText: (
                      <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description={t('alerts.noAlerts', '暂无告警')}
                      />
                    ),
                  }}
                />
              </Card>
            )
          }
        ]}
      />
    </div>
  );
}