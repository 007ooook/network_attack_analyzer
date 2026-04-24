import React, { useState, useEffect } from 'react';
import { Card, Table, Spin, message, Typography, Modal, Descriptions, Button, DatePicker, Input, Space } from 'antd';
import { api } from '../utils/api';
import { useTranslation } from 'react-i18next';

const { RangePicker } = DatePicker;
const { Search } = Input;

const { Title, Text, Link } = Typography;

const DataSourceLogs: React.FC = () => {
  const [dataSources, setDataSources] = useState<any[]>([]);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0
  });
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const [logDetailModalVisible, setLogDetailModalVisible] = useState(false);
  const [filters, setFilters] = useState<{
    timeRange: any,
    keyword: string,
    ip: string
  }>({
    timeRange: null,
    keyword: '',
    ip: ''
  });
  const { t } = useTranslation();

  // 加载数据源列表
  const loadDataSources = async () => {
    try {
      const response = await api.get('/data-sources');
      setDataSources(response.data.sources || []);
    } catch (error) {
      console.error('Error loading data sources:', error);
      message.error(t('common.error'));
    }
  };

  // 加载所有数据源日志
  const loadDataSourceLogs = async (page: number = 1, pageSize: number = 10) => {
    setLoading(true);
    try {
      const params: any = {
        limit: pageSize,
        offset: (page - 1) * pageSize
      };

      // 添加筛选参数
      if (filters.timeRange && filters.timeRange[0]) {
        params.start_time = filters.timeRange[0].toISOString();
      }
      if (filters.timeRange && filters.timeRange[1]) {
        params.end_time = filters.timeRange[1].toISOString();
      }
      if (filters.keyword) {
        params.keyword = filters.keyword;
      }
      if (filters.ip) {
        params.ip = filters.ip;
      }

      const response = await api.get('/data-source-logs', {
        params
      });
      setLogs(response.data.logs || []);
      setPagination({
        ...pagination,
        current: page,
        pageSize: pageSize,
        total: response.data.total || 0
      });
    } catch (error) {
      console.error('Error loading data source logs:', error);
      message.error(t('common.error'));
    } finally {
      setLoading(false);
    }
  };

  // 初始化加载数据
  useEffect(() => {
    loadDataSources();
    loadDataSourceLogs(1, pagination.pageSize);
  }, []);

  // 分页处理
  const handlePaginationChange = (page: number, pageSize: number) => {
    loadDataSourceLogs(page, pageSize);
  };

  // 查看日志详情
  const handleViewLogDetail = (log: any) => {
    setSelectedLog(log);
    setLogDetailModalVisible(true);
  };

  // 从日志中提取IP地址
  const extractIP = (log: string) => {
    if (!log) return '-';
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const matches = log.match(ipPattern);
    if (matches && matches.length > 0) {
      return matches[0];
    }
    return '-';
  };

  // 根据source_id获取数据源名称
  const getDataSourceName = (sourceId: number) => {
    const source = dataSources.find(s => s.id === sourceId);
    if (source) {
      return `${source.name} (${source.source_type})`;
    }
    return `ID: ${sourceId}`;
  };

  // 根据source_id获取数据源状态图标
  const getDataSourceStatusIcon = (sourceId: number) => {
    const source = dataSources.find(s => s.id === sourceId);
    if (source) {
      return source.status === 'active' ? '🟢' : source.status === 'error' ? '🔴' : '⚪';
    }
    return '⚪';
  };

  // 表格列定义
  const columns = [
    {
      title: t('dataSourceLogs.id'),
      dataIndex: 'id',
      key: 'id',
      width: 80,
    },
    {
      title: t('dataSourceLogs.dataSource'),
      dataIndex: 'source_id',
      key: 'source_id',
      width: 180,
      render: (source_id: any) => {
        if (!source_id) return '-';
        return (
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <span style={{ marginRight: 8, fontSize: 16 }}>
              {getDataSourceStatusIcon(source_id)}
            </span>
            <span>{getDataSourceName(source_id)}</span>
          </div>
        );
      },
    },
    {
      title: t('dataSourceLogs.receivedAt'),
      dataIndex: 'received_at',
      key: 'received_at',
      width: 180,
      render: (received_at: any) => {
        if (!received_at) return '-';
        try {
          return new Date(received_at).toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
          });
        } catch {
          return received_at;
        }
      },
    },
    {
      title: t('dataSourceLogs.ip'),
      dataIndex: 'source_ip',
      key: 'ip',
      width: 150,
      render: (_: any, record: any) => {
        return extractIP(record.raw_log);
      },
    },
    {
      title: t('dataSourceLogs.rawLog'),
      dataIndex: 'raw_log',
      key: 'raw_log',
      render: (raw_log: any) => <Text ellipsis>{raw_log || '-'}</Text>,
    },
    {
      title: t('dataSourceLogs.processed'),
      dataIndex: 'processed',
      key: 'processed',
      width: 100,
      render: (processed: boolean) => (
        <Text style={{ color: processed ? 'green' : 'red' }}>
          {processed ? t('dataSourceLogs.yes') : t('dataSourceLogs.no')}
        </Text>
      ),
    },
    {
      title: t('dataSourceLogs.errorMessage'),
      dataIndex: 'error_message',
      key: 'error_message',
      render: (error_message: any) => <Text ellipsis>{error_message || '-'}</Text>,
    },
    {
      title: t('dataSourceLogs.actions'),
      key: 'actions',
      width: 100,
      render: (_: any, record: any) => (
        <Link onClick={() => handleViewLogDetail(record)}>
          {t('dataSourceLogs.viewDetail')}
        </Link>
      ),
    },
  ];

  return (
    <Card title={t('dataSourceLogs.title')}>
      {/* 筛选器 */}
      <Card size="small" style={{ marginBottom: 16 }} title={t('dataSourceLogs.filters.title')}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space style={{ width: '100%', justifyContent: 'space-between' }}>
            <RangePicker 
              style={{ width: 300 }}
              placeholder={[t('dataSourceLogs.filters.startTime'), t('dataSourceLogs.filters.endTime')]}
              value={filters.timeRange}
              onChange={(dates) => {
                setFilters({ ...filters, timeRange: dates });
                if (!dates) {
                  loadDataSourceLogs(1, pagination.pageSize);
                }
              }}
              allowClear
            />
            <Search
              placeholder={t('dataSourceLogs.filters.keyword')}
              style={{ width: 300 }}
              value={filters.keyword}
              onChange={(e) => setFilters({ ...filters, keyword: e.target.value })}
              onSearch={() => loadDataSourceLogs(1, pagination.pageSize)}
              allowClear
              onClear={() => {
                setFilters({ ...filters, keyword: '' });
                loadDataSourceLogs(1, pagination.pageSize);
              }}
            />
            <Input
              placeholder={t('dataSourceLogs.filters.ip')}
              style={{ width: 200 }}
              value={filters.ip}
              onChange={(e) => setFilters({ ...filters, ip: e.target.value })}
              allowClear
              onClear={() => {
                setFilters({ ...filters, ip: '' });
                loadDataSourceLogs(1, pagination.pageSize);
              }}
            />
          </Space>
          <Space style={{ justifyContent: 'flex-end' }}>
            <Button 
              onClick={() => {
                setFilters({
                  timeRange: null,
                  keyword: '',
                  ip: ''
                });
                loadDataSourceLogs(1, pagination.pageSize);
              }}
            >
              {t('dataSourceLogs.filters.reset')}
            </Button>
            <Button 
              type="primary" 
              onClick={() => loadDataSourceLogs(1, pagination.pageSize)}
            >
              {t('dataSourceLogs.filters.apply')}
            </Button>
          </Space>
        </Space>
      </Card>

      <Spin spinning={loading}>
        <Table 
          columns={columns} 
          dataSource={logs} 
          rowKey="id" 
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: pagination.total,
            onChange: handlePaginationChange
          }}
          className="data-source-logs-table"
          scroll={{
            x: 1200,
            y: 'max-content'
          }}
          size="middle"
        />
      </Spin>

      {/* 日志详情模态框 */}
      <Modal
        title={t('dataSourceLogs.logDetail')}
        open={logDetailModalVisible}
        onCancel={() => setLogDetailModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setLogDetailModalVisible(false)}>
            {t('common.close')}
          </Button>
        ]}
        width={800}
      >
        {selectedLog && (
          <div>
            <Descriptions bordered column={4}>
              <Descriptions.Item label={t('dataSourceLogs.id')}>{selectedLog.id}</Descriptions.Item>
              <Descriptions.Item label={t('dataSourceLogs.sourceId')}>{selectedLog.source_id}</Descriptions.Item>
              <Descriptions.Item label={t('dataSourceLogs.ip')}>
                {extractIP(selectedLog.raw_log)}
              </Descriptions.Item>
              <Descriptions.Item label={t('dataSourceLogs.receivedAt')}>
                {selectedLog.received_at ? new Date(selectedLog.received_at).toLocaleString('zh-CN') : '-'}
              </Descriptions.Item>
              <Descriptions.Item label={t('dataSourceLogs.processed')}>
                <Text style={{ color: selectedLog.processed ? 'green' : 'red' }}>
                  {selectedLog.processed ? t('dataSourceLogs.yes') : t('dataSourceLogs.no')}
                </Text>
              </Descriptions.Item>
              <Descriptions.Item label={t('dataSourceLogs.errorMessage')} span={3}>
                {selectedLog.error_message || '-'}
              </Descriptions.Item>
            </Descriptions>

            <div style={{ marginTop: 20 }}>
              <Title level={5}>{t('dataSourceLogs.rawLog')}</Title>
              <Card size="small" style={{ backgroundColor: '#f5f5f5' }}>
                <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {selectedLog.raw_log || '-'}
                </pre>
              </Card>
            </div>

            <div style={{ marginTop: 20 }}>
              <Title level={5}>{t('dataSourceLogs.parsedLog')}</Title>
              <Card size="small" style={{ backgroundColor: '#f0f8ff' }}>
                <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {JSON.stringify(selectedLog.parsed_log, null, 2) || '-'}
                </pre>
              </Card>
            </div>
          </div>
        )}
      </Modal>
    </Card>
  );
};

export default DataSourceLogs;