import React, { useState, useEffect } from 'react';
import { Card, Table, Spin, message, Modal, Button, Descriptions, Tag } from 'antd';
import { api } from '../utils/api';
import { useTranslation } from 'react-i18next';
import { EyeOutlined } from '@ant-design/icons';

const LogsList: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0
  });
  const [detailVisible, setDetailVisible] = useState(false);
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const { t } = useTranslation();

  // 加载日志数据
  const loadLogs = async (page: number = 1, pageSize: number = 10) => {
    setLoading(true);
    try {
      const offset = (page - 1) * pageSize;
      const response = await api.get('/logs', {
        params: {
          limit: pageSize,
          offset: offset
        }
      });
      setLogs(response.data.logs);
      // 使用API返回的总日志数
      setPagination({
        ...pagination,
        current: page,
        pageSize: pageSize,
        total: response.data.total || 0
      });
    } catch (error) {
      console.error('Error loading logs:', error);
      message.error(t('common.error'));
    } finally {
      setLoading(false);
    }
  };

  // 初始化加载数据
  useEffect(() => {
    loadLogs();
  }, []);

  // 表格列定义
  const columns = [
    {
      title: t('logsList.ip'),
      dataIndex: 'ip',
      key: 'ip',
      width: 120,
      render: (ip: any) => ip || '-',
    },
    {
      title: t('logsList.timestamp'),
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (timestamp: any) => {
        if (!timestamp) return '-';
        try {
          return new Date(timestamp).toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
          });
        } catch {
          return timestamp;
        }
      },
    },
    {
      title: t('logsList.receivedAt'),
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
      title: t('logsList.method'),
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: any) => method || '-',
    },
    {
      title: t('logsList.path'),
      dataIndex: 'path',
      key: 'path',
      render: (path: any) => <span title={path || '-'}>{path || '-'}</span>,
    },
    {
      title: t('logsList.status'),
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (status: any) => status || 0,
    },
    {
      title: t('logsList.size'),
      dataIndex: 'size',
      key: 'size',
      width: 80,
      render: (size: any) => size || 0,
    },
    {
      title: t('logsList.userAgent'),
      dataIndex: 'user_agent',
      key: 'user_agent',
      render: (userAgent: any) => <span title={userAgent || '-'}>{userAgent || '-'}</span>,
    },
    {
      title: t('logsList.attackType'),
      dataIndex: 'analysis',
      key: 'attack_type',
      width: 120,
      render: (analysis: any) => {
        if (!analysis) return '-';
        return (
          <span style={{ color: analysis.attack_type !== 'Normal' ? 'red' : 'green' }}>
            {analysis.attack_type || 'Normal'}
          </span>
        );
      },
    },
    {
      title: t('logsList.threatLevel'),
      dataIndex: 'analysis',
      key: 'threat_level',
      width: 100,
      render: (analysis: any) => {
        if (!analysis) return '-';
        let color = 'green';
        if (analysis.threat_level === 'Medium') color = 'orange';
        if (analysis.threat_level === 'High') color = 'red';
        return <span style={{ color }}>{analysis.threat_level || 'Low'}</span>;
      },
    },
    {
      title: t('logsList.actions'),
      key: 'actions',
      width: 80,
      render: (_: any, record: any) => (
        <Button
          type="link"
          icon={<EyeOutlined />}
          onClick={() => showDetail(record)}
        >
          {t('common.view')}
        </Button>
      ),
    },
  ];

  // 分页处理
  const handlePaginationChange = (page: number, pageSize: number) => {
    loadLogs(page, pageSize);
  };

  // 显示日志详情
  const showDetail = (log: any) => {
    setSelectedLog(log);
    setDetailVisible(true);
  };

  // 关闭详情弹窗
  const closeDetail = () => {
    setDetailVisible(false);
    setSelectedLog(null);
  };

  return (
    <div>
      <Card title={t('logsList.title')}>
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
            className="logs-table"
            scroll={{
              x: 1600, // 增加宽度以容纳更多列
              y: 600, // 固定高度，启用虚拟滚动
              scrollToFirstRowOnChange: true
            }}
            size="middle" // 中等大小，提高可读性
            style={{ minWidth: 1600 }} // 确保表格最小宽度
            virtual // 启用虚拟滚动
          />
        </Spin>
      </Card>
      
      {/* 日志详情弹窗 */}
      <Modal
        title={t('logsList.detailTitle')}
        open={detailVisible}
        onCancel={closeDetail}
        width={800}
        footer={[
          <Button key="close" onClick={closeDetail}>
            {t('common.close')}
          </Button>
        ]}
      >
        {selectedLog && (
          <Descriptions bordered column={2} size="small">
            <Descriptions.Item label={t('logsList.id')}>
            {selectedLog.id}
          </Descriptions.Item>
            <Descriptions.Item label={t('logsList.timestamp')}>
              {selectedLog.timestamp || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.receivedAt')}>
            {selectedLog.received_at || '-'}
          </Descriptions.Item>
          <Descriptions.Item label={t('logsList.sourceIp')}>
            {selectedLog.source_ip || '-'}
          </Descriptions.Item>
          <Descriptions.Item label={t('logsList.destinationIp')}>
            {selectedLog.ip || '-'}
          </Descriptions.Item>
          <Descriptions.Item label={t('logsList.sourcePort')}>
            {selectedLog.source_port || '-'}
          </Descriptions.Item>
          <Descriptions.Item label={t('logsList.destinationPort')}>
            {selectedLog.destination_port || '-'}
          </Descriptions.Item>
          <Descriptions.Item label={t('logsList.protocol')}>
            {selectedLog.protocol || '-'}
          </Descriptions.Item>
            <Descriptions.Item label={t('logsList.method')} span={2}>
              {selectedLog.method || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.path')} span={2}>
              {selectedLog.path || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.query')} span={2}>
              {selectedLog.url_query ? <code>{selectedLog.url_query}</code> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.status')} span={2}>
              {selectedLog.status || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.size')} span={2}>
              {selectedLog.size || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.userAgent')} span={2}>
              {selectedLog.user_agent || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.rawLog')} span={2}>
              <div style={{ 
                maxHeight: '200px', 
                overflowY: 'auto', 
                backgroundColor: '#f5f5f5',
                padding: '10px',
                borderRadius: '4px',
                fontFamily: 'monospace',
                fontSize: '12px'
              }}>
                <pre>{selectedLog.raw || '-'}</pre>
              </div>
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.threatLevel')} span={2}>
              {selectedLog.analysis?.threat_level ? (
                <Tag color={
                  selectedLog.analysis.threat_level === 'Critical' ? 'red' :
                  selectedLog.analysis.threat_level === 'High' ? 'orange' :
                  selectedLog.analysis.threat_level === 'Medium' ? 'yellow' : 'green'
                }>
                  {selectedLog.analysis.threat_level}
                </Tag>
              ) : '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.attackType')} span={2}>
              {selectedLog.analysis?.attack_type || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.threatIndicators')} span={2}>
              {selectedLog.threat_indicators && selectedLog.threat_indicators.length > 0 ? (
                <div>
                  {selectedLog.threat_indicators.map((indicator: any, index: number) => (
                    <Tag key={index} style={{ marginBottom: '5px' }}>
                      {indicator.type}: {indicator.value}
                    </Tag>
                  ))}
                </div>
              ) : '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('logsList.ruleAnalysis')} span={2}>
              {selectedLog.rule_analysis && selectedLog.rule_analysis.length > 0 ? (
                <div>
                  {selectedLog.rule_analysis.map((rule: any, index: number) => (
                    <div key={index} style={{ marginBottom: '5px' }}>
                      <Tag color={
                        rule.severity === 'Critical' ? 'red' :
                        rule.severity === 'High' ? 'orange' :
                        rule.severity === 'Medium' ? 'yellow' : 'blue'
                      }>
                        {rule.rule_name}
                      </Tag>
                      <span style={{ marginLeft: '10px', fontSize: '12px', color: '#666' }}>
                        {rule.description}
                      </span>
                    </div>
                  ))}
                </div>
              ) : '-'}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
};

export default LogsList;
