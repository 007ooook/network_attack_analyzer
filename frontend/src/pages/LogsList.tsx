import React, { useState, useEffect } from 'react';
import { Card, Table, Spin, message } from 'antd';
import axios from 'axios';
import { useTranslation } from 'react-i18next';

// API基础URL配置
const API_BASE_URL = 'http://localhost:8006/api';

const LogsList: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0
  });
  const { t } = useTranslation();

  // 加载日志数据
  const loadLogs = async (page: number = 1, pageSize: number = 10) => {
    setLoading(true);
    try {
      const offset = (page - 1) * pageSize;
      const response = await axios.get(`${API_BASE_URL}/logs`, {
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
      ellipsis: {
        showTooltip: true, // 显示工具提示
        tooltipProps: {
          placement: 'top',
          title: (path: any) => path || '-',
        },
      },
      render: (path: any) => path || '-',
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
      ellipsis: {
        showTooltip: true,
        tooltipProps: {
          placement: 'top',
          title: (userAgent: any) => userAgent || '-',
        },
      },
      render: (userAgent: any) => userAgent || '-',
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
  ];

  // 分页处理
  const handlePaginationChange = (page: number, pageSize: number) => {
    loadLogs(page, pageSize);
  };

  return (
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
            y: 'max-content' // 自适应高度
          }}
          size="middle" // 中等大小，提高可读性
          style={{ minWidth: 1600 }} // 确保表格最小宽度
        />
      </Spin>
    </Card>
  );
};

export default LogsList;
