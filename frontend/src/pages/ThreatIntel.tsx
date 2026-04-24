import React, { useState, useEffect } from 'react';
import { Card, Table, message, Tag, Button } from 'antd';
import { api } from '../utils/api';
import { useTranslation } from 'react-i18next';
import { SyncOutlined } from '@ant-design/icons';

const ThreatIntel: React.FC = () => {
  const [threats, setThreats] = useState<any[]>([]);
  const [fetching, setFetching] = useState(false);
  const { t } = useTranslation();

  // 加载威胁情报数据
  const loadThreats = async () => {
    try {
      const response = await api.get('/threats');
      setThreats(response.data.threats || []);
    } catch (error) {
      console.error('Error loading threats:', error);
      message.error(t('common.error'));
    }
  };

  // 初始化加载数据
  useEffect(() => {
    loadThreats();
    startAutoFetch();
  }, []);

  // 自动拉取信誉IP
  const startAutoFetch = () => {
    const fetchInterval = setInterval(() => {
      fetchThreats();
    }, 3600000); // 每小时拉取一次

    // 返回清理函数
    return () => {
      if (fetchInterval) {
        clearInterval(fetchInterval);
      }
    };
  };

  const fetchThreats = async (): Promise<void> => {
    try {
      const response = await api.post('/fetch-threats');
      if (response.data.success) {
        console.log(response.data.message);
        await loadThreats();
        message.success(response.data.message || '拉取成功');
      } else {
        console.error(response.data.error || '拉取威胁情报失败');
        message.error(response.data.error || '拉取失败');
      }
    } catch (error: any) {
      console.error(`拉取失败: ${error.response?.data?.error || error.message || '拉取威胁情报失败'}`);
      message.error(error.response?.data?.error || error.message || '拉取失败');
    }
  };

  const handleManualFetch = async () => {
    setFetching(true);
    message.loading({ content: '正在拉取威胁情报...', key: 'fetch-threats', duration: 0 });
    try {
      await fetchThreats();
    } finally {
      setFetching(false);
      message.destroy('fetch-threats');
    }
  };

  // 加载系统配置（仅用于验证配置是否存在）
  useEffect(() => {
    const checkConfig = async () => {
      try {
        const response = await api.get('/config');
        if (response.data.config) {
          const config = response.data.config;
          // 检查微步 API 配置是否存在
          if (!config.api_key) {
            console.warn('微步 API Key 未配置。请在系统设置中设置。');
          }
        }
      } catch (error) {
        console.error('Error loading config:', error);
      }
    };

    checkConfig();
  }, []);

  // 解析描述中的详细信息
  const parseDescription = (description: string) => {
    const info: any = {};
    const lines = description.split('\n');
    lines.forEach(line => {
      const parts = line.split(': ');
      if (parts.length === 2) {
        const key = parts[0].trim();
        const value = parts[1].trim();
        info[key] = value;
      }
    });
    return info;
  };

  // 表格列定义
  const columns = [
    {
      title: t('threatIntel.indicator'),
      dataIndex: 'indicator',
      key: 'indicator',
      width: 150,
    },
    {
      title: t('threatIntel.indicatorType'),
      dataIndex: 'indicator_type',
      key: 'indicator_type',
      width: 120,
    },
    {
      title: t('threatIntel.threatType'),
      dataIndex: 'threat_type',
      key: 'threat_type',
      width: 120,
    },
    {
      title: t('threatIntel.severity'),
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: any) => {
        let color = 'green';
        if (severity === 'Medium') color = 'orange';
        if (severity === 'High') color = 'red';
        return <span style={{ color }}>{severity}</span>;
      },
    },
    {
      title: t('threatIntel.location'),
      key: 'location',
      width: 150,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        return info['地理位置'] || '-';
      },
    },
    {
      title: t('threatIntel.isp'),
      key: 'isp',
      width: 120,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        return info['运营商'] || '-';
      },
    },
    {
      title: t('threatIntel.verdict'),
      key: 'verdict',
      width: 120,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        return info['情报判定'] || '-';
      },
    },
    {
      title: t('threatIntel.tags'),
      key: 'tags',
      width: 150,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        const tags = info['标签'] || '';
        if (!tags) return '-';
        return tags.split(', ').map((tag: string) => (
          <Tag key={tag} style={{ marginBottom: 4, fontSize: '12px' }}>
            {tag}
          </Tag>
        ));
      },
    },
    {
      title: t('threatIntel.asn'),
      key: 'asn',
      width: 150,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        return info['ASN'] || '-';
      },
    },
    {
      title: t('threatIntel.rdns'),
      key: 'rdns',
      width: 150,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        return info['RDNS'] || '-';
      },
    },
    {
      title: t('threatIntel.ports'),
      key: 'ports',
      width: 120,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        return info['开放端口'] || '-';
      },
    },
    {
      title: t('threatIntel.domains'),
      key: 'domains',
      width: 150,
      render: (_: any, record: any) => {
        const info = parseDescription(record.description);
        return info['反查域名'] || '-';
      },
    },
    {
      title: t('threatIntel.source'),
      dataIndex: 'source',
      key: 'source',
      width: 120,
    },
    {
      title: t('threatIntel.created_at'),
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
    },
  ];

  return (
    <div>
      <Card 
        title={t('threatIntel.title')}
        extra={
          <Button 
            type="primary" 
            icon={<SyncOutlined spin={fetching} />}
            onClick={handleManualFetch}
          >
            {t('threatIntel.fetch')}
          </Button>
        }
      >
        <Table 
          columns={columns} 
          dataSource={threats} 
          rowKey="id" 
          pagination={{ pageSize: 10 }}
          scroll={{ x: 'max-content' }}
        />
      </Card>
    </div>
  );
};

export default ThreatIntel;
