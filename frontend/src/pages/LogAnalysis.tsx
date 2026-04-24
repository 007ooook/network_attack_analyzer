import React, { useState, useEffect, useRef } from 'react';
import { Card, Row, Col, Form, Select, DatePicker, Button, Table, Tag, Badge, Spin, message } from 'antd';
import { api } from '../utils/api';
import { useTranslation } from 'react-i18next';
import * as echarts from 'echarts';
import { BarChart, Bar, PieChart, Pie, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';

const { Option } = Select;
const { RangePicker } = DatePicker;

const LogAnalysis: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [logData, setLogData] = useState<any[]>([]);
  const [statistics, setStatistics] = useState<any>({});
  const [attackTrends, setAttackTrends] = useState<any[]>([]);
  const [attackDistribution, setAttackDistribution] = useState<any[]>([]);
  const [logFormatDistribution, setLogFormatDistribution] = useState<any[]>([]);
  const [severityDistribution, setSeverityDistribution] = useState<any[]>([]);
  const [form] = Form.useForm();
  const { t } = useTranslation();
  const pieChartRef = useRef<HTMLDivElement>(null);
  const trendChartRef = useRef<HTMLDivElement>(null);

  // 加载日志数据和统计信息
  const loadData = async (_filters: any = {}) => {
    setLoading(true);
    try {
      // 获取统计信息
      const statsResponse = await api.get('/statistics');
      setStatistics(statsResponse.data);
      
      // 获取攻击趋势
      const trendResponse = await api.get('/attack-trends');
      setAttackTrends(trendResponse.data.trends || []);
      
      // 获取日志数据
      const logsResponse = await api.get('/logs', {
        params: {
          limit: 50,
          offset: 0
        }
      });
      setLogData(logsResponse.data.logs || []);
      
      // 分析日志格式分布
      const formatDistribution = logsResponse.data.logs.reduce((acc: any, log: any) => {
        const format = log.analysis?.log_format || 'unknown';
        acc[format] = (acc[format] || 0) + 1;
        return acc;
      }, {});
      setLogFormatDistribution(Object.entries(formatDistribution).map(([name, value]) => ({ name, value })));
      
      // 分析严重程度分布
      const severityDist = logsResponse.data.logs.reduce((acc: any, log: any) => {
        const severity = log.analysis?.severity || 'Low';
        acc[severity] = (acc[severity] || 0) + 1;
        return acc;
      }, {});
      setSeverityDistribution(Object.entries(severityDist).map(([name, value]) => ({ name, value })));
      
      // 分析攻击类型分布
      if (statsResponse.data.attack_distribution) {
        setAttackDistribution(statsResponse.data.attack_distribution);
      }
      
    } catch (error) {
      console.error('Error loading data:', error);
      message.error(t('common.error'));
    } finally {
      setLoading(false);
    }
  };

  // 初始化加载数据
  useEffect(() => {
    loadData();
  }, []);

  // 渲染图表
  useEffect(() => {
    if (pieChartRef.current) {
      const pieChart = echarts.init(pieChartRef.current);
      const option = {
        title: {
          text: t('logAnalysis.attackTypeDistribution'),
          left: 'center'
        },
        tooltip: {
          trigger: 'item'
        },
        legend: {
          orient: 'vertical',
          left: 'left'
        },
        series: [
          {
            name: t('logAnalysis.attackType'),
            type: 'pie',
            radius: '50%',
            data: attackDistribution,
            emphasis: {
              itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: 'rgba(0, 0, 0, 0.5)'
              }
            }
          }
        ]
      };
      pieChart.setOption(option);
    }

    if (trendChartRef.current) {
      const trendChart = echarts.init(trendChartRef.current);
      const option = {
        title: {
          text: t('logAnalysis.attackTrend24h'),
          left: 'center'
        },
        tooltip: {
          trigger: 'axis'
        },
        xAxis: {
          type: 'category',
          data: attackTrends.map(item => item.hour)
        },
        yAxis: {
          type: 'value'
        },
        series: [
          {
            data: attackTrends.map(item => item.count),
            type: 'line',
            smooth: true,
            areaStyle: {}
          }
        ]
      };
      trendChart.setOption(option);
    }

    // 响应窗口大小变化
    const handleResize = () => {
      if (pieChartRef.current) {
        echarts.getInstanceByDom(pieChartRef.current)?.resize();
      }
      if (trendChartRef.current) {
        echarts.getInstanceByDom(trendChartRef.current)?.resize();
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [attackDistribution, attackTrends, t]);

  // 处理表单提交
  const handleSubmit = (values: any) => {
    loadData(values);
  };

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
      title: t('logAnalysis.logFormat'),
      dataIndex: 'analysis',
      key: 'log_format',
      width: 100,
      render: (analysis: any) => {
        if (!analysis) return '-';
        return (
          <Tag color="blue">{analysis.log_format || 'unknown'}</Tag>
        );
      },
    },
    {
      title: t('logsList.attackType'),
      dataIndex: 'analysis',
      key: 'attack_type',
      width: 120,
      render: (analysis: any) => {
        if (!analysis) return '-';
        return (
          <Tag color={analysis.attack_type !== 'Normal' ? 'red' : 'green'}>
            {analysis.attack_type || 'Normal'}
          </Tag>
        );
      },
    },
    {
      title: t('logsList.threatLevel'),
      dataIndex: 'analysis',
      key: 'severity',
      width: 100,
      render: (analysis: any) => {
        if (!analysis) return '-';
        let color = 'green';
        if (analysis.severity === 'Medium') color = 'orange';
        if (analysis.severity === 'High') color = 'red';
        if (analysis.severity === 'Critical') color = 'purple';
        return <Tag color={color}>{analysis.severity || 'Low'}</Tag>;
      },
    },
    {
      title: t('logAnalysis.threatSources'),
      dataIndex: 'analysis',
      key: 'threat_sources',
      render: (analysis: any) => {
        if (!analysis || !analysis.threat_sources) return '-';
        return analysis.threat_sources.map((source: string) => (
          <Badge key={source} status="error" text={source} style={{ marginRight: 8 }} />
        ));
      },
    },
    {
      title: t('logAnalysis.ruleAnalysis'),
      dataIndex: 'analysis',
      key: 'rule_analysis',
      render: (analysis: any) => {
        if (!analysis || !analysis.rule_analysis || analysis.rule_analysis.length === 0) return '-';
        return analysis.rule_analysis.map((rule: any) => (
          <Tag key={rule.rule_name} color="orange">{rule.rule_name}</Tag>
        ));
      },
    },
  ];

  // 颜色配置
  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#82ca9d'];

  return (
    <div className="log-analysis-page">
      <Card title={t('logAnalysis.title')} style={{ marginBottom: '20px' }}>
        <Form form={form} onFinish={handleSubmit} layout="inline">
          <Form.Item name="logFormat" label={t('logAnalysis.logFormat')}>
            <Select placeholder={t('logAnalysis.selectLogFormat')} style={{ width: 150 }} allowClear>
              <Option value="apache">Apache</Option>
              <Option value="nginx">Nginx</Option>
              <Option value="iis">IIS</Option>
              <Option value="syslog">Syslog</Option>
              <Option value="windows">Windows</Option>
              <Option value="custom">Custom</Option>
            </Select>
          </Form.Item>
          <Form.Item name="severity" label={t('logAnalysis.severity')}>
            <Select placeholder={t('logAnalysis.selectSeverity')} style={{ width: 150 }} allowClear>
              <Option value="Low">Low</Option>
              <Option value="Medium">Medium</Option>
              <Option value="High">High</Option>
              <Option value="Critical">Critical</Option>
            </Select>
          </Form.Item>
          <Form.Item name="timeRange" label={t('logAnalysis.timeRange')}>
            <RangePicker style={{ width: 300 }} allowClear />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading}>
              {t('logAnalysis.analyze')}
            </Button>
          </Form.Item>
        </Form>
      </Card>

      <Row gutter={[16, 16]}>
        <Col span={8}>
          <Card title={t('logAnalysis.statistics')}>
            <div className="statistic-item">
              <span className="statistic-label">{t('logAnalysis.totalLogs')}:</span>
              <span className="statistic-value">{statistics.total_logs || 0}</span>
            </div>
            <div className="statistic-item">
              <span className="statistic-label">{t('logAnalysis.anomalyLogs')}:</span>
              <span className="statistic-value">{statistics.anomaly_logs || 0}</span>
            </div>
            <div className="statistic-item">
              <span className="statistic-label">{t('logAnalysis.attackPercentage')}:</span>
              <span className="statistic-value">
                {statistics.total_logs ? Math.round((statistics.anomaly_logs || 0) / statistics.total_logs * 100) : 0}%
              </span>
            </div>
          </Card>
        </Col>
        <Col span={16}>
          <Card title={t('logAnalysis.logFormatDistribution')}>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={logFormatDistribution}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="value" name={t('logAnalysis.count')}>
                  {logFormatDistribution.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card title={t('logAnalysis.attackTypeDistribution')}>
            <div ref={pieChartRef} style={{ width: '100%', height: 300 }} />
          </Card>
        </Col>
        <Col span={12}>
          <Card title={t('logAnalysis.attackTrend24h')}>
            <div ref={trendChartRef} style={{ width: '100%', height: 300 }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={24}>
          <Card title={t('logAnalysis.severityDistribution')}>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={severityDistribution}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name}: ${((percent || 0) * 100).toFixed(0)}%`}
                >
                  {severityDistribution.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      <Card title={t('logAnalysis.recentLogs')} style={{ marginTop: 16 }}>
        <Spin spinning={loading}>
          <Table
            columns={columns}
            dataSource={logData}
            rowKey="id"
            pagination={{ pageSize: 10 }}
            scroll={{ x: 1600 }}
          />
        </Spin>
      </Card>


    </div>
  );
};

export default LogAnalysis;