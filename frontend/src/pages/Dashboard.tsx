import React, { useState, useEffect } from 'react';
import { Card, Statistic, Row, Col, Tag, Badge, Table, Spin, Empty } from 'antd';
import {
  AreaChart, Area, PieChart, Pie,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, Cell
} from 'recharts';
import {
  DashboardOutlined,
  AlertOutlined,
  DatabaseOutlined,
  FileTextOutlined,
  BugOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import { api } from '../utils/api';
import { useTranslation } from 'react-i18next';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#82ca9d', '#ffc658', '#ff6b6b', '#4ecdc4', '#45b7d1'];

const Dashboard: React.FC = () => {
  const { t } = useTranslation();

  const [statistics, setStatistics] = useState<any>({});
  const [systemHealth, setSystemHealth] = useState<any>(null);
  const [alertStats, setAlertStats] = useState<any>(null);
  const [threatSummary, setThreatSummary] = useState<any>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [recentLogs, setRecentLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const loadAllData = async () => {
    try {
      const [statsRes, healthRes, alertStatsRes, threatRes, alertsRes, logsRes] = await Promise.all([
        api.get('/statistics').then(r => r.data).catch(() => ({})),
        api.get('/system-health').then(r => r.data).catch(() => ({})),
        api.get('/alerts/statistics').then(r => r.data).catch(() => ({})),
        api.get('/threat-intel-summary').then(r => r.data).catch(() => ({})),
        api.get('/alerts?limit=5').then(r => r.data).catch(() => ({})),
        api.get('/logs?limit=5').then(r => r.data).catch(() => ({})),
      ]);

      setStatistics(statsRes);
      setSystemHealth(healthRes);
      setAlertStats(alertStatsRes.statistics || null);
      setThreatSummary(threatRes.error ? null : threatRes);
      setRecentAlerts(alertsRes.alerts || []);
      setRecentLogs(logsRes.logs || []);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 60000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadAllData();
    setRefreshing(false);
  };

  const getSeverityColor = (severity: string) => {
    const map: Record<string, string> = { Critical: 'red', High: 'orange', Medium: 'blue', Low: 'green', Info: 'default' };
    return map[severity] || 'default';
  };

  const recentAlertColumns = [
    { title: t('alerts.severity'), dataIndex: 'severity', key: 'severity', width: 90, render: (s: string) => <Badge color={getSeverityColor(s)} text={s} /> },
    { title: t('alerts.attackType'), dataIndex: 'attack_type', key: 'attack_type', width: 130 },
    { title: t('alerts.sourceIP'), dataIndex: 'source_ip', key: 'source_ip', width: 130, render: (ip: string) => <code style={{ fontSize: 12 }}>{ip}</code> },
    { title: t('alerts.confidence'), dataIndex: 'confidence', key: 'confidence', width: 80, render: (v: number) => <span>{Math.round(v * 100)}%</span> },
    { title: t('alerts.description'), dataIndex: 'description', key: 'description', ellipsis: true },
    { title: t('alerts.createdAt'), dataIndex: 'created_at', key: 'created_at', width: 160, render: (d: string) => <span style={{ fontSize: 12, color: '#8c8c8c' }}>{d ? new Date(d).toLocaleString('zh-CN') : '-'}</span> },
  ];

  const recentLogColumns = [
    { title: t('logsList.ip'), dataIndex: 'ip', key: 'ip', width: 130, render: (ip: string) => <code style={{ fontSize: 12 }}>{ip}</code> },
    { title: t('logsList.timestamp'), dataIndex: 'timestamp', key: 'timestamp', width: 160, render: (ts: string) => <span style={{ fontSize: 12, color: '#8c8c8c' }}>{ts || '-'}</span> },
    { title: t('logsList.attackType'), dataIndex: ['analysis', 'attack_type'], key: 'log_attack_type', width: 130, render: (_: any, r: any) => r.analysis?.attack_type || '-' },
    { title: t('logsList.threatLevel'), dataIndex: ['analysis', 'threat_level'], key: 'threat_level', width: 100, render: (_: any, r: any) => {
      const score = r.analysis?.anomaly_score || 0;
      const color = score > 0.7 ? 'red' : score > 0.4 ? 'orange' : 'green';
      return <Tag key="threat-level" color={color}>{(score * 100).toFixed(0)}%</Tag>;
    }},
  ];

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <Spin size="large" />
      </div>
    );
  }

  const totalLogs = statistics.total_logs || 0;
  const anomalyLogs = statistics.anomaly_logs || 0;
  const attackRate = totalLogs > 0 ? Math.round((anomalyLogs / totalLogs) * 100) : 0;
  const totalAlerts = alertStats?.total_alerts || 0;
  const uniqueIPs = alertStats?.unique_source_ips || 0;

  return (
    <div>
      <Row justify="space-between" align="middle" style={{ marginBottom: 20 }}>
        <Col>
          <h2 style={{ fontSize: 22, fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 8 }}>
            <DashboardOutlined style={{ color: '#1890ff' }} />
            {t('dashboard.title')}
          </h2>
        </Col>
        <Col>
          <ReloadOutlined
            spin={refreshing}
            onClick={handleRefresh}
            style={{ fontSize: 18, cursor: 'pointer', color: '#1890ff' }}
          />
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ borderTop: '3px solid #1890ff' }}>
            <Statistic
              title={t('dashboard.totalLogs')}
              value={totalLogs}
              prefix={<FileTextOutlined style={{ color: '#1890ff' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ borderTop: '3px solid #ff4d4f' }}>
            <Statistic
              title={t('dashboard.anomalyLogs')}
              value={anomalyLogs}
              prefix={<BugOutlined style={{ color: '#ff4d4f' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ borderTop: '3px solid #faad14' }}>
            <Statistic
              title={t('dashboard.attackLogs')}
              value={attackRate}
              suffix="%"
              prefix={<AlertOutlined style={{ color: '#faad14' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable style={{ borderTop: '3px solid #722ed1' }}>
            <Statistic
              title={t('dashboard.activeAlerts')}
              value={totalAlerts}
              prefix={<SafetyCertificateOutlined style={{ color: '#722ed1' }} />}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable size="small" style={{ borderTop: '3px solid #52c41a' }}>
            <Statistic
              title={t('dashboard.uniqueSourceIPs')}
              value={uniqueIPs}
              prefix={<ThunderboltOutlined style={{ color: '#52c41a' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable size="small" style={{ borderTop: '3px solid #fa8c16' }}>
            <Statistic
              title={t('dashboard.databaseSize')}
              value={systemHealth.db_size || 0}
              suffix="MB"
              prefix={<DatabaseOutlined style={{ color: '#fa8c16' }} />}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        <Col xs={24} lg={12}>
          <Card title={t('dashboard.attackTrend')} hoverable>
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={statistics.attack_trend || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Legend />
                <Area type="monotone" dataKey="count" name={t('dashboard.attackCount')} stroke="#8884d8" fill="rgba(136,132,216,0.3)" />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title={t('dashboard.attackDistribution')} hoverable>
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={(statistics.attack_distribution || []).map((d: any) => ({ name: d.type, value: d.count }))}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }: { name?: string; percent?: number }) => `${name || '-'}: ${((percent || 0) * 100).toFixed(0)}%`}
                  outerRadius={90}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {(statistics.attack_distribution || []).map((d: any, index: number) => (
                    <Cell key={`attack-${d.type || index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        <Col xs={24} lg={12}>
          <Card title={t('dashboard.threatSummary')} hoverable size="small">
            {threatSummary && !threatSummary.error ? (
              <Row gutter={[12, 12]}>
                <Col span={8}>
                  <div style={{ textAlign: 'center', padding: '12px 0', backgroundColor: '#f0f2f5', borderRadius: 8 }}>
                    <div style={{ fontSize: 12, color: '#666' }}>{t('prediction.totalClassifications')}</div>
                    <div style={{ fontSize: 22, fontWeight: 'bold', color: '#1890ff' }}>{threatSummary.total_classifications || 0}</div>
                  </div>
                </Col>
                <Col span={8}>
                  <div style={{ textAlign: 'center', padding: '12px 0', backgroundColor: '#f0f2f5', borderRadius: 8 }}>
                    <div style={{ fontSize: 12, color: '#666' }}>{t('prediction.totalAttacks')}</div>
                    <div style={{ fontSize: 22, fontWeight: 'bold', color: '#ff4d4f' }}>{threatSummary.total_attacks || 0}</div>
                  </div>
                </Col>
                <Col span={8}>
                  <div style={{ textAlign: 'center', padding: '12px 0', backgroundColor: '#f0f2f5', borderRadius: 8 }}>
                    <div style={{ fontSize: 12, color: '#666' }}>{t('prediction.detectionRate')}</div>
                    <div style={{ fontSize: 22, fontWeight: 'bold', color: '#52c41a' }}>{threatSummary.detection_rate || 0}%</div>
                  </div>
                </Col>
                {threatSummary.severity_distribution && Object.keys(threatSummary.severity_distribution).length > 0 && (
                  <Col span={24} style={{ marginTop: 8 }}>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                      {Object.entries(threatSummary.severity_distribution).map(([severity, count]) => (
                        <Tag key={`threat-severity-${severity}`} color={getSeverityColor(severity)} style={{ padding: '4px 10px' }}>
                          {severity}: {String(count)}
                        </Tag>
                      ))}
                    </div>
                  </Col>
                )}
                {threatSummary.top_attacks && Object.keys(threatSummary.top_attacks).length > 0 && (
                  <Col span={24} style={{ marginTop: 4 }}>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={Object.entries(threatSummary.top_attacks).map(([name, value]) => ({ name, value }))}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, percent }: { name?: string; percent?: number }) => `${name}: ${((percent || 0) * 100).toFixed(0)}%`}
                          outerRadius={70}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          {Object.entries(threatSummary.top_attacks).map(([name]: [string, any], index: number) => (
                            <Cell key={`threat-${name}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </Col>
                )}
              </Row>
            ) : (
              <Empty description={t('prediction.noThreatData')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title={t('dashboard.alertSeverityDistribution')} hoverable size="small">
            {alertStats && alertStats.severity_breakdown ? (
              <div style={{ padding: '8px 0' }}>
                {Object.entries(alertStats.severity_breakdown).map(([severity, count]: [string, any]) => (
                  <div key={`severity-${severity}`} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: getSeverityColor(severity) === 'red' ? '#ff4d4f' : getSeverityColor(severity) === 'orange' ? '#ff7a45' : getSeverityColor(severity) === 'blue' ? '#1890ff' : getSeverityColor(severity) === 'green' ? '#52c41a' : '#8c8c8c' }} />
                      <span style={{ fontSize: 14 }}>{severity}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <span style={{ fontSize: 14, width: 120, textAlign: 'right' }}>{totalAlerts > 0 ? Math.round((count / totalAlerts) * 100) : 0}%</span>
                      <Badge count={count} showZero style={{ backgroundColor: getSeverityColor(severity) === 'red' ? '#ff4d4f' : getSeverityColor(severity) === 'orange' ? '#ff7a45' : getSeverityColor(severity) === 'blue' ? '#1890ff' : getSeverityColor(severity) === 'green' ? '#52c41a' : '#8c8c8c' }} />
                    </div>
                  </div>
                ))}
                {alertStats.top_source_ips && alertStats.top_source_ips.length > 0 && (
                  <div style={{ marginTop: 16, borderTop: '1px solid #f0f0f0', paddingTop: 12 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: '#666' }}>{t('dashboard.topSourceIPs')}</div>
                    {alertStats.top_source_ips.slice(0, 5).map((item: any) => (
                      <div key={item.ip} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <code style={{ fontSize: 12 }}>{item.ip}</code>
                        <Badge count={item.count} showZero />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <Empty description={t('alerts.noAlerts')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        <Col xs={24} lg={12}>
          <Card title={t('dashboard.recentAlerts')} hoverable size="small">
            {recentAlerts.length > 0 ? (
              <Table
                columns={recentAlertColumns}
                dataSource={recentAlerts}
                rowKey="id"
                pagination={false}
                size="small"
                scroll={{ x: 600 }}
              />
            ) : (
              <Empty description={t('alerts.noAlerts')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title={t('dashboard.recentLogs')} hoverable size="small">
            {recentLogs.length > 0 ? (
              <Table
                columns={recentLogColumns}
                dataSource={recentLogs}
                rowKey={(r: any) => r.id || r.ip + r.timestamp}
                pagination={false}
                size="small"
                scroll={{ x: 500 }}
              />
            ) : (
              <Empty description={t('logsList.noLogs')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;
