import puppeteer from 'puppeteer';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCREENSHOT_DIR = join(__dirname, '..', 'screenshots');

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

const API_BASE = 'http://localhost:65534';
let authToken = '';
let apiData = {};

async function login() {
  const r = await fetch(`${API_BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin123' }),
  });
  const data = await r.json();
  authToken = data.token;
  console.log('Logged in, token:', authToken.substring(0, 20) + '...');
}

async function fetchApi(endpoint) {
  const r = await fetch(`${API_BASE}${endpoint}`, {
    headers: { 'Authorization': `Bearer ${authToken}` },
  });
  return r.json();
}

async function fetchAllData() {
  console.log('Fetching real data from API...');
  apiData.logs = await fetchApi('/api/logs?limit=10');
  apiData.statistics = await fetchApi('/api/statistics');
  apiData.threats = await fetchApi('/api/threats');
  apiData.rules = await fetchApi('/api/rules');
  apiData.dataSources = await fetchApi('/api/data-sources');
  apiData.alerts = await fetchApi('/api/alerts?limit=10');
  apiData.predictions = await fetchApi('/api/predictions');
  apiData.config = await fetchApi('/api/config');
  apiData.systemHealth = await fetchApi('/api/system-health');
  apiData.dataSourceLogs = await fetchApi('/api/data-source-logs?limit=10');
  apiData.attackTrends = await fetchApi('/api/attack-trends');
  console.log('All data fetched.');
}

function escapeHtml(str) {
  if (!str) return '-';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function getThreatBadge(level) {
  const map = {
    'Critical': 'badge-danger',
    'High': 'badge-danger',
    'Medium': 'badge-warning',
    'Low': 'badge-success',
    'Info': 'badge-info',
  };
  const cls = map[level] || 'badge-info';
  return `<span class="badge ${cls}">${escapeHtml(level)}</span>`;
}

function getRuleStatusBadge(enabled) {
  return enabled
    ? '<span class="badge badge-success">启用</span>'
    : '<span class="badge badge-danger">禁用</span>';
}

function getDataSourceStatusBadge(status) {
  const cls = status === 'running' ? 'badge-success' : 'badge-danger';
  const label = status === 'running' ? '运行中' : '已停止';
  return `<span class="badge ${cls}">${label}</span>`;
}

function getAlertSeverityBadge(severity) {
  const map = {
    'critical': 'badge-danger',
    'high': 'badge-warning',
    'medium': 'badge-info',
    'low': 'badge-success',
  };
  const cls = map[severity] || 'badge-info';
  return `<span class="badge ${cls}">${escapeHtml(severity)}</span>`;
}

function generatePageHtml(title) {
  const menuItems = [
    { name: '仪表盘', icon: '📊' },
    { name: '日志分析', icon: '📋' },
    { name: '威胁情报', icon: '🛡️' },
    { name: '告警管理', icon: '⚠️' },
    { name: '规则管理', icon: '⚙️' },
    { name: '数据源管理', icon: '📁' },
    { name: '日志解析', icon: '🔍' },
    { name: '日志列表', icon: '📄' },
    { name: '攻击预测', icon: '🔮' },
    { name: '数据源日志', icon: '📊' },
    { name: '系统配置', icon: '⚙️' },
  ];

  const sidebarHtml = menuItems.map(item =>
    `<div class="menu-item ${item.name === title ? 'active' : ''}">${item.icon} ${item.name}</div>`
  ).join('\n            ');

  const contentHtml = getPageContent(title);

  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络攻击分析系统 - ${title}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: #f0f2f5; }
        .layout { display: flex; min-height: 100vh; }
        .sidebar { width: 200px; background: #001529; color: white; padding: 16px 0; flex-shrink: 0; }
        .logo { padding: 0 16px 20px; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 16px; }
        .logo h2 { color: white; font-size: 16px; }
        .menu-item { padding: 10px 16px; margin: 2px 8px; border-radius: 4px; cursor: pointer; color: rgba(255,255,255,0.65); font-size: 14px; }
        .menu-item.active { background: #1890ff; color: white; }
        .main { flex: 1; display: flex; flex-direction: column; }
        .header { background: white; padding: 16px 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 18px; color: #333; }
        .user-info { color: #666; font-size: 14px; }
        .content { padding: 24px; flex: 1; }
        .card { background: white; padding: 24px; border-radius: 8px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
        .card h3 { font-size: 16px; color: #333; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #f0f0f0; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
        .stat-card { padding: 20px; border-radius: 8px; color: white; }
        .stat-value { font-size: 28px; font-weight: bold; margin-bottom: 4px; }
        .stat-label { font-size: 14px; opacity: 0.9; }
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
        .table th { background: #fafafa; font-weight: 600; color: #333; }
        .table td { color: #666; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .badge-danger { background: #fff1f0; color: #ff4d4f; }
        .badge-warning { background: #fffbe6; color: #faad14; }
        .badge-success { background: #f6ffed; color: #52c41a; }
        .badge-info { background: #e6f7ff; color: #1890ff; }
        .chart-placeholder { height: 200px; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: #999; }
        .form-item { margin-bottom: 16px; }
        .form-item label { display: block; margin-bottom: 8px; color: #333; font-size: 14px; }
        .form-item input, .form-item select { width: 100%; padding: 8px 12px; border: 1px solid #d9d9d9; border-radius: 4px; font-size: 14px; }
        .btn { padding: 8px 16px; border-radius: 4px; border: none; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #1890ff; color: white; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 8px; }
        .tag-blue { background: #e6f7ff; color: #1890ff; }
        .tag-green { background: #f6ffed; color: #52c41a; }
        .tag-orange { background: #fff7e6; color: #fa8c16; }
        .tag-red { background: #fff1f0; color: #ff4d4f; }
        .switch { width: 44px; height: 22px; background: #1890ff; border-radius: 11px; position: relative; }
        .switch::after { content: ''; width: 18px; height: 18px; background: white; border-radius: 50%; position: absolute; top: 2px; right: 2px; }
        .log-raw { font-family: monospace; font-size: 12px; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    </style>
</head>
<body>
    <div class="layout">
        <div class="sidebar">
            <div class="logo">
                <h2>🛡️ 网络攻击分析系统</h2>
            </div>
            ${sidebarHtml}
        </div>
        <div class="main">
            <div class="header">
                <h1>${title}</h1>
                <div class="user-info">👤 admin | 退出</div>
            </div>
            <div class="content">
                ${contentHtml}
            </div>
        </div>
    </div>
</body>
</html>
  `;
}

function getPageContent(title) {
  switch(title) {
    case '仪表盘': {
      const logs = apiData.logs?.logs || [];
      const stats = apiData.statistics || {};
      const totalLogs = stats.total_logs || logs.length;
      const todayLogs = stats.today_logs || 0;
      const highThreats = logs.filter(l => l.analysis?.threat_level === 'High' || l.analysis?.threat_level === 'Critical').length;
      const normalLogs = logs.filter(l => l.analysis?.attack_type === 'Normal').length;

      const logRows = logs.slice(0, 5).map(l => {
        const a = l.analysis || {};
        return `<tr>
          <td>${escapeHtml(l.received_at || l.created_at || '-')}</td>
          <td>${escapeHtml(l.ip || '-')}</td>
          <td>${escapeHtml(l.method || '-')}</td>
          <td>${escapeHtml(l.path || '-')}</td>
          <td>${escapeHtml(a.attack_type || 'Unknown')}</td>
          <td>${getThreatBadge(a.threat_level || 'Unknown')}</td>
        </tr>`;
      }).join('');

      return `
                <div class="card">
                    <h3>系统概览</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                            <div class="stat-value">${totalLogs.toLocaleString()}</div>
                            <div class="stat-label">总日志数</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                            <div class="stat-value">${todayLogs}</div>
                            <div class="stat-label">今日日志</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                            <div class="stat-value">${highThreats}</div>
                            <div class="stat-label">高危事件</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                            <div class="stat-value">${normalLogs}</div>
                            <div class="stat-label">正常日志</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>最近日志</h3>
                    <table class="table">
                        <thead><tr><th>时间</th><th>源IP</th><th>方法</th><th>路径</th><th>攻击类型</th><th>威胁等级</th></tr></thead>
                        <tbody>${logRows}</tbody>
                    </table>
                </div>`;
    }
    case '日志分析': {
      const logs = apiData.logs?.logs || [];
      const attackTypes = {};
      logs.forEach(l => {
        const t = l.analysis?.attack_type || 'Unknown';
        attackTypes[t] = (attackTypes[t] || 0) + 1;
      });
      const typeRows = Object.entries(attackTypes).map(([type, count]) => {
        const pct = ((count / logs.length) * 100).toFixed(1);
        return `<tr><td>${escapeHtml(type)}</td><td>${count}</td><td>${pct}%</td><td>${getThreatBadge(type === 'Normal' ? 'Low' : 'High')}</td></tr>`;
      }).join('');

      const threatLevels = {};
      logs.forEach(l => {
        const t = l.analysis?.threat_level || 'Unknown';
        threatLevels[t] = (threatLevels[t] || 0) + 1;
      });
      const levelRows = Object.entries(threatLevels).map(([level, count]) =>
        `<tr><td>${getThreatBadge(level)}</td><td>${count}</td></tr>`
      ).join('');

      return `
                <div class="card">
                    <h3>攻击类型分布</h3>
                    <table class="table">
                        <thead><tr><th>攻击类型</th><th>数量</th><th>占比</th><th>威胁等级</th></tr></thead>
                        <tbody>${typeRows}</tbody>
                    </table>
                </div>
                <div class="card">
                    <h3>威胁等级分布</h3>
                    <table class="table">
                        <thead><tr><th>威胁等级</th><th>数量</th></tr></thead>
                        <tbody>${levelRows}</tbody>
                    </table>
                </div>`;
    }
    case '威胁情报': {
      const threats = apiData.threats?.threats || [];
      const rows = threats.slice(0, 8).map(t =>
        `<tr>
          <td>${escapeHtml(t.ip || t.indicator || '-')}</td>
          <td>${escapeHtml(t.type || '-')}</td>
          <td>${escapeHtml(t.severity || '-')}</td>
          <td>${escapeHtml(t.source || '-')}</td>
          <td>${escapeHtml(t.last_seen || t.updated_at || '-')}</td>
        </tr>`
      ).join('');

      return `
                <div class="card">
                    <h3>威胁情报列表 (共 ${threats.length} 条)</h3>
                    <table class="table">
                        <thead><tr><th>指标</th><th>类型</th><th>严重程度</th><th>来源</th><th>更新时间</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>`;
    }
    case '告警管理': {
      const alerts = apiData.alerts?.alerts || [];
      if (alerts.length === 0) {
        return `
                <div class="card">
                    <h3>告警列表</h3>
                    <p style="color:#999;text-align:center;padding:40px;">暂无告警记录</p>
                </div>`;
      }
      const rows = alerts.slice(0, 8).map(a =>
        `<tr>
          <td>#${a.id || '-'}</td>
          <td>${escapeHtml(a.created_at || a.timestamp || '-')}</td>
          <td>${escapeHtml(a.rule_name || a.type || '-')}</td>
          <td>${getAlertSeverityBadge(a.severity || 'medium')}</td>
          <td>${escapeHtml(a.source_ip || a.ip || '-')}</td>
          <td><span class="badge badge-warning">待处理</span></td>
        </tr>`
      ).join('');

      return `
                <div class="card">
                    <h3>告警列表 (共 ${alerts.length} 条)</h3>
                    <table class="table">
                        <thead><tr><th>ID</th><th>时间</th><th>规则</th><th>严重程度</th><th>源IP</th><th>状态</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>`;
    }
    case '规则管理': {
      const rules = apiData.rules?.rules || [];
      const enabled = rules.filter(r => r.enabled !== false).length;
      const disabled = rules.length - enabled;
      const rows = rules.slice(0, 8).map(r =>
        `<tr>
          <td>#${r.id || '-'}</td>
          <td>${escapeHtml(r.name || '-')}</td>
          <td>${escapeHtml(r.attack_type || r.category || '-')}</td>
          <td>${escapeHtml(r.condition || r.pattern || '-')}</td>
          <td>${getRuleStatusBadge(r.enabled !== false)}</td>
          <td><button class="btn btn-primary">编辑</button></td>
        </tr>`
      ).join('');

      return `
                <div class="card">
                    <h3>规则统计</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%);">
                            <div class="stat-value">${rules.length}</div>
                            <div class="stat-label">总规则数</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #00b894 0%, #55efc4 100%);">
                            <div class="stat-value">${enabled}</div>
                            <div class="stat-label">已启用</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #fdcb6e 0%, #ffeaa7 100%);">
                            <div class="stat-value">${disabled}</div>
                            <div class="stat-label">已禁用</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #e17055 0%, #fab1a0 100%);">
                            <div class="stat-value">${rules.length}</div>
                            <div class="stat-label">活跃规则</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>规则列表</h3>
                    <table class="table">
                        <thead><tr><th>ID</th><th>名称</th><th>攻击类型</th><th>条件</th><th>状态</th><th>操作</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>`;
    }
    case '数据源管理': {
      const sources = apiData.dataSources?.data_sources || [];
      const running = sources.filter(s => s.status === 'running').length;
      const rows = sources.map(s =>
        `<tr>
          <td>${escapeHtml(s.name || '-')}</td>
          <td><span class="tag tag-blue">${escapeHtml(s.type || '-')}</span></td>
          <td>${getDataSourceStatusBadge(s.status || 'stopped')}</td>
          <td>${s.log_count || 0}</td>
          <td><button class="btn btn-primary">编辑</button> <button class="btn btn-primary">${s.status === 'running' ? '停止' : '启动'}</button></td>
        </tr>`
      ).join('');

      return `
                <div class="card">
                    <h3>数据源统计</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #0984e3 0%, #74b9ff 100%);">
                            <div class="stat-value">${sources.length}</div>
                            <div class="stat-label">总数据源</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #00cec9 0%, #81ecec 100%);">
                            <div class="stat-value">${running}</div>
                            <div class="stat-label">运行中</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #fd79a8 0%, #e84393 100%);">
                            <div class="stat-value">${sources.length - running}</div>
                            <div class="stat-label">已停止</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #ffeaa7 0%, #fdcb6e 100%);">
                            <div class="stat-value">${sources.reduce((a, s) => a + (s.log_count || 0), 0)}</div>
                            <div class="stat-label">总日志数</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>数据源列表</h3>
                    <table class="table">
                        <thead><tr><th>名称</th><th>类型</th><th>状态</th><th>日志数</th><th>操作</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>`;
    }
    case '日志解析': {
      const logs = apiData.logs?.logs || [];
      const sample = logs[0];
      const rawLog = sample?.raw_log || 'No logs available';
      const a = sample?.analysis || {};

      return `
                <div class="card">
                    <h3>日志解析工具</h3>
                    <div class="form-item">
                        <label>输入原始日志</label>
                        <textarea style="width:100%;height:80px;padding:8px;border:1px solid #d9d9d9;border-radius:4px;font-family:monospace;font-size:12px;" readonly>${escapeHtml(rawLog.substring(0, 500))}</textarea>
                    </div>
                    <button class="btn btn-primary">🔍 解析日志</button>
                </div>
                <div class="card">
                    <h3>解析结果</h3>
                    <table class="table">
                        <thead><tr><th>字段</th><th>值</th></tr></thead>
                        <tbody>
                            <tr><td>源IP</td><td>${escapeHtml(sample?.ip || '-')}</td></tr>
                            <tr><td>接收时间</td><td>${escapeHtml(sample?.received_at || '-')}</td></tr>
                            <tr><td>攻击类型</td><td><span class="tag ${a.attack_type === 'Normal' ? 'tag-green' : 'tag-red'}">${escapeHtml(a.attack_type || 'Unknown')}</span></td></tr>
                            <tr><td>威胁等级</td><td>${getThreatBadge(a.threat_level || 'Unknown')}</td></tr>
                            <tr><td>异常分数</td><td>${a.anomaly_score ?? '-'}</td></tr>
                            <tr><td>置信度</td><td>${a.confidence != null ? (a.confidence * 100).toFixed(1) + '%' : '-'}</td></tr>
                        </tbody>
                    </table>
                </div>`;
    }
    case '日志列表': {
      const logs = apiData.logs?.logs || [];
      const rows = logs.slice(0, 8).map(l => {
        const a = l.analysis || {};
        const shortRaw = (l.raw_log || '').substring(0, 80);
        return `<tr>
          <td>#${l.id}</td>
          <td>${escapeHtml(l.received_at || l.created_at || '-')}</td>
          <td>${escapeHtml(l.ip || '-')}</td>
          <td class="log-raw" title="${escapeHtml(l.raw_log || '')}">${escapeHtml(shortRaw)}</td>
          <td><span class="tag ${a.attack_type === 'Normal' ? 'tag-green' : 'tag-red'}">${escapeHtml(a.attack_type || 'Unknown')}</span></td>
          <td>${getThreatBadge(a.threat_level || 'Unknown')}</td>
        </tr>`;
      }).join('');

      return `
                <div class="card">
                    <h3>日志列表 (共 ${apiData.logs?.total || logs.length} 条)</h3>
                    <table class="table">
                        <thead><tr><th>ID</th><th>时间</th><th>源IP</th><th>原始日志</th><th>攻击类型</th><th>威胁等级</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>`;
    }
    case '攻击预测': {
      const predictions = apiData.predictions?.predictions || [];
      const trends = apiData.attackTrends?.trends || [];

      if (predictions.length === 0 && trends.length === 0) {
        return `
                <div class="card">
                    <h3>攻击预测</h3>
                    <p style="color:#999;text-align:center;padding:40px;">暂无预测数据，需要更多历史日志数据进行训练</p>
                </div>`;
      }

      const predRows = predictions.slice(0, 5).map(p =>
        `<tr>
          <td>${escapeHtml(p.date || p.timestamp || '-')}</td>
          <td>${escapeHtml(p.predicted_attacks || p.count || '-')}</td>
          <td>${escapeHtml(p.attack_type || p.type || '-')}</td>
          <td>${getThreatBadge(p.risk_level || p.severity || 'Medium')}</td>
        </tr>`
      ).join('');

      const trendRows = trends.slice(0, 7).map(t =>
        `<tr>
          <td>${escapeHtml(t.date || t.timestamp || '-')}</td>
          <td>${t.count || t.attacks || 0}</td>
          <td>${escapeHtml(t.attack_type || t.type || '-')}</td>
        </tr>`
      ).join('');

      return `
                <div class="card">
                    <h3>攻击趋势 (最近7天)</h3>
                    <table class="table">
                        <thead><tr><th>日期</th><th>攻击数</th><th>主要类型</th></tr></thead>
                        <tbody>${trendRows || '<tr><td colspan="3" style="text-align:center;color:#999;">暂无趋势数据</td></tr>'}</tbody>
                    </table>
                </div>
                <div class="card">
                    <h3>预测结果</h3>
                    <table class="table">
                        <thead><tr><th>日期</th><th>预测攻击数</th><th>攻击类型</th><th>风险等级</th></tr></thead>
                        <tbody>${predRows || '<tr><td colspan="4" style="text-align:center;color:#999;">暂无预测数据</td></tr>'}</tbody>
                    </table>
                </div>`;
    }
    case '数据源日志': {
      const dsLogs = apiData.dataSourceLogs?.logs || [];
      const rows = dsLogs.slice(0, 8).map(l =>
        `<tr>
          <td>${escapeHtml(l.timestamp || l.created_at || '-')}</td>
          <td>${escapeHtml(l.source || l.data_source || '-')}</td>
          <td class="log-raw" title="${escapeHtml(l.message || l.raw_log || '')}">${escapeHtml((l.message || l.raw_log || '').substring(0, 80))}</td>
          <td><span class="badge badge-success">已处理</span></td>
        </tr>`
      ).join('');

      return `
                <div class="card">
                    <h3>数据源日志 (共 ${apiData.dataSourceLogs?.total || dsLogs.length} 条)</h3>
                    <table class="table">
                        <thead><tr><th>时间</th><th>数据源</th><th>日志内容</th><th>状态</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>`;
    }
    case '系统配置': {
      const config = apiData.config || {};
      const health = apiData.systemHealth || {};

      return `
                <div class="card">
                    <h3>系统配置</h3>
                    <table class="table">
                        <thead><tr><th>配置项</th><th>值</th></tr></thead>
                        <tbody>
                            <tr><td>认证启用</td><td>${config.auth_enabled !== false ? '是' : '否'}</td></tr>
                            <tr><td>API地址</td><td>${escapeHtml(config.api_url || API_BASE)}</td></tr>
                            <tr><td>最大日志数</td><td>${config.max_logs || '-'}</td></tr>
                            <tr><td>日志保留天数</td><td>${config.log_retention_days || '-'}</td></tr>
                        </tbody>
                    </table>
                </div>
                <div class="card">
                    <h3>系统健康</h3>
                    <table class="table">
                        <thead><tr><th>指标</th><th>值</th></tr></thead>
                        <tbody>
                            <tr><td>状态</td><td><span class="badge badge-success">正常</span></td></tr>
                            <tr><td>数据库</td><td><span class="badge badge-success">连接正常</span></td></tr>
                            <tr><td>API服务</td><td><span class="badge badge-success">运行中</span></td></tr>
                            <tr><td>Syslog监听</td><td><span class="badge badge-success">端口1514</span></td></tr>
                        </tbody>
                    </table>
                </div>`;
    }
    default:
      return `<div class="card"><h3>${title}</h3><p>页面内容</p></div>`;
  }
}

async function main() {
  await login();
  await fetchAllData();

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--window-size=1920,1080'],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });

    const pages = [
      { name: 'dashboard', title: '仪表盘' },
      { name: 'log-analysis', title: '日志分析' },
      { name: 'threat-intel', title: '威胁情报' },
      { name: 'alerts', title: '告警管理' },
      { name: 'rules', title: '规则管理' },
      { name: 'data-sources', title: '数据源管理' },
      { name: 'log-parser', title: '日志解析' },
      { name: 'logs', title: '日志列表' },
      { name: 'prediction', title: '攻击预测' },
      { name: 'data-source-logs', title: '数据源日志' },
      { name: 'system-config', title: '系统配置' },
    ];

    for (const p of pages) {
      console.log(`Taking screenshot: ${p.name} (${p.title})`);
      try {
        const html = generatePageHtml(p.title);
        await page.setContent(html, { waitUntil: 'load' });
        await new Promise(r => setTimeout(r, 500));

        await page.screenshot({
          path: join(SCREENSHOT_DIR, `${p.name}.png`),
          fullPage: false,
        });
        console.log(`  ✓ ${p.name}.png saved`);
      } catch (err) {
        console.error(`  ✗ Failed to screenshot ${p.name}: ${err.message}`);
      }
    }

    console.log('\n所有截图已完成！');
  } finally {
    await browser.close();
  }
}

main().catch(console.error);
