import puppeteer from 'puppeteer';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCREENSHOT_DIR = join(__dirname, '..', 'screenshots');

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

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

function generatePageHtml(title) {
  const menuItems = [
    { name: '仪表盘', icon: '📊', path: 'dashboard' },
    { name: '日志分析', icon: '📋', path: 'log-analysis' },
    { name: '威胁情报', icon: '🛡️', path: 'threat-intel' },
    { name: '告警管理', icon: '⚠️', path: 'alerts' },
    { name: '规则管理', icon: '⚙️', path: 'rules' },
    { name: '数据源管理', icon: '📁', path: 'data-sources' },
    { name: '日志解析', icon: '🔍', path: 'log-parser' },
    { name: '日志列表', icon: '📄', path: 'logs' },
    { name: '攻击预测', icon: '🔮', path: 'prediction' },
    { name: '数据源日志', icon: '📊', path: 'data-source-logs' },
    { name: '系统配置', icon: '⚙️', path: 'system-config' },
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
        .badge-purple { background: #f9f0ff; color: #722ed1; }
        .chart-placeholder { height: 200px; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: #999; }
        .form-item { margin-bottom: 16px; }
        .form-item label { display: block; margin-bottom: 8px; color: #333; font-size: 14px; }
        .form-item input, .form-item select { width: 100%; padding: 8px 12px; border: 1px solid #d9d9d9; border-radius: 4px; font-size: 14px; }
        .btn { padding: 8px 16px; border-radius: 4px; border: none; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #1890ff; color: white; }
        .btn-success { background: #52c41a; color: white; }
        .btn-danger { background: #ff4d4f; color: white; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 8px; }
        .tag-blue { background: #e6f7ff; color: #1890ff; }
        .tag-green { background: #f6ffed; color: #52c41a; }
        .tag-orange { background: #fff7e6; color: #fa8c16; }
        .tag-red { background: #fff1f0; color: #ff4d4f; }
        .switch { width: 44px; height: 22px; background: #1890ff; border-radius: 11px; position: relative; }
        .switch::after { content: ''; width: 18px; height: 18px; background: white; border-radius: 50%; position: absolute; top: 2px; right: 2px; }
        .switch-off { background: #d9d9d9; }
        .switch-off::after { left: 2px; right: auto; }
        .progress-bar { height: 8px; background: #f0f0f0; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; border-radius: 4px; }
        .line-chart { height: 200px; position: relative; }
        .line-chart svg { width: 100%; height: 100%; }
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
    case '仪表盘':
      return `
                <div class="card">
                    <h3>系统概览</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                            <div class="stat-value">1,234</div>
                            <div class="stat-label">总日志数</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                            <div class="stat-value">45</div>
                            <div class="stat-label">今日告警</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                            <div class="stat-value">12</div>
                            <div class="stat-label">待处理</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                            <div class="stat-value">98%</div>
                            <div class="stat-label">处理率</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>最近日志</h3>
                    <table class="table">
                        <thead><tr><th>时间</th><th>源IP</th><th>目标IP</th><th>类型</th><th>严重程度</th><th>状态</th></tr></thead>
                        <tbody>
                            <tr><td>2024-01-15 14:23:45</td><td>192.168.1.100</td><td>10.0.0.50</td><td>SQL注入</td><td><span class="badge badge-danger">高危</span></td><td><span class="badge badge-warning">处理中</span></td></tr>
                            <tr><td>2024-01-15 14:20:12</td><td>203.0.113.45</td><td>10.0.0.22</td><td>端口扫描</td><td><span class="badge badge-warning">中危</span></td><td><span class="badge badge-success">已处理</span></td></tr>
                            <tr><td>2024-01-15 14:15:33</td><td>198.51.100.23</td><td>10.0.0.15</td><td>暴力破解</td><td><span class="badge badge-danger">高危</span></td><td><span class="badge badge-info">待处理</span></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '日志分析':
      return `
                <div class="card">
                    <h3>日志分析统计</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #a18cd1 0%, #fbc2eb 100%);">
                            <div class="stat-value">856</div>
                            <div class="stat-label">Apache日志</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);">
                            <div class="stat-value">234</div>
                            <div class="stat-label">Nginx日志</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #a1c4fd 0%, #c2e9fb 100%);">
                            <div class="stat-value">89</div>
                            <div class="stat-label">Syslog</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #d4fc79 0%, #96e6a1 100%);">
                            <div class="stat-value">55</div>
                            <div class="stat-label">其他格式</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>攻击类型分布</h3>
                    <div class="chart-placeholder">📊 攻击类型分布图表 - SQL注入(35%) | XSS(25%) | 暴力破解(20%) | 其他(20%)</div>
                </div>
                <div class="card">
                    <h3>分析结果</h3>
                    <table class="table">
                        <thead><tr><th>日志ID</th><th>格式</th><th>攻击类型</th><th>置信度</th><th>威胁等级</th></tr></thead>
                        <tbody>
                            <tr><td>#1001</td><td>Apache</td><td>SQL注入</td><td>95%</td><td><span class="badge badge-danger">严重</span></td></tr>
                            <tr><td>#1002</td><td>Nginx</td><td>XSS攻击</td><td>88%</td><td><span class="badge badge-warning">高危</span></td></tr>
                            <tr><td>#1003</td><td>Syslog</td><td>端口扫描</td><td>92%</td><td><span class="badge badge-info">中危</span></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '威胁情报':
      return `
                <div class="card">
                    <h3>威胁情报概览</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);">
                            <div class="stat-value">156</div>
                            <div class="stat-label">恶意IP</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #feca57 0%, #ff9f43 100%);">
                            <div class="stat-value">89</div>
                            <div class="stat-label">可疑域名</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);">
                            <div class="stat-value">234</div>
                            <div class="stat-label">威胁指标</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #1dd1a1 0%, #10ac84 100%);">
                            <div class="stat-value">12</div>
                            <div class="stat-label">今日更新</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>威胁情报列表</h3>
                    <table class="table">
                        <thead><tr><th>IP地址</th><th>威胁类型</th><th>置信度</th><th>来源</th><th>更新时间</th></tr></thead>
                        <tbody>
                            <tr><td>203.0.113.45</td><td><span class="tag tag-red">恶意</span></td><td>98%</td><td>微步在线</td><td>2024-01-15</td></tr>
                            <tr><td>198.51.100.23</td><td><span class="tag tag-orange">可疑</span></td><td>75%</td><td>AlienVault</td><td>2024-01-14</td></tr>
                            <tr><td>192.0.2.100</td><td><span class="tag tag-red">恶意</span></td><td>95%</td><td>微步在线</td><td>2024-01-13</td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '告警管理':
      return `
                <div class="card">
                    <h3>告警统计</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #ff4757 0%, #ff6b81 100%);">
                            <div class="stat-value">23</div>
                            <div class="stat-label">严重告警</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #ffa502 0%, #ff7f50 100%);">
                            <div class="stat-value">45</div>
                            <div class="stat-label">高危告警</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #3742fa 0%, #5352ed 100%);">
                            <div class="stat-value">67</div>
                            <div class="stat-label">中危告警</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #2ed573 0%, #7bed9f 100%);">
                            <div class="stat-value">89</div>
                            <div class="stat-label">低危告警</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>告警列表</h3>
                    <table class="table">
                        <thead><tr><th>告警ID</th><th>时间</th><th>类型</th><th>严重程度</th><th>源IP</th><th>状态</th></tr></thead>
                        <tbody>
                            <tr><td>#A001</td><td>14:23:45</td><td>SQL注入</td><td><span class="badge badge-danger">严重</span></td><td>192.168.1.100</td><td><span class="badge badge-warning">处理中</span></td></tr>
                            <tr><td>#A002</td><td>14:20:12</td><td>XSS攻击</td><td><span class="badge badge-warning">高危</span></td><td>203.0.113.45</td><td><span class="badge badge-success">已处理</span></td></tr>
                            <tr><td>#A003</td><td>14:15:33</td><td>暴力破解</td><td><span class="badge badge-info">中危</span></td><td>198.51.100.23</td><td><span class="badge badge-info">待处理</span></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '规则管理':
      return `
                <div class="card">
                    <h3>规则统计</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%);">
                            <div class="stat-value">27</div>
                            <div class="stat-label">总规则数</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #00b894 0%, #55efc4 100%);">
                            <div class="stat-value">24</div>
                            <div class="stat-label">已启用</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #fdcb6e 0%, #ffeaa7 100%);">
                            <div class="stat-value">3</div>
                            <div class="stat-label">已禁用</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #e17055 0%, #fab1a0 100%);">
                            <div class="stat-value">156</div>
                            <div class="stat-label">今日触发</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>规则列表</h3>
                    <table class="table">
                        <thead><tr><th>规则ID</th><th>规则名称</th><th>攻击类型</th><th>条件</th><th>状态</th><th>操作</th></tr></thead>
                        <tbody>
                            <tr><td>#R001</td><td>SQL注入检测</td><td>SQL注入</td><td>置信度>80%</td><td><span class="badge badge-success">启用</span></td><td><button class="btn btn-primary">编辑</button></td></tr>
                            <tr><td>#R002</td><td>XSS攻击检测</td><td>XSS</td><td>置信度>75%</td><td><span class="badge badge-success">启用</span></td><td><button class="btn btn-primary">编辑</button></td></tr>
                            <tr><td>#R003</td><td>暴力破解检测</td><td>暴力破解</td><td>5次/分钟</td><td><span class="badge badge-danger">禁用</span></td><td><button class="btn btn-primary">编辑</button></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '数据源管理':
      return `
                <div class="card">
                    <h3>数据源统计</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #0984e3 0%, #74b9ff 100%);">
                            <div class="stat-value">9</div>
                            <div class="stat-label">支持类型</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #00cec9 0%, #81ecec 100%);">
                            <div class="stat-value">5</div>
                            <div class="stat-label">已配置</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #fd79a8 0%, #e84393 100%);">
                            <div class="stat-value">4</div>
                            <div class="stat-label">运行中</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #ffeaa7 0%, #fdcb6e 100%);">
                            <div class="stat-value">1.2K</div>
                            <div class="stat-label">今日日志</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>数据源列表</h3>
                    <table class="table">
                        <thead><tr><th>名称</th><th>类型</th><th>状态</th><th>日志数</th><th>操作</th></tr></thead>
                        <tbody>
                            <tr><td>Syslog服务器</td><td><span class="tag tag-blue">Syslog</span></td><td><span class="badge badge-success">运行中</span></td><td>856</td><td><button class="btn btn-primary">编辑</button> <button class="btn btn-danger">停止</button></td></tr>
                            <tr><td>Apache日志</td><td><span class="tag tag-green">File</span></td><td><span class="badge badge-success">运行中</span></td><td>234</td><td><button class="btn btn-primary">编辑</button> <button class="btn btn-danger">停止</button></td></tr>
                            <tr><td>Nginx日志</td><td><span class="tag tag-green">File</span></td><td><span class="badge badge-danger">已停止</span></td><td>0</td><td><button class="btn btn-primary">编辑</button> <button class="btn btn-success">启动</button></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '日志解析':
      return `
                <div class="card">
                    <h3>日志解析工具</h3>
                    <div class="form-item">
                        <label>输入原始日志</label>
                        <textarea style="width:100%;height:100px;padding:8px;border:1px solid #d9d9d9;border-radius:4px;font-family:monospace;" placeholder="192.168.1.100 - - [15/Jan/2024:14:23:45 +0800] &quot;GET /admin?id=1 OR 1=1 HTTP/1.1&quot; 200 1234">192.168.1.100 - - [15/Jan/2024:14:23:45 +0800] "GET /admin?id=1 OR 1=1 HTTP/1.1" 200 1234</textarea>
                    </div>
                    <button class="btn btn-primary">🔍 解析日志</button>
                </div>
                <div class="card">
                    <h3>解析结果</h3>
                    <table class="table">
                        <thead><tr><th>字段</th><th>值</th></tr></thead>
                        <tbody>
                            <tr><td>日志格式</td><td><span class="tag tag-blue">Apache Combined</span></td></tr>
                            <tr><td>源IP</td><td>192.168.1.100</td></tr>
                            <tr><td>请求方法</td><td>GET</td></tr>
                            <tr><td>请求路径</td><td>/admin?id=1 OR 1=1</td></tr>
                            <tr><td>攻击类型</td><td><span class="tag tag-red">SQL注入</span></td></tr>
                            <tr><td>威胁等级</td><td><span class="badge badge-danger">严重</span></td></tr>
                            <tr><td>置信度</td><td>95%</td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '日志列表':
      return `
                <div class="card">
                    <h3>日志查询</h3>
                    <div style="display:flex;gap:16px;margin-bottom:16px;">
                        <input type="text" placeholder="搜索关键词..." style="flex:1;padding:8px 12px;border:1px solid #d9d9d9;border-radius:4px;">
                        <select style="padding:8px 12px;border:1px solid #d9d9d9;border-radius:4px;">
                            <option>全部类型</option>
                            <option>SQL注入</option>
                            <option>XSS</option>
                            <option>暴力破解</option>
                        </select>
                        <button class="btn btn-primary">搜索</button>
                    </div>
                </div>
                <div class="card">
                    <h3>日志列表 (共 1,234 条)</h3>
                    <table class="table">
                        <thead><tr><th>ID</th><th>时间</th><th>源IP</th><th>请求</th><th>攻击类型</th><th>威胁等级</th></tr></thead>
                        <tbody>
                            <tr><td>#1001</td><td>14:23:45</td><td>192.168.1.100</td><td>GET /admin?id=1...</td><td><span class="tag tag-red">SQL注入</span></td><td><span class="badge badge-danger">严重</span></td></tr>
                            <tr><td>#1002</td><td>14:20:12</td><td>203.0.113.45</td><td>GET /search?q=<script>...</td><td><span class="tag tag-orange">XSS</span></td><td><span class="badge badge-warning">高危</span></td></tr>
                            <tr><td>#1003</td><td>14:15:33</td><td>198.51.100.23</td><td>POST /login</td><td><span class="tag tag-blue">暴力破解</span></td><td><span class="badge badge-info">中危</span></td></tr>
                            <tr><td>#1004</td><td>14:10:22</td><td>10.0.0.55</td><td>GET /../../etc/passwd</td><td><span class="tag tag-red">路径遍历</span></td><td><span class="badge badge-danger">严重</span></td></tr>
                            <tr><td>#1005</td><td>14:05:11</td><td>172.16.0.100</td><td>GET /api/users</td><td><span class="tag tag-green">正常</span></td><td><span class="badge badge-success">低危</span></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '攻击预测':
      return `
                <div class="card">
                    <h3>攻击预测概览</h3>
                    <div class="stats">
                        <div class="stat-card" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                            <div class="stat-value">高</div>
                            <div class="stat-label">预测风险等级</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);">
                            <div class="stat-value">+35%</div>
                            <div class="stat-label">趋势变化</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);">
                            <div class="stat-value">SQL注入</div>
                            <div class="stat-label">预测主要攻击</div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%);">
                            <div class="stat-value">92%</div>
                            <div class="stat-label">预测准确率</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>7天攻击趋势预测</h3>
                    <div class="chart-placeholder">
                        <svg viewBox="0 0 600 150" style="width:100%;height:100%;">
                            <polyline points="50,120 120,100 190,80 260,90 330,60 400,40 470,50 540,30" fill="none" stroke="#1890ff" stroke-width="2"/>
                            <circle cx="50" cy="120" r="4" fill="#1890ff"/>
                            <circle cx="120" cy="100" r="4" fill="#1890ff"/>
                            <circle cx="190" cy="80" r="4" fill="#1890ff"/>
                            <circle cx="260" cy="90" r="4" fill="#1890ff"/>
                            <circle cx="330" cy="60" r="4" fill="#1890ff"/>
                            <circle cx="400" cy="40" r="4" fill="#1890ff"/>
                            <circle cx="470" cy="50" r="4" fill="#1890ff"/>
                            <circle cx="540" cy="30" r="4" fill="#1890ff"/>
                            <text x="50" y="140" font-size="10" fill="#999">Day1</text>
                            <text x="540" y="140" font-size="10" fill="#999">Day7</text>
                        </svg>
                    </div>
                </div>
                <div class="card">
                    <h3>预测详情</h3>
                    <table class="table">
                        <thead><tr><th>日期</th><th>预测攻击数</th><th>主要类型</th><th>风险等级</th></tr></thead>
                        <tbody>
                            <tr><td>2024-01-16</td><td>45</td><td>SQL注入</td><td><span class="badge badge-danger">高</span></td></tr>
                            <tr><td>2024-01-17</td><td>52</td><td>XSS</td><td><span class="badge badge-danger">高</span></td></tr>
                            <tr><td>2024-01-18</td><td>38</td><td>暴力破解</td><td><span class="badge badge-warning">中</span></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '数据源日志':
      return `
                <div class="card">
                    <h3>数据源日志筛选</h3>
                    <div style="display:flex;gap:16px;margin-bottom:16px;">
                        <select style="padding:8px 12px;border:1px solid #d9d9d9;border-radius:4px;">
                            <option>全部数据源</option>
                            <option>Syslog服务器</option>
                            <option>Apache日志</option>
                            <option>Nginx日志</option>
                        </select>
                        <input type="date" style="padding:8px 12px;border:1px solid #d9d9d9;border-radius:4px;">
                        <button class="btn btn-primary">查询</button>
                    </div>
                </div>
                <div class="card">
                    <h3>Syslog服务器 - 日志列表</h3>
                    <table class="table">
                        <thead><tr><th>时间</th><th>源IP</th><th>日志内容</th><th>处理状态</th></tr></thead>
                        <tbody>
                            <tr><td>14:23:45</td><td>192.168.1.100</td><td>Jan 15 14:23:45 server sshd[1234]: Failed password...</td><td><span class="badge badge-success">已处理</span></td></tr>
                            <tr><td>14:20:12</td><td>10.0.0.50</td><td>Jan 15 14:20:12 server kernel: TCP connection...</td><td><span class="badge badge-success">已处理</span></td></tr>
                            <tr><td>14:15:33</td><td>172.16.0.100</td><td>Jan 15 14:15:33 server sudo: user : TTY=pts/0...</td><td><span class="badge badge-warning">处理中</span></td></tr>
                        </tbody>
                    </table>
                </div>`;
    case '系统配置':
      return `
                <div class="card">
                    <h3>安全配置</h3>
                    <div class="form-item">
                        <label>密码最小长度</label>
                        <input type="number" value="8" min="6" max="32">
                    </div>
                    <div class="form-item">
                        <label>最大登录尝试次数</label>
                        <input type="number" value="5" min="1" max="10">
                    </div>
                    <div class="form-item">
                        <label>账户锁定时间(秒)</label>
                        <input type="number" value="900" min="60" max="3600">
                    </div>
                    <div class="form-item">
                        <label>会话超时(秒)</label>
                        <input type="number" value="3600" min="300" max="86400">
                    </div>
                    <button class="btn btn-primary">保存安全配置</button>
                </div>
                <div class="card">
                    <h3>API配置</h3>
                    <div class="form-item">
                        <label>API地址</label>
                        <input type="text" value="http://localhost:65534/api">
                    </div>
                    <div class="form-item">
                        <label>启用CORS</label>
                        <div class="switch"></div>
                    </div>
                    <div class="form-item">
                        <label>允许的源</label>
                        <input type="text" value="*">
                    </div>
                    <button class="btn btn-primary">保存API配置</button>
                </div>
                <div class="card">
                    <h3>日志配置</h3>
                    <div class="form-item">
                        <label>日志保留天数</label>
                        <input type="number" value="30" min="1" max="365">
                    </div>
                    <div class="form-item">
                        <label>最大日志大小(MB)</label>
                        <input type="number" value="100" min="10" max="1000">
                    </div>
                    <button class="btn btn-primary">保存日志配置</button>
                </div>`;
    default:
      return `
                <div class="card">
                    <h3>${title}</h3>
                    <p>页面内容加载中...</p>
                </div>`;
  }
}

async function main() {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--window-size=1920,1080'],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });

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
