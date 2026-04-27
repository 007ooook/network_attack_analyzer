# Network Attack Analyzer

基于 AI 的网络攻击日志分析与威胁检测系统，支持多数据源接入、实时日志分析、智能攻击分类、告警管理与威胁情报联动。

> 作者: yeJ

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        前端 (React + TypeScript)                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Dashboard│ │日志管理   │ │告警管理   │ │系统配置           │   │
│  │ 仪表盘    │ │分析/解析   │ │规则/统计   │ │数据源/安全       │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
│                    │              │              │               │
│              ┌─────┴──────────────┴──────────────┴──────┐       │
│              │        API 请求 (Authorization: Bearer)    │       │
│              └─────────────────┬────────────────────────┘       │
└────────────────────────────────┼────────────────────────────────┘
                                 │
┌────────────────────────────────┼────────────────────────────────┐
│                    后端 (Python HTTP Server)                     │
│  ┌─────────────────────────────┴──────────────────────────────┐│
│  │                   AnalyzerRequestHandler                    ││
│  │  ┌──────────────────────────────────────────────────────┐   ││
│  │  │              ApiHandlerMixin  (API 路由分发)          │   ││
│  │  │  日志 / 告警 / 数据源 / 认证 / 分析 / 威胁情报       │   ││
│  │  └──────────────────────────────────────────────────────┘   ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  JWT 认证     │  │  速率限制     │  │  CSRF / CORS / 安全   │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ AI 攻击分类器  │  │ 告警规则引擎  │  │ 威胁情报 (微步在线)   │  │
│  │  25 种攻击类型 │  │ 27 条内置规则 │  │  IP 信誉 + 威胁情报  │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────┐  ┌──────────────────────────────┐  │
│  │   数据源管理器           │  │   系统监控 (CPU/内存/磁盘)     │  │
│  │  Syslog/File/API/Webhook│  │   指标收集 / 健康检测         │  │
│  │  Kafka/Redis/ELK/Splunk │  │                              │  │
│  └─────────────────────────┘  └──────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                     SQLite 数据库                            │  │
│  │  日志 / 告警 / 规则 / 数据源 / 预测 / 监控指标 / 安全配置   │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 核心组件

| 层次 | 技术 | 说明 |
|------|------|------|
| **前端** | React 18 + TypeScript + Vite | Ant Design UI 组件库，Recharts/ECharts 可视化，i18n 国际化 |
| **后端** | Python HTTP Server (SimpleHTTPRequestHandler) | 单端口服务，同时提供 API 和静态资源 |
| **AI 引擎** | scikit-learn + 规则引擎 | 25 种攻击类型的机器学习分类 + 27 条专家规则 |
| **数据存储** | SQLite | 统一数据库，日志、告警、配置、监控指标持久化 |
| **认证** | JWT (PyJWT) | Token 认证，密码复杂度验证，登录锁定，密码历史 |
| **安全** | CORS / CSRF / 速率限制 / 输入验证 | 多层安全防护 |

## 界面预览

### 仪表盘

![仪表盘](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/dashboard.png)

系统主界面，左侧为功能导航菜单，右侧显示系统概览统计和最近日志列表。

### 日志分析

![日志分析](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/log-analysis.png)

日志分析页面，支持多种日志格式的分析和统计功能。

### 威胁情报

![威胁情报](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/threat-intel.png)

威胁情报管理界面，展示安全威胁信息和情报分析结果。

### 告警管理

![告警管理](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/alerts.png)

安全告警管理中心，显示系统检测到的安全告警和事件。

### 规则管理

![规则管理](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/rules.png)

告警规则配置界面，支持自定义安全检测规则。

### 数据源管理

![数据源管理](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/data-sources.png)

数据源配置页面，支持多种数据源的接入和管理。

### 日志解析

![日志解析](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/log-parser.png)

日志解析工具，支持自定义日志格式解析规则。

### 日志列表

![日志列表](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/logs.png)

日志查询和浏览界面，支持日志的搜索和筛选。

### 攻击预测

![攻击预测](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/prediction.png)

基于AI的攻击预测分析，提供安全威胁的趋势预测。

### 数据源日志

![数据源日志](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/data-source-logs.png)

数据源日志监控，显示各数据源的运行状态和日志信息。

### 系统配置

![系统配置](https://raw.githubusercontent.com/007ooook/network_attack_analyzer/master/screenshots/system-config.png)

系统参数配置界面，支持系统各项参数的调整和优化。

## 启动方式

### 后端服务

```bash
# 安装依赖
pip install -r requirements.txt

# 启动服务（默认端口 65534）
python services/main.py
```

### 前端开发模式

```bash
cd frontend
npm install
npm run dev
```

### 生产构建

```bash
cd frontend
npm run build
# 构建产物在 frontend/dist/，由后端自动托管
```

## 功能特点

### 1. 多数据源接入

支持 **9 种数据源类型**，统一管理与监控：

| 类型 | 协议/方式 | 适用场景 |
|------|-----------|----------|
| **Syslog** | UDP/TCP | 网络设备、Linux 服务器日志 |
| **File** | 文件轮询 | Apache/Nginx 等日志文件 |
| **API** | HTTP 轮询 | REST API 日志接口 |
| **Webhook** | HTTP POST | 第三方系统推送 |
| **Kafka** | 消息队列 | 大数据日志流 |
| **Redis** | 消息队列 | 实时日志通道 |
| **ELK Stack** | Elasticsearch | 已有 ELK 基础设施 |
| **Splunk** | HTTP Event Collector | Splunk 平台集成 |
| **Graylog** | GELF HTTP | Graylog 集成 |

每个数据源支持实时启停、状态监控、连接测试、日志量统计。

### 2. AI 攻击分类

基于机器学习 + 特征规则的混合检测引擎：

**25 种攻击类型覆盖：**

| 严重程度 | 攻击类型 |
|----------|----------|
| **严重** | SQL 注入、命令注入、RCE、SSTI、认证绕过、恶意软件感染 |
| **高** | XSS、路径遍历、SSRF、文件上传、数据泄露 |
| **中** | CSRF、暴力破解、IDOR、会话固定、开放重定向、API 滥用 |
| **低** | DoS/DDoS、请求头注入、CRLF 注入、参数污染、主机头注入、协议降级、Web 爬虫 |

检测能力：
- 52 维特征向量提取
- 基于 RandomForest 的机器学习分类
- 5 种日志格式自动识别（Apache/Nginx/IIS/Syslog/Custom）
- 规则引擎与 AI 模型双重验证
- 缓存机制提升分析性能

### 3. 智能告警系统

**27 条内置告警规则**，覆盖全部攻击类型：

- 规则支持条件组合（攻击类型、置信度、IP、路径、状态码、时间范围）
- 严重程度分级（Critical / High / Medium / Low）
- 告警去重与聚合
- 自定义规则创建与编辑（UI 可视化操作）
- 规则启停开关，实时生效

### 4. 威胁情报联动

集成 **微步在线 ThreatBook** 威胁情报平台：

- IP 信誉查询
- 公开 IP 自动筛选
- 威胁指标提取与标记
- 威胁情报摘要与分布统计
- 手动/定时威胁情报拉取

### 5. 系统监控

实时系统健康监控：

| 指标 | 说明 |
|------|------|
| CPU 使用率 | 实时 + 历史趋势 |
| 内存使用率 | 实时 + 历史趋势 |
| 磁盘使用率 | 实时 + 历史趋势 |
| 数据库大小 | 监控数据持久化 |
| 5 秒自动刷新 | 实时更新仪表盘 |

### 6. 账号安全

| 功能 | 说明 |
|------|------|
| JWT 认证 | Token 有效期控制 |
| 密码复杂度 | 长度/大小写/数字/特殊字符验证 |
| 登录锁定 | 连续失败 N 次后锁定 M 分钟 |
| 密码历史 | 禁止使用最近 N 次已用密码 |
| 会话超时 | 空闲超时自动登出 |

### 7. 数据可视化

- **仪表盘**: 攻击趋势面积图、攻击分布饼图、威胁摘要、告警严重程度分布、最近告警/日志列表
- **日志分析**: 统计概览、日志格式分布柱状图、攻击类型分布饼图、24h 攻击趋势折线图、严重程度分布
- **预测分析**: 7 天攻击趋势预测折线图、预测列表
- **告警管理**: 严重程度筛选、告警列表、分页查询

## 功能模块

### 仪表盘 (`/`)

系统总览页面，展示核心统计指标和可视化图表：
- 总计日志数 / 异常日志数 / 攻击占比 / 活跃告警数 / 独立源 IP 数 / 数据库大小
- 攻击趋势面积图（24h）
- 攻击分布饼图
- 威胁情报摘要
- 告警严重程度分布
- 最近告警 / 最近日志列表

### 日志解析 (`/log-parser`)

在线日志解析工具：
- 输入原始日志文本
- AI 自动识别日志格式
- 提取攻击类型、威胁等级
- 展示解析结果

### 日志列表 (`/logs`)

原始日志数据浏览：
- 分页查询，支持攻击类型/威胁等级标记
- 日志详情弹窗（完整字段展示）
- 威胁指标标签
- 规则匹配结果展示

### 日志分析 (`/log-analysis`)

深度日志分析中心：
- 格式/严重程度筛选
- 时间范围选择
- 统计概览（总数、异常数、攻击占比）
- 日志格式分布柱状图
- 攻击类型分布饼图（ECharts）
- 24h 攻击趋势折线图（ECharts）
- 严重程度分布（Recharts 饼图）
- 最近日志分析列表

### 威胁情报 (`/threat-intel`)

威胁情报管理：
- 显示当前威胁情报列表
- 一键拉取最新威胁情报
- 展示情报来源和类型分布
- 威胁情报配置状态检查

### 攻击预测 (`/prediction`)

基于历史数据的攻击预测：
- 7 天攻击趋势预测折线图
- 预测详情列表（攻击类型、源 IP、概率、次数）
- 模型版本追踪
- 30 秒自动更新

### 告警管理 (`/alerts`)

安全告警中心：
- 严重程度筛选（Critical/High/Medium/Low/Info）
- 分页告警列表
- 去重/聚合状态标记
- 置信度显示
- 自动刷新（节流控制）

### 规则管理 (`/rules`)

告警规则管理：
- 规则列表展示（ID/名称/描述/严重程度/状态/操作）
- 添加/编辑/删除规则
- 规则条件 JSON 编辑器
- 规则动作配置
- 启用/禁用开关

### 数据源管理 (`/data-sources`)

数据源配置中心：
- 数据源列表（名称/类型/状态/日志量/最后连接时间/最后源 IP）
- 添加/编辑/删除数据源
- 启动/停止/重启/测试操作
- 分类型配置表单（Syslog/File/API/Webhook 等）
- 5 秒自动刷新实时统计

### 数据源日志 (`/data-source-logs`)

按数据源查看日志：
- 数据源筛选
- 时间段选择
- 关键词搜索
- 日志详情弹窗

### 系统配置 (`/system-config`)

系统设置中心：
- **安全配置**: 密码复杂度策略、登录锁定策略、会话超时
- **API 配置**: 威胁情报 API Key（微步在线）
- **服务配置**: 模型版本、告警设置
- AI 对话配置

## 技术栈

| 类别 | 技术 |
|------|------|
| 前端框架 | React 18 + TypeScript |
| 构建工具 | Vite 5 |
| UI 组件 | Ant Design |
| 图表库 | Recharts + ECharts |
| 国际化 | react-i18next (中/英文) |
| 后端语言 | Python 3 |
| 认证 | JWT (PyJWT) |
| 机器学习 | scikit-learn (RandomForest) |
| 数据存储 | SQLite |
| 系统监控 | psutil |
| 威胁情报 | 微步在线 ThreatBook API |

## 致谢

本项目基于以下优秀的开源软件构建，衷心感谢它们的贡献：

### 前端

| 项目 | 用途 | 许可 |
|------|------|------|
| [React](https://react.dev/) | 前端 UI 框架 | MIT |
| [TypeScript](https://www.typescriptlang.org/) | 类型安全的 JavaScript 超集 | Apache-2.0 |
| [Vite](https://vitejs.dev/) | 前端构建工具 | MIT |
| [Ant Design](https://ant.design/) | UI 组件库 | MIT |
| [Recharts](https://recharts.org/) | 图表可视化库 | MIT |
| [ECharts](https://echarts.apache.org/) | 图表可视化库 | Apache-2.0 |
| [axios](https://axios-http.com/) | HTTP 客户端 | MIT |
| [react-router-dom](https://reactrouter.com/) | 前端路由 | MIT |
| [react-i18next](https://react.i18next.com/) | 国际化框架 | MIT |
| [i18next](https://www.i18next.com/) | 国际化引擎 | MIT |

### 后端

| 项目 | 用途 | 许可 |
|------|------|------|
| [Python](https://www.python.org/) | 编程语言 | PSF |
| [scikit-learn](https://scikit-learn.org/) | 机器学习分类器 | BSD-3-Clause |
| [NumPy](https://numpy.org/) | 数值计算 | BSD-3-Clause |
| [pandas](https://pandas.pydata.org/) | 数据处理 | BSD-3-Clause |
| [PyJWT](https://github.com/jpadilla/pyjwt) | JSON Web Token 认证 | MIT |
| [psutil](https://github.com/giampaolo/psutil) | 系统监控 | BSD-3-Clause |
| [joblib](https://joblib.readthedocs.io/) | 模型持久化 | BSD-3-Clause |
| [requests](https://requests.readthedocs.io/) | HTTP 请求库 | Apache-2.0 |

### 开发工具

| 项目 | 用途 | 许可 |
|------|------|------|
| [ESLint](https://eslint.org/) | 代码检查 | MIT |
| [TypeScript ESLint](https://typescript-eslint.io/) | TypeScript 代码检查 | MIT |
| [Vite React Plugin](https://github.com/vitejs/vite-plugin-react) | React 编译支持 | MIT |

### 威胁情报

感谢 **[微步在线 ThreatBook](https://x.threatbook.com/)** 提供的威胁情报 API 支持。

---

*再次感谢所有开源项目的贡献者，让本项目得以站在巨人的肩膀上。*
