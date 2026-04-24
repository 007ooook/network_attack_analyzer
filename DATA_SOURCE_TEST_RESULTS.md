# 数据源服务测试结果

## 测试时间
2026-04-03

## 测试环境
- 操作系统: Linux
- 服务端IP: 1.1.1.155
- 数据源端口: 1514
- 数据源协议: UDP

## 测试结果

### 1. 数据源服务状态
✅ **数据源服务运行正常**
- 服务进程: python3 services/main.py
- 数据源ID 1: 状态 active, 已接收 23+ 条日志
- 数据源ID 2: 状态 error (端口514需要特权权限)

### 2. UDP日志接收测试
✅ **UDP日志接收正常**
```bash
echo "Test message $(date)" | nc -u 1.1.1.155 1514
```
结果: 日志成功接收并保存到数据库

### 3. TCP连接测试
⚠️ **TCP连接被拒绝 (预期行为)**
```bash
echo "Test TCP message $(date)" | nc -v 1.1.1.155 1514
```
结果: `nc: connect to 1.1.1.155 port 1514 (tcp) failed: Connection refused`

**原因**: 数据源配置为UDP协议，TCP连接自然会被拒绝。

**正确测试方法**:
```bash
# 使用UDP协议测试
echo "Test syslog message $(date)" | nc -u 1.1.1.155 1514

# 或者使用socat
echo "Test message" | socat - UDP:1.1.1.155:1514
```

### 4. 错误处理优化
✅ **已优化的错误处理机制**
- 添加了更详细的日志记录
- 改进了UDP/TCP监听器的错误处理
- 添加了source_id参数用于追踪
- 优化了日志接收时的验证和错误报告

## 问题分析

### 用户报告的问题
用户使用以下命令测试:
```bash
echo "../../../etc/passwd $(date)" | nc -v 1.1.1.155 1514
```

得到结果: `Ncat: Connection refused`

### 原因分析
1. **协议不匹配**: 用户使用TCP协议(-v参数默认TCP)，但数据源配置的是UDP协议
2. **路径遍历尝试**: "../../../etc/passwd" 看起来像是路径遍历攻击尝试，但这对UDP端口没有影响

### 解决方案
1. **使用正确的协议**: 使用UDP协议测试
   ```bash
   echo "Test message" | nc -u 1.1.1.155 1514
   ```

2. **查看数据源配置**: 确认数据源使用的协议类型
   - 可以通过前端界面查看数据源配置
   - 或者查询数据库: `SELECT syslog_protocol FROM data_sources WHERE id=1;`

3. **使用正确的测试工具**: 
   - UDP: `nc -u <host> <port>`
   - TCP: `nc -v <host> <port>`

## 优化内容

### 1. 数据源管理器优化
- ✅ 添加了source_id参数到UDP/TCP监听器
- ✅ 改进了start()方法的错误处理
- ✅ 添加了更详细的启动日志
- ✅ 优化了stop()方法的资源清理
- ✅ 改进了_on_log_received()的日志验证和错误处理

### 2. 错误报告优化
- ✅ 添加了数据库错误的专门处理
- ✅ 改进了日志接收错误的追踪
- ✅ 添加了来源IP的记录
- ✅ 优化了错误信息的格式

### 3. 数据源列表功能
- ✅ 聚焦第三方日志资产管理
- ✅ 显示实时日志统计
- ✅ 显示威胁检测结果
- ✅ 显示最后错误信息

## 测试结论

✅ **数据源服务功能正常**
- UDP日志接收正常
- 错误处理机制完善
- 数据库记录正常
- 前端界面正常

⚠️ **用户报告的"Connection refused"是预期行为**
- 原因: 协议不匹配(TCP vs UDP)
- 解决: 使用UDP协议测试

## 使用建议

1. **测试数据源连接**:
   ```bash
   # UDP测试
   echo "Test message" | nc -u <host> <port>
   
   # TCP测试
   echo "Test message" | nc -v <host> <port>
   ```

2. **查看数据源配置**:
   ```bash
   curl http://localhost:8006/api/data-sources | jq .
   ```

3. **查看接收的日志**:
   ```bash
   curl "http://localhost:8006/api/data-source-logs?source_id=1&limit=10" | jq .
   ```

4. **使用前端界面管理**:
   - 访问: http://localhost:8006/datasource
   - 查看数据源状态
   - 查看实时日志
   - 测试数据源连接

## 附录

### 数据库查询
```sql
-- 查看所有数据源
SELECT id, name, source_type, syslog_host, syslog_port, syslog_protocol, status, enabled FROM data_sources;

-- 查看最近的日志
SELECT id, source_id, raw_log, received_at, processed FROM data_source_logs ORDER BY received_at DESC LIMIT 10;
```

### 日志文件位置
- 服务日志: /tmp/data_source_service.log
- 数据库: data/network_attack_analyzer.db
