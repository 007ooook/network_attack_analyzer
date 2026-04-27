"""日志、配置、导入解析与批量保存。"""

import json
import sqlite3
from datetime import datetime
from typing import Dict, Any

try:
    from services.cache import cached
except ImportError:
    def cached(ttl=None):
        def decorator(func):
            return func
        return decorator

from services.web.database import DatabaseConnection


def calculate_threat_level(classification_result: Dict[str, Any], anomaly_result: Dict[str, Any]) -> str:
    """计算威胁等级
    
    根据攻击类型、AI 分类的严重程度和置信度综合计算威胁等级
    
    Args:
        classification_result: 分类结果，包含 attack_type, confidence, severity
        anomaly_result: 异常检测结果，包含 is_anomaly, anomaly_score
        
    Returns:
        威胁等级：'Low', 'Medium', 'High', 'Critical'
    """
    # 获取攻击类型的基础严重程度
    attack_type = classification_result.get('attack_type', 'Normal')
    confidence = classification_result.get('confidence', 0)
    ai_severity = classification_result.get('severity', 'Low')
    is_anomaly = anomaly_result.get('is_anomaly', False)
    anomaly_score = anomaly_result.get('anomaly_score', 0)
    
    # 如果是正常流量
    if attack_type == 'Normal':
        return 'Low'
    
    # 如果置信度较高或异常检测非常确认，保持 AI 的严重程度判断
    if confidence >= 0.5 or anomaly_score >= 0.9:
        return ai_severity
    
    # 如果置信度中等，根据异常检测结果微调
    if confidence >= 0.3:
        # 如果异常检测也确认，保持 AI 的严重程度
        if is_anomaly and anomaly_score > 0.5:
            return ai_severity
        # 否则降低一级
        else:
            severity_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
            current_level = severity_order.get(ai_severity, 1)
            if current_level > 1:
                return [k for k, v in severity_order.items() if v == current_level - 1][0]
            return ai_severity
    
    # 如果置信度很低，主要依赖异常检测
    else:
        if is_anomaly and anomaly_score > 0.6:
            # 异常检测确认，降低一级
            severity_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
            current_level = severity_order.get(ai_severity, 1)
            if current_level > 1:
                return [k for k, v in severity_order.items() if v == current_level - 1][0]
            return ai_severity
        elif is_anomaly:
            return 'Low'
        else:
            return 'Low'


class LogsHandlersMixin:
    def handle_get_logs(self, query_params):
        try:
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
        
            with DatabaseConnection(self.ctx) as conn:
                cursor = conn.cursor()
            
                # 获取总日志数
                cursor.execute('SELECT COUNT(*) FROM logs')
                total_logs = cursor.fetchone()[0]
            
                cursor.execute('''
                SELECT l.id, l.timestamp, l.source, l.ip, l.method, l.path, l.status, l.size, 
                       l.referer, l.user_agent, l.raw_log, l.created_at,
                       a.anomaly_score, a.attack_type, a.confidence, a.threat_level
                FROM logs l
                LEFT JOIN analysis_results a ON l.id = a.log_id
                ORDER BY l.created_at DESC
                LIMIT ? OFFSET ?
                ''', (limit, offset))
            
                logs = []
                for row in cursor.fetchall():
                    log = {
                        'id': row['id'],
                        'timestamp': row['timestamp'],
                        'received_at': row['created_at'],
                        'source': row['source'],
                        'ip': row['ip'],
                        'method': row['method'],
                        'path': row['path'],
                        'status': row['status'],
                        'size': row['size'],
                        'referer': row['referer'],
                        'user_agent': row['user_agent'],
                        'raw_log': row['raw_log'],
                        'created_at': row['created_at'],
                        'analysis': {
                            'anomaly_score': row['anomaly_score'],
                            'attack_type': row['attack_type'],
                            'confidence': row['confidence'],
                            'threat_level': row['threat_level']
                        }
                    }
                    logs.append(log)
            
                response = {'logs': logs, 'limit': limit, 'offset': offset, 'total': total_logs}
                self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting logs: {str(e)}"}
            self.write_json(response)
    
    @cached(ttl=60)  # 缓存60秒
    def handle_get_statistics(self):
        try:
            with DatabaseConnection(self.ctx) as conn:
                cursor = conn.cursor()
            
                # 总日志数
                cursor.execute('SELECT COUNT(*) FROM logs')
                total_logs = cursor.fetchone()[0]
            
                # 异常日志数
                cursor.execute('SELECT COUNT(*) FROM analysis_results WHERE anomaly_score > 0.5')
                anomaly_logs = cursor.fetchone()[0]
            
                # 攻击类型分布
                cursor.execute('''
                SELECT attack_type, COUNT(*) as count
                FROM analysis_results
                WHERE attack_type != 'Normal'
                GROUP BY attack_type
                ORDER BY count DESC
                ''')
                attack_distribution = [{'type': row['attack_type'], 'count': row['count']} for row in cursor.fetchall()]
            
                # 最近24小时的攻击趋势
                cursor.execute('''
                SELECT strftime('%H:00', created_at) as hour, COUNT(*) as count
                FROM analysis_results
                WHERE attack_type != 'Normal' AND created_at >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
                ''')
                attack_trend = [{'hour': row['hour'], 'count': row['count']} for row in cursor.fetchall()]
            
                response = {
                    'total_logs': total_logs,
                    'anomaly_logs': anomaly_logs,
                    'attack_distribution': attack_distribution,
                    'attack_trend': attack_trend
                }
                self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting statistics: {str(e)}"}
            self.write_json(response)
    
    @cached(ttl=300)  # 缓存5分钟
    def handle_get_config(self):
        try:
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            cursor.execute('SELECT COUNT(*) FROM system_config')
            if cursor.fetchone()[0] == 0:
                # 插入默认配置
                default_config = {
                    'api_url': 'http://localhost:8003/api',
                    'log_retention_days': '30',
                    'max_log_size': '100',
                    'enable_email_alert': 'True',
                    'email_recipients': 'admin@example.com',
                    'alert_threshold': '0.7',
                    'model_version': '1.0.0',
                    'enable_rate_limiting': 'True',
                    'rate_limit': '1000',
                    'enable_ip_blocking': 'True',
                    'block_duration': '3600',
                    'enable_ssl': 'False',
                    'ssl_cert_path': '',
                    'ssl_key_path': '',
                    'enable_cors': 'True',
                    'allowed_origins': '*',
                    'api_key': ''
                }
            
                for key, value in default_config.items():
                    cursor.execute('''
                    INSERT INTO system_config (key, value)
                    VALUES (?, ?)
                    ''', (key, value))
                conn.commit()
        
            # 读取配置
            cursor.execute('SELECT key, value FROM system_config')
            config_rows = cursor.fetchall()
        
            config = {}
            for row in config_rows:
                key = row['key']
                value = row['value']
                # 转换类型
                if value == 'True':
                    config[key] = True
                elif value == 'False':
                    config[key] = False
                elif value.isdigit():
                    config[key] = int(value)
                elif '.' in value and all(part.isdigit() for part in value.split('.')) and value.count('.') == 1:
                    config[key] = float(value)
                else:
                    config[key] = value
        
            conn.close()
        
            response = {'config': config}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting config: {str(e)}"}
            self.write_json(response)

    def handle_update_config(self, data):
        try:
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            # 开始事务
            conn.execute('BEGIN TRANSACTION')
        
            # 批量处理配置更新
            for key, value in data.items():
                # 转换为字符串存储
                str_value = str(value)
            
                # 使用 INSERT OR REPLACE 语句，避免先查询再插入/更新
                cursor.execute('''
                INSERT OR REPLACE INTO system_config (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (key, str_value))
        
            # 提交事务
            conn.commit()
            conn.close()
        
            # 清除配置缓存
            if self.ctx.cache_available:
                # 清除handle_get_config的缓存
                cache_key = f"handle_get_config"
                self.ctx.cache_manager.delete(cache_key)
        
            response = {'message': 'System configuration updated successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error updating config: {str(e)}"}
            self.write_json(response)
    
    def handle_reset_config(self, data):
        """重置指定模块的配置为默认值"""
        try:
            section = data.get('section', '')
            default_configs = {
                'api': {
                    'api_url': 'http://localhost:65534',
                    'enable_cors': 'True',
                    'allowed_origins': '*'
                },
                'log': {
                    'log_retention_days': '30',
                    'max_log_size': '100'
                },
                'alert': {
                    'enable_email_alert': 'False',
                    'email_recipients': '',
                    'alert_threshold': '0.7'
                },
                'security': {
                    'enable_rate_limiting': 'True',
                    'rate_limit': '1000',
                    'enable_ip_blocking': 'False',
                    'block_duration': '3600',
                    'enable_ssl': 'False',
                    'ssl_cert_path': '',
                    'ssl_key_path': ''
                },
                'ai': {
                    'model_version': '1.0.0'
                },
                'threat_intel': {
                    'api_key': ''
                }
            }
            
            if section not in default_configs:
                self.write_json({'error': f'未知的配置模块: {section}'})
                return
            
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
            
            for key, value in default_configs[section].items():
                cursor.execute('''
                INSERT OR REPLACE INTO system_config (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (key, value))
            
            conn.commit()
            conn.close()
            
            if self.ctx.cache_available:
                cache_key = f"handle_get_config"
                self.ctx.cache_manager.delete(cache_key)
            
            self.write_json({'success': True, 'message': f'{section}配置已重置为默认值'})
        except Exception as e:
            self.write_json({'error': f"Error resetting config: {str(e)}"})
    
    def handle_update_single_config(self, data):
        """处理单个配置项的更新"""
        try:
            key = data.get('key')
            value = data.get('value')
        
            if not key:
                response = {'error': 'Config key is required'}
                self.write_json(response)
                return
        
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            # 转换为字符串存储
            str_value = str(value)
        
            # 使用 INSERT OR REPLACE 语句，避免先查询再插入/更新
            cursor.execute('''
            INSERT OR REPLACE INTO system_config (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, str_value))
        
            conn.commit()
            conn.close()
        
            # 清除配置缓存
            if self.ctx.cache_available:
                # 清除handle_get_config的缓存
                cache_key = f"handle_get_config"
                self.ctx.cache_manager.delete(cache_key)
        
            response = {'message': f'Config {key} updated successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error updating config: {str(e)}"}
            self.write_json(response)
    
    def handle_parse_logs(self, data):
        try:
            # 处理两种数据格式：字符串或字典
            if isinstance(data, str):
                logs = data
            else:
                logs = data.get('logs', '')
            # 解析日志
            lines = logs.strip().split('\n')
            print(f"解析日志行: {len(lines)} 行")
        
            # 分批处理日志
            batch_size = 1000
            parsed_entries = []
            log_entries_to_save = []
            total_entries = 0
            total_invalid = 0
            duplicate_count = 0
        
            # 存储已处理的日志特征，用于去重
            processed_logs = set()
        
            # 分批处理
            for i in range(0, len(lines), batch_size):
                batch_lines = lines[i:i + batch_size]
                print(f"处理批次 {i // batch_size + 1}: {len(batch_lines)} 行")
            
                entries, invalid = self.ctx.lines_to_entries(iter(batch_lines))
                total_entries += len(entries)
                total_invalid += invalid
            
                # 转换为字典格式
                for entry in entries:
                    try:
                        # 生成日志唯一标识符
                        log_key = f"{entry.ip}:{entry.timestamp.isoformat() if entry.timestamp else 'None'}:{entry.method}:{entry.path}"
                    
                        # 检查是否重复
                        if log_key in processed_logs:
                            duplicate_count += 1
                            continue
                    
                        # 添加到已处理集合
                        processed_logs.add(log_key)
                    
                        # 分析单个日志条目
                        if self.ctx.ai_available:
                            # 为AI模型创建一个包含datetime对象的字典
                            ai_entry_dict = {
                                'ip': entry.ip,
                                'timestamp': entry.timestamp,
                                'received_at': entry.received_at,
                                'method': entry.method,
                                'path': entry.path,
                                'status': entry.status,
                                'size': entry.size,
                                'referer': entry.referer,
                                'user_agent': entry.user_agent,
                                'query_params': entry.query_params,
                                'post_data': entry.post_data,
                                'headers': entry.headers,
                                'cookies': entry.cookies,
                                'url_path': entry.url_path,
                                'query_string': entry.query_string
                            }
                        
                            anomaly_result = self.ctx.anomaly_detector.detect(ai_entry_dict)
                            classification_result = self.ctx.attack_classifier.classify(ai_entry_dict)
                        
                            # 为API响应创建一个包含ISO格式字符串的字典
                            entry_dict = {
                                'ip': entry.ip,
                                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                                'received_at': entry.received_at.isoformat(),
                                'method': entry.method,
                                'path': entry.path,
                                'status': entry.status,
                                'size': entry.size,
                                'referer': entry.referer,
                                'user_agent': entry.user_agent,
                                'query_params': entry.query_params,
                                'post_data': entry.post_data,
                                'headers': entry.headers,
                                'cookies': entry.cookies,
                                'url_path': entry.url_path,
                                'query_string': entry.query_string,
                                'anomaly': anomaly_result,
                                'classification': classification_result
                            }
                        
                            log_entries_to_save.append((entry, anomaly_result, classification_result))
                        else:
                            # AI模型不可用时，使用默认分析结果
                            entry_dict = {
                                'ip': entry.ip,
                                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                                'received_at': entry.received_at.isoformat(),
                                'method': entry.method,
                                'path': entry.path,
                                'status': entry.status,
                                'size': entry.size,
                                'referer': entry.referer,
                                'user_agent': entry.user_agent,
                                'query_params': entry.query_params,
                                'post_data': entry.post_data,
                                'headers': entry.headers,
                                'cookies': entry.cookies,
                                'url_path': entry.url_path,
                                'query_string': entry.query_string,
                                'anomaly': {'score': 0.0, 'is_anomaly': False, 'anomaly_score': 0.0},
                                'classification': {'attack_type': 'Normal', 'confidence': 1.0, 'severity': 'Low'}
                            }
                            log_entries_to_save.append((entry, {'score': 0.0, 'is_anomaly': False, 'anomaly_score': 0.0}, {'attack_type': 'Normal', 'confidence': 1.0, 'severity': 'Low'}))
                    
                        parsed_entries.append(entry_dict)
                    except Exception as e:
                        print(f"处理条目时出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        continue
            
                # 每批处理完后保存到数据库
                if log_entries_to_save:
                    print(f"保存 {len(log_entries_to_save)} 个日志条目到数据库")
                    try:
                        self.save_logs_batch(log_entries_to_save)
                        print("保存成功")
                        log_entries_to_save = []  # 清空已保存的条目
                    except Exception as e:
                        print(f"保存到数据库时出错: {str(e)}")
        
            response = {
                'parsed': parsed_entries,
                'invalid_count': total_invalid,
                'duplicate_count': duplicate_count,
                'total_count': len(lines)
            }
            self.write_json(response)
        except Exception as e:
            print(f"处理日志时出错: {str(e)}")
            import traceback
            traceback.print_exc()
            response = {'error': f"Error parsing logs: {str(e)}"}
            self.write_json(response)
    def handle_export_logs(self, data):
        try:
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            # 根据条件查询日志
            query = '''
            SELECT l.*, a.anomaly_score, a.attack_type, a.confidence, a.threat_level
            FROM logs l
            LEFT JOIN analysis_results a ON l.id = a.log_id
            WHERE 1=1
            '''
            params = []
        
            if 'start_date' in data:
                query += ' AND l.created_at >= ?'
                params.append(data['start_date'])
        
            if 'end_date' in data:
                query += ' AND l.created_at <= ?'
                params.append(data['end_date'])
        
            if 'attack_type' in data and data['attack_type']:
                query += ' AND a.attack_type = ?'
                params.append(data['attack_type'])
        
            cursor.execute(query, params)
        
            logs = []
            for row in cursor.fetchall():
                log = {
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'source': row['source'],
                    'ip': row['ip'],
                    'method': row['method'],
                    'path': row['path'],
                    'status': row['status'],
                    'size': row['size'],
                    'referer': row['referer'],
                    'user_agent': row['user_agent'],
                    'raw_log': row['raw_log'],
                    'created_at': row['created_at'],
                    'anomaly_score': row['anomaly_score'],
                    'attack_type': row['attack_type'],
                    'confidence': row['confidence'],
                    'threat_level': row['threat_level']
                }
                logs.append(log)
        
            conn.close()
        
            response = {'logs': logs, 'count': len(logs)}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error exporting logs: {str(e)}"}
            self.write_json(response)
    
    def handle_analyze_behavior(self, data):
        try:
            if not self.ctx.ai_available:
                response = {'error': 'AI models not available'}
                self.write_json(response)
                return
        
            analysis = self.ctx.attack_classifier.analyze_behavior_patterns(data)
            self.write_json(analysis)
        except Exception as e:
            response = {'error': f"Error analyzing behavior: {str(e)}"}
            self.write_json(response)
    def save_logs_batch(self, log_entries):
        """批量保存日志到数据库，减少数据库连接次数"""
        if not log_entries:
            return
    
        conn = self.ctx.get_db_connection()
        cursor = conn.cursor()
    
        try:
            # 开始事务
            conn.execute('BEGIN TRANSACTION')
        
            # 内存去重：使用已存在的日志特征
            existing_logs = set()
            cursor.execute('SELECT ip, timestamp, method, path FROM logs')
            for row in cursor.fetchall():
                log_key = f"{row['ip']}:{row['timestamp']}:{row['method']}:{row['path']}"
                existing_logs.add(log_key)
        
            # 批量插入日志
            logs_data = []
            analysis_data = []
            valid_indices = []
            duplicate_count = 0
        
            for i, (log_entry, anomaly_result, classification_result) in enumerate(log_entries):
                # 生成日志唯一标识符
                log_key = f"{log_entry.ip}:{log_entry.timestamp.isoformat() if log_entry.timestamp else 'None'}:{log_entry.method}:{log_entry.path}"
            
                # 检查是否重复
                if log_key in existing_logs:
                    duplicate_count += 1
                    continue
            
                # 添加到已处理集合
                existing_logs.add(log_key)
            
                # 计算威胁级别 - 使用新的计算函数
                threat_level = calculate_threat_level(classification_result, anomaly_result)
            
                logs_data.append((
                    log_entry.timestamp.isoformat() if log_entry.timestamp else None,
                    'unknown',  # 可以根据实际情况设置来源
                    log_entry.ip,
                    log_entry.method,
                    log_entry.path,
                    log_entry.status,
                    log_entry.size,
                    log_entry.referer,
                    log_entry.user_agent,
                    log_entry.raw_line
                ))
            
                # 分析结果将在获取log_id后插入
                analysis_data.append((
                    None,  # log_id will be filled later
                    anomaly_result['anomaly_score'],
                    classification_result['attack_type'],
                    classification_result['confidence'],
                    threat_level,
                    'IsolationForest + RandomForest'
                ))
                valid_indices.append(i)
        
            if not logs_data:
                conn.rollback()
                print(f"所有日志都是重复的，跳过保存。重复数: {duplicate_count}")
                return
        
            # 获取插入前的最大ID
            cursor.execute('SELECT MAX(id) FROM logs')
            before_max_id = cursor.fetchone()[0] or 0
        
            # 批量插入日志
            cursor.executemany('''
            INSERT INTO logs (timestamp, source, ip, method, path, status, size, referer, user_agent, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', logs_data)
        
            # 获取插入后的最大ID
            cursor.execute('SELECT MAX(id) FROM logs')
            after_max_id = cursor.fetchone()[0] or 0
        
            # 计算实际插入的日志ID
            inserted_log_ids = []
            if after_max_id > before_max_id:
                # 生成连续的ID范围
                inserted_log_ids = list(range(before_max_id + 1, after_max_id + 1))
        
            # 只处理实际插入的日志的分析结果
            valid_analysis_data = []
            valid_log_entries = []
        
            for i, log_id in enumerate(inserted_log_ids):
                if i < len(analysis_data):
                    valid_analysis_data.append((log_id,) + analysis_data[i][1:])
                    if i < len(log_entries):
                        valid_log_entries.append(log_entries[i])
        
            # 批量插入分析结果
            if valid_analysis_data:
                cursor.executemany('''
                INSERT INTO analysis_results (log_id, anomaly_score, attack_type, confidence, threat_level, ai_model)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', valid_analysis_data)
        
            # 生成告警并进行降噪处理
            if self.ctx.alert_manager and valid_log_entries:
                alerts_to_generate = []
                for i, (log_entry, anomaly_result, classification_result) in enumerate(valid_log_entries):
                    if i < len(inserted_log_ids):
                        log_id = inserted_log_ids[i]
                    
                        # 重新计算威胁级别 - 使用新的计算函数
                        threat_level = calculate_threat_level(classification_result, anomaly_result)
                    
                        # 使用告警规则引擎评估
                        matched_rules = self.ctx.policy_manager.rule_engine.evaluate_rules(
                            {
                                'ip': log_entry.ip,
                                'method': log_entry.method,
                                'path': log_entry.path,
                                'status': log_entry.status,
                                'size': log_entry.size,
                                'referer': log_entry.referer,
                                'user_agent': log_entry.user_agent
                            },
                            {
                                'attack_type': classification_result['attack_type'],
                                'severity': threat_level,
                                'confidence': classification_result['confidence'],
                                'anomaly_score': anomaly_result['anomaly_score']
                            }
                        )
                    
                        # 如果有匹配的规则，生成告警
                        if matched_rules:
                            # 使用最高优先级的规则
                            highest_priority_rule = max(matched_rules, key=lambda r: AlertPrioritizer.SEVERITY_SCORES.get(r.severity, 50))
                        
                            alert = {
                                'alert_type': 'Security Alert',
                                'source_ip': log_entry.ip,
                                'target_ip': None,
                                'attack_type': classification_result['attack_type'],
                                'severity': highest_priority_rule.severity,
                                'confidence': classification_result['confidence'],
                                'description': f"检测到异常行为: {classification_result['attack_type']} (规则: {highest_priority_rule.name})",
                                'signature': f"{log_entry.ip}:{log_entry.path}:{classification_result['attack_type']}",
                                'timestamp': datetime.now(),
                                'matched_rules': [rule.rule_id for rule in matched_rules]
                            }
                            alerts_to_generate.append(alert)
            
                # 对告警进行降噪处理
                if alerts_to_generate:
                    try:
                        processed_alerts = self.ctx.alert_manager.noise_reducer.process_alerts(alerts_to_generate)
                    
                        # 保存处理后的告警
                        for alert in processed_alerts:
                            if not alert.get('is_duplicate'):
                                self.ctx.alert_manager.save_alert(alert)
                            
                                # 触发告警通知
                                self.ctx.notification_manager.queue_alert(alert)
                            
                        print(f"生成了 {len(processed_alerts)} 个告警，其中 {len([a for a in processed_alerts if not a.get('is_duplicate')])} 个为新告警")
                    except Exception as alert_error:
                        print(f"处理告警时出错: {alert_error}")
        
            # 提交事务
            conn.commit()
        except Exception as e:
            print(f"Error saving logs to database: {str(e)}")
            conn.rollback()
        finally:
            conn.close()
