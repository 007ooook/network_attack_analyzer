"""预测、IP 分析、攻击趋势。"""

import json
import sqlite3

from services.web.database import DatabaseConnection


class AnalyticsHandlersMixin:
    def handle_get_predictions(self, query_params):
        try:
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
        
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            cursor.execute('''
            SELECT id, prediction_time, attack_type, probability, prediction_date, model_version, created_at
            FROM predictions
            ORDER BY prediction_time DESC
            LIMIT ? OFFSET ?
            ''', (limit, offset))
        
            predictions = []
            for row in cursor.fetchall():
                prediction = {
                    'id': row['id'],
                    'prediction_time': row['prediction_time'],
                    'attack_type': row['attack_type'],
                    'probability': row['probability'],
                    'prediction_date': row['prediction_date'],
                    'model_version': row['model_version'],
                    'created_at': row['created_at']
                }
                predictions.append(prediction)
        
            conn.close()
        
            response = {'predictions': predictions, 'limit': limit, 'offset': offset}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting predictions: {str(e)}"}
            self.write_json(response)
    
    def handle_generate_prediction(self, data):
        try:
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            # 这里应该调用实际的预测模型，暂时使用模拟数据
            # 模拟预测结果
            import random
            attack_types = ['Brute Force', 'DDoS', 'SQL Injection', 'XSS', 'Malware']
            predictions = []
        
            time_range = data.get('time_range', '24h')
            attack_types_selected = data.get('attack_types', attack_types)
        
            # 生成模拟预测数据
            for attack_type in attack_types_selected:
                probability = random.uniform(0.1, 0.9)
                prediction_date = datetime.now().strftime('%Y-%m-%d')
            
                # 保存到数据库
                cursor.execute('''
                INSERT INTO predictions (prediction_time, attack_type, probability, prediction_date, model_version)
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    attack_type,
                    probability,
                    prediction_date,
                    '1.0.0'
                ))
            
                predictions.append({
                    'attack_type': attack_type,
                    'probability': probability,
                    'prediction_date': prediction_date
                })
        
            conn.commit()
            conn.close()
        
            response = {'predictions': predictions, 'message': 'Prediction generated successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error generating prediction: {str(e)}"}
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
    
    def _call_threatbook_api(self, api_key: str, ip: str) -> dict:
        """调用微步在线X情报社区API查询IP情报"""
        try:
            # 使用 v3 IP查询 API 端点
            api_url = 'https://api.threatbook.cn/v3/scene/ip_reputation'
            params = {
                'apikey': api_key,
                'resource': ip
            }
        
            print(f"调用微步API: {api_url}, params: {params}")
            response = requests.get(api_url, params=params, timeout=30)
            response.raise_for_status()
        
            result = response.json()
            print(f"微步API响应: {result}")
        
            return {
                'success': True,
                'result': result
            }
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            print(f"微步API调用异常: {error_msg}")
        
            if '401' in error_msg or '403' in error_msg:
                return {
                    'success': False,
                    'error': 'API密钥无效或权限不足，请检查API密钥配置'
                }
            elif '404' in error_msg:
                return {
                    'success': False,
                    'error': 'API端点不存在，请检查API URL'
                }
            elif 'timeout' in error_msg.lower():
                return {
                    'success': False,
                    'error': 'API调用超时，请稍后重试'
                }
            else:
                return {
                    'success': False,
                    'error': f'API调用失败: {error_msg}'
                }
        except Exception as e:
            error_msg = str(e)
            print(f"微步API调用异常: {error_msg}")
        
            return {
                'success': False,
                'error': f'API调用异常: {error_msg}'
            }

    def handle_analyze_ip(self, path):
        try:
            ip = path.split('/')[-1]
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            # 获取该 IP 的日志统计
            cursor.execute('''
            SELECT COUNT(*) as total_logs, 
                   COUNT(CASE WHEN a.attack_type != 'Normal' THEN 1 END) as attack_logs,
                   MAX(l.created_at) as last_seen
            FROM logs l
            LEFT JOIN analysis_results a ON l.id = a.log_id
            WHERE l.ip = ?
            ''', (ip,))
        
            result = cursor.fetchone()
        
            # 获取该 IP 的攻击类型分布
            cursor.execute('''
            SELECT a.attack_type, COUNT(*) as count
            FROM logs l
            LEFT JOIN analysis_results a ON l.id = a.log_id
            WHERE l.ip = ? AND a.attack_type != 'Normal'
            GROUP BY a.attack_type
            ORDER BY count DESC
            ''', (ip,))
        
            attack_distribution = [{'type': row['attack_type'], 'count': row['count']} for row in cursor.fetchall()]
        
            conn.close()
        
            response = {
                'ip': ip,
                'total_logs': result['total_logs'],
                'attack_logs': result['attack_logs'],
                'last_seen': result['last_seen'],
                'attack_distribution': attack_distribution
            }
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error analyzing IP: {str(e)}"}
            self.write_json(response)
    
    def handle_get_attack_trends(self, query_params):
        try:
            time_range = query_params.get('time_range', ['7d'])[0]
        
            conn = self.ctx.get_db_connection()
            cursor = conn.cursor()
        
            # 根据时间范围设置查询条件
            if time_range == "24h":
                time_format = "%H:00"
                time_column = "strftime('%H:00', created_at)"
            elif time_range == "7d":
                time_format = "%Y-%m-%d"
                time_column = "strftime('%Y-%m-%d', created_at)"
            elif time_range == "30d":
                time_format = "%Y-%m-%d"
                time_column = "strftime('%Y-%m-%d', created_at)"
            else:
                time_format = "%Y-%m-%d"
                time_column = "strftime('%Y-%m-%d', created_at)"
        
            # 获取攻击趋势
            cursor.execute(f'''
            SELECT {time_column} as hour, COUNT(*) as count
            FROM analysis_results
            WHERE attack_type != 'Normal' AND created_at >= datetime('now', '-{time_range}')
            GROUP BY hour
            ORDER BY hour
            ''')
        
            trends = [{'hour': row['hour'], 'count': row['count']} for row in cursor.fetchall()]
        
            conn.close()
        
            response = {'trends': trends, 'time_range': time_range}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting attack trends: {str(e)}"}
            self.write_json(response)
    
    def handle_get_metrics(self, query_params):
        try:
            from services.monitoring import get_metrics_summary
            
            # 获取时间范围
            hours = int(query_params.get('hours', ['24'])[0])
            
            # 获取指标摘要
            summary = get_metrics_summary(hours)
            
            response = {'metrics': summary, 'hours': hours}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting metrics: {str(e)}"}
            self.write_json(response)
