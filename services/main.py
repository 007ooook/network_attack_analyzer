import http.server
import socketserver
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import requests
import concurrent.futures
import ipaddress

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# 导入数据源管理器
try:
    from services.data_source_manager import get_data_source_manager, DataSourceConfig
    DATA_SOURCE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Data source manager not available: {e}")
    DATA_SOURCE_AVAILABLE = False

# 导入必要的模块
try:
    from utils.log_parsers import lines_to_entries
    from ai.models.anomaly_detection import AnomalyDetector
    from ai.models.attack_classifier import EnhancedAttackClassifier
    from ai.models.alert_deduplication import AlertManager, AlertPrioritizer
    from ai.models.alert_rules import AlertPolicyManager
    from ai.models.alert_notification import AlertNotificationManager, LogDetailedAction
    from config.database import init_database, DB_PATH
    
    # 初始化数据库
    init_database()
    
    # 初始化AI模型
    model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ai', 'models')
    anomaly_model_path = os.path.join(model_dir, 'anomaly_detector.joblib')
    classifier_model_path = os.path.join(model_dir, 'attack_classifier.joblib')
    
    anomaly_detector = AnomalyDetector(anomaly_model_path)
    attack_classifier = EnhancedAttackClassifier(classifier_model_path)
    alert_manager = AlertManager()
    policy_manager = AlertPolicyManager()
    notification_manager = AlertNotificationManager()
    
    # 创建默认规则和策略
    policy_manager.rule_engine.create_default_rules()
    policy_manager.create_default_policies()
    
    # 添加默认的响应动作
    log_detailed_action = LogDetailedAction(
        log_file=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'detailed_alerts.log'),
        enabled=True
    )
    notification_manager.add_response_action(log_detailed_action)
    
    # 启动后台通知工作线程
    notification_manager.start_background_worker()
    
    # 从数据库加载历史记录
    attack_classifier.load_history_from_database()
    
    AI_AVAILABLE = True
    print("Info: AI models loaded successfully")
except Exception as e:
    print(f"Warning: AI models not available: {e}")
    AI_AVAILABLE = False
    alert_manager = None

# 导入数据库连接函数（必须成功导入）
try:
    from config.database import get_db_connection
except ImportError as e:
    print(f"Error: Cannot import database connection: {e}")
    get_db_connection = None

# 数据库连接上下文管理器
class DatabaseConnection:
    """数据库连接上下文管理器，确保连接在使用后正确关闭"""
    def __init__(self):
        self.conn = None
    
    def __enter__(self):
        self.conn = get_db_connection()
        return self.conn
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            try:
                if exc_type is None:
                    self.conn.commit()
            except:
                pass
            finally:
                self.conn.close()
        return False

# 自定义HTTP请求处理器
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        # 处理前端静态文件和路由
        if path == '/' or path.startswith('/index.html') or (not path.startswith('/api/') and not path.startswith('/assets/') and not path.startswith('/locales/')):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'dist')
            index_path = os.path.join(frontend_dir, 'index.html')
            if os.path.exists(index_path):
                with open(index_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b'<html><head><title>Network Attack Analyzer</title></head><body><h1>Network Attack Analyzer</h1><p>Frontend files not found. Please run `npm run build` in the frontend directory.</p></body></html>')
        elif path.startswith('/assets/'):
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'dist')
            asset_path = os.path.join(frontend_dir, path.lstrip('/'))
            if os.path.exists(asset_path):
                with open(asset_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Not Found")
        elif path.startswith('/locales/'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'dist')
            locale_path = os.path.join(frontend_dir, path.lstrip('/'))
            if os.path.exists(locale_path):
                with open(locale_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Not Found")
        # 处理API请求
        elif path.startswith('/api/'):
            # 处理不同的API端点
            if path == '/api/logs':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_logs(query_params)
            elif path == '/api/statistics':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_statistics()
            elif path == '/api/config':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_config()
            elif path.startswith('/api/predict-attack/'):
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_predict_attack(path)
            elif path == '/api/threat-intel-summary':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_threat_intel_summary()
            elif path == '/api/system-health':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_system_health()
            elif path == '/api/threats':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_threats(query_params)
            elif path == '/api/predictions':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_predictions(query_params)
            elif path == '/api/attack-trends':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_attack_trends(query_params)
            elif path.startswith('/api/ip-analysis/'):
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_analyze_ip(path)
            elif path == '/api/data-sources':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_data_sources()
            elif path.startswith('/api/data-sources/'):
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_data_source_detail(path)
            elif path == '/api/data-source-logs':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_data_source_logs(query_params)
            elif path == '/api/alerts':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_alerts(query_params)
            elif path == '/api/alerts/statistics':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_alert_statistics()
            elif path == '/api/alert-rules':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_alert_rules()
            elif path.startswith('/api/alert-rules/'):
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_alert_rule_operations(path)
            elif path == '/api/alert-policies':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_alert_policies()
            elif path.startswith('/api/alert-policies/'):
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_alert_policy_operations(path)
            elif path == '/api/notification-history':
                # 设置CORS头
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.handle_get_notification_history(query_params)
            else:
                # 尝试提供其他静态文件
                frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'dist')
                file_path = os.path.join(frontend_dir, path.lstrip('/'))
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    self.send_response(200)
                    if file_path.endswith('.js'):
                        self.send_header('Content-type', 'application/javascript')
                    elif file_path.endswith('.css'):
                        self.send_header('Content-type', 'text/css')
                    elif file_path.endswith('.json'):
                        self.send_header('Content-type', 'application/json')
                    elif file_path.endswith('.svg'):
                        self.send_header('Content-type', 'image/svg+xml')
                    else:
                        self.send_header('Content-type', 'application/octet-stream')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    with open(file_path, 'rb') as f:
                        self.wfile.write(f.read())
                else:
                    self.send_error(404, "Not Found")
    
    def do_POST(self):
        # 设置CORS头
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        # 读取请求体
        content_length = self.headers.get('Content-Length')
        if content_length is None:
            content_length = 0
        else:
            content_length = int(content_length)
        
        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        
        # 处理不同的API端点
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # 解析请求体
        data = {}
        if path == '/api/parse':
            # 处理text/plain格式的请求体
            content_type = self.headers.get('Content-Type', '')
            if 'text/plain' in content_type:
                data = {'logs': post_data.decode('utf-8')}
            else:
                try:
                    data = json.loads(post_data)
                except json.JSONDecodeError:
                    data = {}
        else:
            # 处理其他POST端点的JSON请求体
            try:
                data = json.loads(post_data)
            except json.JSONDecodeError:
                data = {}
        
        # 处理具体的API端点
        if path == '/api/parse':
            self.handle_parse_logs(data)
        elif path == '/api/config':
            self.handle_update_config(data)
        elif path == '/api/config/single':
            self.handle_update_single_config(data)
        elif path == '/api/threats':
            self.handle_add_threat(data)
        elif path == '/api/predict':
            self.handle_generate_prediction(data)
        elif path == '/api/export-logs':
            self.handle_export_logs(data)
        elif path == '/api/behavior-analysis':
            self.handle_analyze_behavior(data)
        elif path == '/api/data-sources':
            self.handle_create_data_source(data)
        elif path.startswith('/api/data-sources/'):
            # 处理数据源相关操作
            parts = path.split('/')
            if len(parts) >= 4:
                source_id = parts[3]
                action = parts[4] if len(parts) > 4 else None
                if action == 'start':
                    self.handle_start_data_source(source_id)
                elif action == 'stop':
                    self.handle_stop_data_source(source_id)
                elif action == 'test':
                    self.handle_test_data_source(source_id, data)
                else:
                    self.handle_update_data_source(source_id, data)
            else:
                self.send_error(404, "Not Found")
        elif path == '/api/webhook-logs':
            self.handle_webhook_logs(data)
        elif path == '/api/alert-rules':
            self.handle_create_alert_rule(data)
        elif path == '/api/alert-policies':
            self.handle_create_alert_policy(data)
        elif path == '/api/fetch-threats':
            self.handle_fetch_threats(data)
        elif path == '/api/test-threat-intel':
            self.handle_test_threat_intel(data)
        else:
            self.send_error(404, "Not Found")
    
    def do_DELETE(self):
        # 处理DELETE请求
        path = self.path
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)
        else:
            data = {}
        
        # 设置CORS头
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        if path.startswith('/api/data-sources/'):
            # 处理删除数据源
            parts = path.split('/')
            if len(parts) == 4:
                source_id = parts[3]
                self.handle_delete_data_source(source_id)
            else:
                self.send_error(404, "Not Found")
        else:
            self.send_error(404, "Not Found")
    
    def do_OPTIONS(self):
        # 处理CORS预检请求
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def handle_get_logs(self, query_params):
        try:
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
            
            with DatabaseConnection() as conn:
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
                self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting logs: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_statistics(self):
        try:
            with DatabaseConnection() as conn:
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
                self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting statistics: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_config(self):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 检查配置表是否存在
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_config'")
            if not cursor.fetchone():
                # 创建配置表
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
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
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting config: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_update_config(self, data):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 确保配置表存在（只执行一次）
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
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
            
            response = {'message': 'System configuration updated successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error updating config: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_update_single_config(self, data):
        """处理单个配置项的更新"""
        try:
            key = data.get('key')
            value = data.get('value')
            
            if not key:
                response = {'error': 'Config key is required'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 确保配置表存在
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # 转换为字符串存储
            str_value = str(value)
            
            # 使用 INSERT OR REPLACE 语句，避免先查询再插入/更新
            cursor.execute('''
            INSERT OR REPLACE INTO system_config (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, str_value))
            
            conn.commit()
            conn.close()
            
            response = {'message': f'Config {key} updated successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error updating config: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_parse_logs(self, data):
        try:
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
                
                entries, invalid = lines_to_entries(iter(batch_lines))
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
                        if AI_AVAILABLE:
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
                            
                            anomaly_result = anomaly_detector.detect(ai_entry_dict)
                            classification_result = attack_classifier.classify(ai_entry_dict)
                            
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
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            print(f"处理日志时出错: {str(e)}")
            import traceback
            traceback.print_exc()
            response = {'error': f"Error parsing logs: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_predict_attack(self, path):
        try:
            # 解析IP地址
            ip = path.split('/')[-1]
            
            if not AI_AVAILABLE:
                response = {
                    'ip': ip,
                    'prediction': 'Normal',
                    'confidence': 0.5,
                    'risk_level': 'Low',
                    'metrics': {
                        'request_rate': 0,
                        'failure_rate': 0,
                        'path_diversity': 0,
                        'sample_size': 0
                    },
                    'recommendations': [
                        'AI models not available. Install numpy, scikit-learn, and joblib to enable AI predictions.',
                        'Monitor this IP for suspicious activity.',
                        'Check system logs for any unusual patterns.'
                    ]
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            # AI预测
            ai_prediction = attack_classifier.predict_future_attacks(ip)
            
            # 整合AI预测结果
            combined_result = ai_prediction
            
            self.wfile.write(json.dumps(combined_result).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error predicting attack: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_threat_intel_summary(self):
        try:
            if not AI_AVAILABLE:
                response = {'error': 'AI models not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            summary = attack_classifier.get_threat_intel_summary()
            self.wfile.write(json.dumps(summary).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting threat intel summary: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_system_health(self):
        try:
            import os
            import psutil
            
            # 获取数据库大小
            db_size = 0
            if os.path.exists(DB_PATH):
                db_size = os.path.getsize(DB_PATH) / (1024 * 1024)  # MB
            
            # 获取日志数量
            with DatabaseConnection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM logs')
                log_count = cursor.fetchone()[0]
            
            # 获取真实的系统资源使用情况
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            disk = psutil.disk_usage('/')
            disk_usage = disk.percent
            
            response = {
                'cpu_usage': round(cpu_usage, 1),
                'memory_usage': round(memory_usage, 1),
                'disk_usage': round(disk_usage, 1),
                'db_size': round(db_size, 2),
                'log_count': log_count
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            # 如果psutil不可用，使用默认值
            try:
                import os
                
                # 获取数据库大小
                db_size = 0
                if os.path.exists(DB_PATH):
                    db_size = os.path.getsize(DB_PATH) / (1024 * 1024)  # MB
                
                # 获取日志数量
                with DatabaseConnection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT COUNT(*) FROM logs')
                    log_count = cursor.fetchone()[0]
                
                response = {
                    'cpu_usage': 25.5,
                    'memory_usage': 45.2,
                    'disk_usage': 60.8,
                    'db_size': round(db_size, 2),
                    'log_count': log_count
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
            except Exception as e2:
                response = {'error': f"Error getting system health: {str(e2)}"}
                self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_threats(self, query_params):
        try:
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, indicator, indicator_type, threat_type, severity, description, source, created_at
            FROM threat_intel
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            threats = []
            for row in cursor.fetchall():
                threat = {
                    'id': row['id'],
                    'indicator': row['indicator'],
                    'indicator_type': row['indicator_type'],
                    'threat_type': row['threat_type'],
                    'severity': row['severity'],
                    'description': row['description'],
                    'source': row['source'],
                    'created_at': row['created_at']
                }
                threats.append(threat)
            
            conn.close()
            
            response = {'threats': threats, 'limit': limit, 'offset': offset}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting threats: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_fetch_threats(self, data):
        """从日志列表获取IP并查询微步API"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT value FROM system_config WHERE key = ?', ('api_key',))
            result = cursor.fetchone()
            
            if not result or not result['value']:
                conn.close()
                response = {
                    'success': False,
                    'error': 'API密钥未配置，请在系统设置中配置微步API密钥'
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            api_key = result['value']
            
            # 从日志列表获取唯一的IP地址
            cursor.execute('''
            SELECT DISTINCT ip FROM logs 
            WHERE ip IS NOT NULL AND ip != ''
            ''')
            log_ips = [row['ip'] for row in cursor.fetchall()]
            
            if not log_ips:
                conn.close()
                response = {
                    'success': False,
                    'error': '日志列表中没有找到IP地址'
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            print(f"从日志中获取到 {len(log_ips)} 个唯一IP")
            
            # 过滤内网IP地址
            def is_public_ip(ip_str):
                try:
                    ip = ipaddress.ip_address(ip_str)
                    return not ip.is_private and not ip.is_loopback and not ip.is_link_local
                except:
                    return False
            
            public_ips = [ip for ip in log_ips if is_public_ip(ip)]
            print(f"过滤后得到 {len(public_ips)} 个公网IP")
            
            if not public_ips:
                conn.close()
                response = {
                    'success': False,
                    'error': '日志列表中没有公网IP地址'
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            # 获取数据库中已有的威胁情报IP
            cursor.execute('SELECT DISTINCT indicator FROM threat_intel WHERE indicator_type = ?', ('ip',))
            existing_threats = set(row['indicator'] for row in cursor.fetchall())
            
            # 只查询未查询过的IP
            ips_to_query = [ip for ip in public_ips if ip not in existing_threats]
            
            print(f"需要查询 {len(ips_to_query)} 个新IP")
            
            if not ips_to_query:
                conn.close()
                response = {
                    'success': True,
                    'message': '所有IP已查询过，无需重复查询',
                    'fetched_count': 0
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            # 使用并发查询提高速度
            fetched_count = 0
            failed_count = 0
            
            def query_single_ip(ip):
                """查询单个IP的函数"""
                try:
                    api_result = self._call_threatbook_api(api_key, ip)
                    if not api_result['success']:
                        return {'ip': ip, 'success': False, 'error': api_result.get('error', '未知错误')}
                    
                    if not api_result.get('result'):
                        return {'ip': ip, 'success': False, 'error': '无返回数据'}
                    
                    result_data = api_result['result']
                    
                    # 处理 v3 scene API 响应格式
                    if result_data.get('response_code') != 0:
                        response_code = result_data.get('response_code')
                        verbose_msg = result_data.get('verbose_msg', '未知错误')
                        
                        if response_code == -1:
                            error_msg = f'API 密钥无效或没有访问权限: {verbose_msg}'
                        elif response_code == -2:
                            error_msg = f'API 调用方法无效: {verbose_msg}'
                        elif response_code == -3:
                            error_msg = f'请求频率超限: {verbose_msg}'
                        elif response_code == -4:
                            error_msg = f'超出访问限制: {verbose_msg}'
                        elif response_code == 1001:
                            error_msg = f'IP 资源格式错误: {verbose_msg}'
                        else:
                            error_msg = f'API 查询失败 (响应码: {response_code}): {verbose_msg}'
                        
                        return {'ip': ip, 'success': False, 'error': error_msg}
                    
                    # v3 IP查询 API 响应格式
                    ip_data = result_data.get('data', {}).get(ip, {})
                    
                    # 提取情报信息
                    basic = ip_data.get('basic', {})
                    location_info = basic.get('location', {})
                    location = f"{location_info.get('country', '')} {location_info.get('province', '')} {location_info.get('city', '')}".strip()
                    
                    isp = basic.get('carrier', '')
                    
                    asn = ip_data.get('asn', {})
                    asn_info = f"{asn.get('number', '')} {asn.get('info', '')}".strip()
                    
                    # 提取威胁信息
                    verdict = 'Unknown'
                    if ip_data.get('is_malicious', False):
                        verdict = 'malicious'
                    else:
                        verdict = 'benign'
                    
                    judgments = ip_data.get('judgments', [])
                    tag_str = ', '.join(judgments) if isinstance(judgments, list) else ''
                    
                    severity = ip_data.get('severity', 'info')
                    severity_map = {
                        'critical': 'High',
                        'high': 'High',
                        'medium': 'Medium',
                        'low': 'Low',
                        'info': 'Low'
                    }
                    severity = severity_map.get(severity, 'Low')
                    
                    # 构建描述
                    description_parts = []
                    if location:
                        description_parts.append(f"地理位置: {location}")
                    if isp:
                        description_parts.append(f"运营商: {isp}")
                    if verdict != 'Unknown':
                        description_parts.append(f"情报判定: {verdict}")
                    if tag_str:
                        description_parts.append(f"标签: {tag_str}")
                    if asn_info:
                        description_parts.append(f"ASN: {asn_info}")
                    
                    description = '\n'.join(description_parts) if description_parts else '无详细情报信息'
                    
                    threat_type = 'Malicious IP' if verdict == 'malicious' else 'Benign IP'
                    
                    return {
                        'ip': ip,
                        'success': True,
                        'threat_type': threat_type,
                        'severity': severity,
                        'description': description
                    }
                except Exception as e:
                    return {'ip': ip, 'success': False, 'error': str(e)}
            
            # 使用线程池并发查询
            max_workers = min(5, len(ips_to_query))  # 限制并发数
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {executor.submit(query_single_ip, ip): ip for ip in ips_to_query}
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    result = future.result()
                    if result['success']:
                        try:
                            cursor.execute('''
                            INSERT INTO threat_intel (indicator, indicator_type, threat_type, severity, description, source)
                            VALUES (?, ?, ?, ?, ?, ?)
                            ''', (result['ip'], 'ip', result['threat_type'], result['severity'], result['description'], 'ThreatBook API'))
                            fetched_count += 1
                            print(f"成功查询 IP {result['ip']}")
                        except Exception as e:
                            print(f"保存 IP {result['ip']} 数据失败: {str(e)}")
                    else:
                        failed_count += 1
                        print(f"查询 IP {result['ip']} 失败: {result['error']}")
            
            conn.commit()
            conn.close()
            
            response = {
                'success': True,
                'message': f'成功拉取 {fetched_count} 个信誉IP，失败 {failed_count} 个',
                'fetched_count': fetched_count,
                'failed_count': failed_count
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error fetching threats: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_test_threat_intel(self, data):
        """测试威胁情报API配置"""
        try:
            api_key = data.get('api_key', '')
            
            if not api_key:
                response = {
                    'success': False,
                    'error': 'API密钥未提供'
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            # 使用第一个日志IP进行测试
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT DISTINCT ip FROM logs 
            WHERE ip IS NOT NULL AND ip != ''
            LIMIT 1
            ''')
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                response = {
                    'success': False,
                    'error': '日志列表中没有找到IP地址用于测试'
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            test_ip = result['ip']
            api_result = self._call_threatbook_api(api_key, test_ip)
            
            if not api_result['success']:
                response = {
                    'success': False,
                    'error': api_result.get('error', 'API调用失败')
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            result_data = api_result['result']
            
            if result_data.get('response_code') != 0:
                response_code = result_data.get('response_code')
                verbose_msg = result_data.get('verbose_msg', '未知错误')
                
                if response_code == -1:
                    error_msg = f'API密钥无效或没有访问权限: {verbose_msg}'
                elif response_code == -2:
                    error_msg = f'API调用方法无效: {verbose_msg}'
                elif response_code == -3:
                    error_msg = f'请求频率超限: {verbose_msg}'
                elif response_code == -4:
                    error_msg = f'超出访问限制: {verbose_msg}'
                elif response_code == 1001:
                    error_msg = f'IP资源格式错误: {verbose_msg}'
                else:
                    error_msg = f'API查询失败 (响应码: {response_code}): {verbose_msg}'
                
                response = {
                    'success': False,
                    'error': error_msg
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            ip_data = result_data.get('data', {}).get(test_ip, {})
            
            # 成功测试
            verdict = 'Unknown'
            if ip_data.get('is_malicious', False):
                verdict = 'malicious'
            else:
                verdict = 'benign'
            
            response = {
                'success': True,
                'message': f'API连接成功！IP: {test_ip}, 情报判定: {verdict}'
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error testing threat intel: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_add_threat(self, data):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO threat_intel (indicator, indicator_type, threat_type, severity, description, source)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                data.get('indicator'),
                data.get('indicator_type'),
                data.get('threat_type'),
                data.get('severity'),
                data.get('description'),
                data.get('source')
            ))
            
            conn.commit()
            conn.close()
            
            response = {'message': 'Threat intelligence added successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error adding threat: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_predictions(self, query_params):
        try:
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
            
            conn = get_db_connection()
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
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting predictions: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_generate_prediction(self, data):
        try:
            conn = get_db_connection()
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
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error generating prediction: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_export_logs(self, data):
        try:
            conn = get_db_connection()
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
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error exporting logs: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_analyze_behavior(self, data):
        try:
            if not AI_AVAILABLE:
                response = {'error': 'AI models not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            analysis = attack_classifier.analyze_behavior_patterns(data)
            self.wfile.write(json.dumps(analysis).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error analyzing behavior: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
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
            conn = get_db_connection()
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
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error analyzing IP: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_attack_trends(self, query_params):
        try:
            time_range = query_params.get('time_range', ['7d'])[0]
            
            conn = get_db_connection()
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
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting attack trends: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def save_logs_batch(self, log_entries):
        """批量保存日志到数据库，减少数据库连接次数"""
        if not log_entries:
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 开始事务
            conn.execute('BEGIN TRANSACTION')
            
            # 批量插入日志
            logs_data = []
            analysis_data = []
            valid_indices = []
            
            for i, (log_entry, anomaly_result, classification_result) in enumerate(log_entries):
                # 计算威胁级别
                threat_level = 'Low'
                if anomaly_result['is_anomaly']:
                    if classification_result['attack_type'] != 'Normal' and classification_result['confidence'] > 0.7:
                        threat_level = 'High'
                    else:
                        threat_level = 'Medium'
                
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
            if alert_manager and valid_log_entries:
                alerts_to_generate = []
                for i, (log_entry, anomaly_result, classification_result) in enumerate(valid_log_entries):
                    if i < len(inserted_log_ids):
                        log_id = inserted_log_ids[i]
                        
                        # 重新计算威胁级别
                        threat_level = 'Low'
                        if anomaly_result['is_anomaly']:
                            if classification_result['attack_type'] != 'Normal' and classification_result['confidence'] > 0.7:
                                threat_level = 'High'
                            else:
                                threat_level = 'Medium'
                        
                        # 使用告警规则引擎评估
                        matched_rules = policy_manager.rule_engine.evaluate_rules(
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
                        processed_alerts = alert_manager.noise_reducer.process_alerts(alerts_to_generate)
                        
                        # 保存处理后的告警
                        for alert in processed_alerts:
                            if not alert.get('is_duplicate'):
                                alert_manager.save_alert(alert)
                                
                                # 触发告警通知
                                notification_manager.queue_alert(alert)
                                
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

    # ========== 数据源管理 API ==========
    def handle_get_data_sources(self):
        """获取所有数据源列表"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            manager = get_data_source_manager()
            sources = manager.get_all_data_sources()
            
            response = {
                'sources': [{
                    'id': s.id,
                    'name': s.name,
                    'source_type': s.source_type,
                    'enabled': s.enabled,
                    'status': s.status,
                    'created_at': s.created_at,
                    'updated_at': s.updated_at,
                    'last_error': s.last_error,
                    'last_connected_at': s.last_connected_at,
                    'total_logs_received': s.total_logs_received,
                    'total_logs_processed': s.total_logs_processed
                } for s in sources]
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting data sources: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_get_data_source_detail(self, path):
        """获取单个数据源详情"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            parts = path.split('/')
            if len(parts) < 4:
                self.send_error(404, "Not Found")
                return
            
            source_id = int(parts[3])
            manager = get_data_source_manager()
            source = manager.get_data_source(source_id)
            
            if not source:
                response = {'error': 'Data source not found'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            response = {
                'source': {
                    'id': source.id,
                    'name': source.name,
                    'source_type': source.source_type,
                    'enabled': source.enabled,
                    'status': source.status,
                    # Syslog配置
                    'syslog_host': source.syslog_host,
                    'syslog_port': source.syslog_port,
                    'syslog_protocol': source.syslog_protocol,
                    # 文件配置
                    'file_path': source.file_path,
                    'file_format': source.file_format,
                    'file_encoding': source.file_encoding,
                    'file_poll_interval': source.file_poll_interval,
                    # API配置
                    'api_url': source.api_url,
                    'api_method': source.api_method,
                    'api_headers': source.api_headers,
                    'api_auth_type': source.api_auth_type,
                    'api_poll_interval': source.api_poll_interval,
                    # Webhook配置
                    'webhook_secret': source.webhook_secret,
                    'webhook_verify_signature': source.webhook_verify_signature,
                    # 通用配置
                    'log_format': source.log_format,
                    'log_pattern': source.log_pattern,
                    'field_mapping': source.field_mapping,
                    'filters': source.filters,
                    'created_at': source.created_at,
                    'updated_at': source.updated_at,
                    'last_error': source.last_error,
                    'last_connected_at': source.last_connected_at,
                    'total_logs_received': source.total_logs_received,
                    'total_logs_processed': source.total_logs_processed
                }
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting data source: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_create_data_source(self, data):
        """创建数据源"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            config = DataSourceConfig(
                name=data.get('name', ''),
                source_type=data.get('source_type', ''),
                enabled=data.get('enabled', True),
                # Syslog配置
                syslog_host=data.get('syslog_host', '0.0.0.0'),
                syslog_port=data.get('syslog_port', 514),
                syslog_protocol=data.get('syslog_protocol', 'udp'),
                # 文件配置
                file_path=data.get('file_path', ''),
                file_format=data.get('file_format', 'auto'),
                file_encoding=data.get('file_encoding', 'utf-8'),
                file_poll_interval=data.get('file_poll_interval', 5),
                # API配置
                api_url=data.get('api_url', ''),
                api_method=data.get('api_method', 'GET'),
                api_headers=json.dumps(data.get('api_headers', {})),
                api_auth_type=data.get('api_auth_type', 'none'),
                api_auth_config=json.dumps(data.get('api_auth_config', {})),
                api_poll_interval=data.get('api_poll_interval', 60),
                # Webhook配置
                webhook_secret=data.get('webhook_secret', ''),
                webhook_verify_signature=data.get('webhook_verify_signature', False),
                # 通用配置
                log_format=data.get('log_format', 'auto'),
                log_pattern=data.get('log_pattern', ''),
                field_mapping=json.dumps(data.get('field_mapping', {})),
                filters=json.dumps(data.get('filters', {}))
            )
            
            manager = get_data_source_manager()
            source_id = manager.create_data_source(config)
            
            response = {'success': True, 'id': source_id, 'message': 'Data source created successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error creating data source: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_update_data_source(self, source_id, data):
        """更新数据源"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            source_id = int(source_id)
            manager = get_data_source_manager()
            
            existing = manager.get_data_source(source_id)
            if not existing:
                response = {'error': 'Data source not found'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            config = DataSourceConfig(
                id=source_id,
                name=data.get('name', existing.name),
                source_type=data.get('source_type', existing.source_type),
                enabled=data.get('enabled', existing.enabled),
                status=existing.status,
                # Syslog配置
                syslog_host=data.get('syslog_host', existing.syslog_host),
                syslog_port=data.get('syslog_port', existing.syslog_port),
                syslog_protocol=data.get('syslog_protocol', existing.syslog_protocol),
                # 文件配置
                file_path=data.get('file_path', existing.file_path),
                file_format=data.get('file_format', existing.file_format),
                file_encoding=data.get('file_encoding', existing.file_encoding),
                file_poll_interval=data.get('file_poll_interval', existing.file_poll_interval),
                # API配置
                api_url=data.get('api_url', existing.api_url),
                api_method=data.get('api_method', existing.api_method),
                api_headers=json.dumps(data.get('api_headers', {})) if 'api_headers' in data else existing.api_headers,
                api_auth_type=data.get('api_auth_type', existing.api_auth_type),
                api_auth_config=json.dumps(data.get('api_auth_config', {})) if 'api_auth_config' in data else existing.api_auth_config,
                api_poll_interval=data.get('api_poll_interval', existing.api_poll_interval),
                # Webhook配置
                webhook_secret=data.get('webhook_secret', existing.webhook_secret),
                webhook_verify_signature=data.get('webhook_verify_signature', existing.webhook_verify_signature),
                # 通用配置
                log_format=data.get('log_format', existing.log_format),
                log_pattern=data.get('log_pattern', existing.log_pattern),
                field_mapping=json.dumps(data.get('field_mapping', {})) if 'field_mapping' in data else existing.field_mapping,
                filters=json.dumps(data.get('filters', {})) if 'filters' in data else existing.filters
            )
            
            success = manager.update_data_source(source_id, config)
            
            response = {'success': success, 'message': 'Data source updated successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error updating data source: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_start_data_source(self, source_id):
        """启动数据源"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            source_id = int(source_id)
            manager = get_data_source_manager()
            success = manager.start_data_source(source_id)
            
            response = {'success': success, 'message': 'Data source started successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error starting data source: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_stop_data_source(self, source_id):
        """停止数据源"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            source_id = int(source_id)
            manager = get_data_source_manager()
            success = manager.stop_data_source(source_id)
            
            response = {'success': success, 'message': 'Data source stopped successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error stopping data source: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_test_data_source(self, source_id, data):
        """测试数据源连接"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            source_id = int(source_id)
            manager = get_data_source_manager()
            config = manager.get_data_source(source_id)
            
            if not config:
                response = {'error': 'Data source not found'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            # 根据数据源类型进行测试
            success = False
            message = ''
            
            if config.source_type == 'syslog':
                # 测试端口是否可用
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.bind((config.syslog_host, config.syslog_port))
                    success = True
                    message = f"Port {config.syslog_port} is available"
                except socket.error as e:
                    success = False
                    message = f"Port {config.syslog_port} is not available: {str(e)}"
                finally:
                    sock.close()
            
            elif config.source_type == 'file':
                if os.path.exists(config.file_path):
                    success = True
                    message = f"File exists: {config.file_path}"
                else:
                    success = False
                    message = f"File not found: {config.file_path}"
            
            elif config.source_type == 'api':
                import requests
                try:
                    headers = json.loads(config.api_headers) if config.api_headers else {}
                    auth = None
                    if config.api_auth_type == 'basic':
                        auth_config = json.loads(config.api_auth_config) if config.api_auth_config else {}
                        auth = (auth_config.get('username'), auth_config.get('password'))
                    elif config.api_auth_type == 'bearer':
                        auth_config = json.loads(config.api_auth_config) if config.api_auth_config else {}
                        headers['Authorization'] = f"Bearer {auth_config.get('token')}"
                    
                    resp = requests.request(
                        method=config.api_method,
                        url=config.api_url,
                        headers=headers,
                        auth=auth,
                        timeout=10
                    )
                    success = resp.status_code < 400
                    message = f"API responded with status {resp.status_code}"
                except Exception as e:
                    success = False
                    message = f"API test failed: {str(e)}"
            
            else:
                success = True
                message = "Test not implemented for this source type"
            
            response = {'success': success, 'message': message}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error testing data source: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_get_data_source_logs(self, query_params):
        """获取数据源接收的日志"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            source_id = query_params.get('source_id', [None])[0]
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
            
            try:
                conn = get_db_connection()
            except NameError:
                response = {'error': 'Database connection not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            cursor = conn.cursor()
            
            if source_id:
                cursor.execute('''
                    SELECT * FROM data_source_logs
                    WHERE source_id = ?
                    ORDER BY received_at DESC
                    LIMIT ? OFFSET ?
                ''', (source_id, limit, offset))
            else:
                cursor.execute('''
                    SELECT * FROM data_source_logs
                    ORDER BY received_at DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
            
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    'id': row['id'],
                    'source_id': row['source_id'],
                    'raw_log': row['raw_log'],
                    'parsed_log': json.loads(row['parsed_log']) if row['parsed_log'] else {},
                    'received_at': row['received_at'],
                    'processed': bool(row['processed']),
                    'error_message': row['error_message']
                })
            
            conn.close()
            
            response = {'logs': logs, 'limit': limit, 'offset': offset}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting data source logs: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_delete_data_source(self, source_id):
        """删除数据源"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            try:
                conn = get_db_connection()
            except NameError:
                response = {'error': 'Database connection not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            cursor = conn.cursor()
            
            # 开始事务
            conn.execute('BEGIN TRANSACTION')
            
            try:
                # 删除相关的日志记录
                cursor.execute('DELETE FROM data_source_logs WHERE source_id = ?', (source_id,))
                
                # 删除数据源记录
                cursor.execute('DELETE FROM data_sources WHERE id = ?', (source_id,))
                
                # 提交事务
                conn.execute('COMMIT')
                
                response = {'success': True, 'message': 'Data source deleted successfully'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
            except Exception as e:
                # 回滚事务
                conn.execute('ROLLBACK')
                response = {'error': f"Error deleting data source: {str(e)}"}
                self.wfile.write(json.dumps(response).encode('utf-8'))
            finally:
                conn.close()
        except Exception as e:
            response = {'error': f"Error deleting data source: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_webhook_logs(self, data):
        """接收Webhook日志"""
        try:
            if not DATA_SOURCE_AVAILABLE:
                response = {'error': 'Data source manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            # 从请求头中获取数据源标识
            source_name = self.headers.get('X-Data-Source', 'webhook')
            
            # 查找或创建Webhook数据源
            manager = get_data_source_manager()
            sources = manager.get_all_data_sources()
            
            webhook_source = None
            for s in sources:
                if s.source_type == 'webhook' and s.name == source_name:
                    webhook_source = s
                    break
            
            if not webhook_source:
                # 自动创建Webhook数据源
                config = DataSourceConfig(
                    name=source_name,
                    source_type='webhook',
                    enabled=True
                )
                source_id = manager.create_data_source(config)
            else:
                source_id = webhook_source.id
            
            # 处理接收到的日志
            log_data = {
                'raw': json.dumps(data),
                'parsed': data,
                'source': 'webhook',
                'received_at': datetime.now().isoformat()
            }
            
            manager._on_log_received(source_id, log_data)
            
            response = {'success': True, 'message': 'Log received'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error processing webhook: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_get_alerts(self, query_params):
        """获取告警列表"""
        try:
            if not alert_manager:
                response = {'error': 'Alert manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
            severity = query_params.get('severity', [None])[0]
            start_date = query_params.get('start_date', [None])[0]
            end_date = query_params.get('end_date', [None])[0]
            
            alerts = alert_manager.get_alerts(
                limit=limit,
                offset=offset,
                severity=severity,
                start_date=start_date,
                end_date=end_date
            )
            
            # 转换数字为布尔值
            for alert in alerts:
                alert['is_duplicate'] = bool(alert.get('is_duplicate', 0))
                alert['is_aggregated'] = bool(alert.get('is_aggregated', 0))
            
            response = {'alerts': alerts, 'limit': limit, 'offset': offset}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting alerts: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_alert_statistics(self):
        """获取告警统计信息"""
        try:
            if not alert_manager:
                response = {'error': 'Alert manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            statistics = alert_manager.get_alert_statistics()
            response = {'statistics': statistics}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting alert statistics: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_alert_rules(self):
        """获取所有告警规则"""
        try:
            if not policy_manager:
                response = {'error': 'Policy manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            rules = policy_manager.rule_engine.get_all_rules()
            rules_data = [{
                'rule_id': rule.rule_id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'conditions': rule.conditions,
                'actions': rule.actions
            } for rule in rules]
            
            response = {'rules': rules_data}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting alert rules: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_alert_rule_operations(self, path):
        """处理告警规则操作"""
        try:
            if not policy_manager:
                response = {'error': 'Policy manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            parts = path.split('/')
            if len(parts) < 4:
                self.send_error(400, "Bad Request")
                return
            
            rule_id = parts[3]
            action = parts[4] if len(parts) > 4 else None
            
            if action == 'enable':
                success = policy_manager.rule_engine.enable_rule(rule_id)
                response = {'success': success, 'message': f'Rule {rule_id} enabled' if success else 'Rule not found'}
            elif action == 'disable':
                success = policy_manager.rule_engine.disable_rule(rule_id)
                response = {'success': success, 'message': f'Rule {rule_id} disabled' if success else 'Rule not found'}
            elif action == 'delete':
                success = policy_manager.rule_engine.remove_rule(rule_id)
                response = {'success': success, 'message': f'Rule {rule_id} deleted' if success else 'Rule not found'}
            else:
                response = {'error': 'Invalid action'}
            
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error handling alert rule operation: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_alert_policies(self):
        """获取所有告警策略"""
        try:
            if not policy_manager:
                response = {'error': 'Policy manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            policies = policy_manager.get_all_policies()
            response = {'policies': policies}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting alert policies: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_alert_policy_operations(self, path):
        """处理告警策略操作"""
        try:
            if not policy_manager:
                response = {'error': 'Policy manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            parts = path.split('/')
            if len(parts) < 4:
                self.send_error(400, "Bad Request")
                return
            
            policy_id = parts[3]
            action = parts[4] if len(parts) > 4 else None
            
            if action == 'delete':
                success = policy_manager.delete_policy(policy_id)
                response = {'success': success, 'message': f'Policy {policy_id} deleted' if success else 'Policy not found'}
            else:
                response = {'error': 'Invalid action'}
            
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error handling alert policy operation: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_create_alert_rule(self, data):
        """创建告警规则"""
        try:
            if not policy_manager:
                response = {'error': 'Policy manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            rule_id = data.get('rule_id', f'rule_{datetime.now().timestamp()}')
            name = data.get('name')
            description = data.get('description', '')
            severity = data.get('severity', 'Medium')
            enabled = data.get('enabled', True)
            conditions = data.get('conditions', {})
            actions = data.get('actions', [])
            
            if not name:
                response = {'error': 'Rule name is required'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            from ai.models.alert_rules import AlertRule
            rule = AlertRule(
                rule_id=rule_id,
                name=name,
                description=description,
                severity=severity,
                enabled=enabled,
                conditions=conditions,
                actions=actions
            )
            
            policy_manager.rule_engine.add_rule(rule)
            response = {'success': True, 'rule_id': rule_id, 'message': 'Rule created successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error creating alert rule: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_create_alert_policy(self, data):
        """创建告警策略"""
        try:
            if not policy_manager:
                response = {'error': 'Policy manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            policy_id = data.get('policy_id', f'policy_{datetime.now().timestamp()}')
            name = data.get('name')
            description = data.get('description', '')
            enabled = data.get('enabled', True)
            alert_threshold = data.get('alert_threshold', 0.5)
            dedup_window_minutes = data.get('dedup_window_minutes', 30)
            aggregation_window_minutes = data.get('aggregation_window_minutes', 5)
            
            if not name:
                response = {'error': 'Policy name is required'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            policy_config = {
                'name': name,
                'description': description,
                'enabled': enabled,
                'alert_threshold': alert_threshold,
                'dedup_window_minutes': dedup_window_minutes,
                'aggregation_window_minutes': aggregation_window_minutes
            }
            
            policy_manager.add_policy(policy_id, policy_config)
            response = {'success': True, 'policy_id': policy_id, 'message': 'Policy created successfully'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error creating alert policy: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def handle_get_notification_history(self, query_params):
        """获取通知历史"""
        try:
            if not notification_manager:
                response = {'error': 'Notification manager not available'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
            
            history = notification_manager.get_notification_history(limit=limit, offset=offset)
            response = {'history': history, 'limit': limit, 'offset': offset}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            response = {'error': f"Error getting notification history: {str(e)}"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
# 启动服务器
def start_server():
    PORT = 8006
    Handler = RequestHandler
    
    # 设置SO_REUSEADDR选项，避免端口占用问题
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Server running at http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()
