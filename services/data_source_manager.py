"""数据源管理器"""

import os
import sqlite3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from .data_sources import (
    DataSource, DataSourceConfig, DataSourceType, DataSourceStatus,
    DataSourceFactory
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DataSourceManager:
    """数据源管理器"""
    
    def __init__(self, db_path: str = None, attack_classifier: Any = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'network_attack_analyzer.db')
        self.db_path = db_path
        self.active_connections: Dict[int, DataSource] = {}
        self.running = False
        self.attack_classifier = attack_classifier
        self._init_database()
        
        # 将自身设置到日志处理器中，避免循环依赖
        try:
            from .log_processor import get_log_processor
            log_processor = get_log_processor()
            log_processor.set_data_source_manager(self)
            logger.info("已将数据源管理器设置到日志处理器")
        except ImportError as e:
            logger.warning(f"导入日志处理器失败: {e}")
        except Exception as e:
            logger.error(f"设置日志处理器失败: {e}")
    
    def _get_connection(self):
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_database(self):
        """初始化数据源表"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # 创建数据源表（如果不存在）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS data_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'inactive',
                    
                    -- Syslog配置
                    syslog_host TEXT DEFAULT '0.0.0.0',
                    syslog_port INTEGER DEFAULT 1514,
                    syslog_protocol TEXT DEFAULT 'udp',
                    syslog_max_packet_size INTEGER DEFAULT 8192,
                    
                    -- 文件监控配置
                    file_path TEXT,
                    file_format TEXT DEFAULT 'auto',
                    file_encoding TEXT DEFAULT 'utf-8',
                    file_poll_interval INTEGER DEFAULT 5,
                    file_max_lines INTEGER DEFAULT 1000,
                    file_rotate_detection INTEGER DEFAULT 1,
                    
                    -- API配置
                    api_url TEXT,
                    api_method TEXT DEFAULT 'GET',
                    api_headers TEXT,
                    api_auth_type TEXT DEFAULT 'none',
                    api_auth_config TEXT,
                    api_poll_interval INTEGER DEFAULT 60,
                    api_timeout INTEGER DEFAULT 30,
                    api_retries INTEGER DEFAULT 3,
                    api_retry_interval INTEGER DEFAULT 5,
                    
                    -- Webhook配置
                    webhook_secret TEXT,
                    webhook_verify_signature INTEGER DEFAULT 0,
                    webhook_max_payload_size INTEGER DEFAULT 1048576,
                    
                    -- Kafka配置
                    kafka_bootstrap_servers TEXT DEFAULT 'localhost:9092',
                    kafka_topic TEXT DEFAULT 'logs',
                    kafka_group_id TEXT DEFAULT 'network_attack_analyzer',
                    kafka_auto_offset_reset TEXT DEFAULT 'latest',
                    kafka_max_poll_records INTEGER DEFAULT 100,
                    
                    -- Redis配置
                    redis_host TEXT DEFAULT 'localhost',
                    redis_port INTEGER DEFAULT 6379,
                    redis_db INTEGER DEFAULT 0,
                    redis_password TEXT,
                    redis_channel TEXT DEFAULT 'logs',
                    
                    -- ELK配置
                    elk_url TEXT DEFAULT 'http://localhost:9200',
                    elk_index TEXT DEFAULT 'logs-*',
                    elk_query TEXT,
                    elk_username TEXT,
                    elk_password TEXT,
                    
                    -- Splunk配置
                    splunk_url TEXT DEFAULT 'http://localhost:8089',
                    splunk_query TEXT DEFAULT 'search *',
                    splunk_username TEXT,
                    splunk_password TEXT,
                    splunk_interval INTEGER DEFAULT 60,
                    
                    -- Graylog配置
                    graylog_url TEXT DEFAULT 'http://localhost:12900',
                    graylog_query TEXT DEFAULT '*',
                    graylog_username TEXT,
                    graylog_password TEXT,
                    graylog_interval INTEGER DEFAULT 60,
                    
                    -- 通用配置
                    log_format TEXT DEFAULT 'auto',
                    log_pattern TEXT,
                    field_mapping TEXT,
                    filters TEXT,
                    batch_size INTEGER DEFAULT 100,
                    processing_timeout INTEGER DEFAULT 30,
                    enable_compression INTEGER DEFAULT 0,
                    
                    -- 实时处理配置
                    enable_realtime INTEGER DEFAULT 1,
                    realtime_buffer_size INTEGER DEFAULT 1000,
                    realtime_flush_interval INTEGER DEFAULT 1,
                    
                    -- 健康检查配置
                health_check_interval INTEGER DEFAULT 60,
                max_consecutive_errors INTEGER DEFAULT 5,
                
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_error TEXT,
                last_connected_at TEXT,
                last_log_received TEXT,
                last_source_ip TEXT,
                total_logs_received INTEGER DEFAULT 0,
                total_logs_processed INTEGER DEFAULT 0,
                total_errors INTEGER DEFAULT 0
                )
            ''')
            
            # 创建数据源日志接收表（如果不存在）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS data_source_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER,
                    raw_log TEXT,
                    parsed_log TEXT,
                    analyzed_log TEXT,
                    is_threat INTEGER DEFAULT 0,
                    severity TEXT DEFAULT 'Low',
                    received_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    processed INTEGER DEFAULT 0,
                    error_message TEXT,
                    source_ip TEXT DEFAULT '',
                    FOREIGN KEY (source_id) REFERENCES data_sources (id)
                )
            ''')
            
            # 创建数据源指标表（如果不存在）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS source_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    logs_received INTEGER DEFAULT 0,
                    logs_processed INTEGER DEFAULT 0,
                    errors INTEGER DEFAULT 0,
                    processing_time REAL DEFAULT 0,
                    FOREIGN KEY (source_id) REFERENCES data_sources (id)
                )
            ''')
            
            self._migrate_schema(cursor)
            conn.commit()
            logger.info("数据源管理表初始化完成")
        finally:
            conn.close()
    
    def _migrate_schema(self, cursor):
        """为已存在的数据库补齐新增列（SQLite IF NOT EXISTS 不会 ALTER 旧表）"""
        # 迁移 data_sources 表
        cursor.execute("PRAGMA table_info(data_sources)")
        existing = {row[1] for row in cursor.fetchall()}
        additions = [
            ("last_source_ip", "TEXT DEFAULT ''"),
        ]
        for col_name, col_def in additions:
            if col_name not in existing:
                cursor.execute(
                    f"ALTER TABLE data_sources ADD COLUMN {col_name} {col_def}"
                )
                logger.info("已添加缺失列 data_sources.%s", col_name)
        
        # 迁移 data_source_logs 表
        cursor.execute("PRAGMA table_info(data_source_logs)")
        existing_logs = {row[1] for row in cursor.fetchall()}
        log_additions = [
            ("source_ip", "TEXT DEFAULT ''"),
        ]
        for col_name, col_def in log_additions:
            if col_name not in existing_logs:
                cursor.execute(
                    f"ALTER TABLE data_source_logs ADD COLUMN {col_name} {col_def}"
                )
                logger.info("已添加缺失列 data_source_logs.%s", col_name)
    
    def create_data_source(self, config: DataSourceConfig) -> int:
        """创建数据源"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # 简化SQL语句，只插入必要的字段
            cursor.execute('''
                INSERT INTO data_sources (name, source_type, enabled, status)
                VALUES (?, ?, ?, ?)
            ''', (
                config.name, config.source_type, int(config.enabled), config.status
            ))
            conn.commit()
            source_id = cursor.lastrowid
            logger.info(f"数据源创建成功: {config.name} (ID: {source_id})")
            return source_id
        except Exception as e:
            logger.error(f"创建数据源失败: {e}")
            import traceback
            traceback.print_exc()
            raise
        finally:
            conn.close()
    
    def update_data_source(self, source_id: int, config: DataSourceConfig) -> bool:
        """更新数据源"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE data_sources SET
                    name = ?, source_type = ?, enabled = ?, status = ?,
                    syslog_host = ?, syslog_port = ?, syslog_protocol = ?, syslog_max_packet_size = ?,
                    file_path = ?, file_format = ?, file_encoding = ?, file_poll_interval = ?, file_max_lines = ?, file_rotate_detection = ?,
                    api_url = ?, api_method = ?, api_headers = ?, api_auth_type = ?, api_auth_config = ?, api_poll_interval = ?, api_timeout = ?, api_retries = ?, api_retry_interval = ?,
                    webhook_secret = ?, webhook_verify_signature = ?, webhook_max_payload_size = ?,
                    kafka_bootstrap_servers = ?, kafka_topic = ?, kafka_group_id = ?, kafka_auto_offset_reset = ?, kafka_max_poll_records = ?,
                    redis_host = ?, redis_port = ?, redis_db = ?, redis_password = ?, redis_channel = ?,
                    elk_url = ?, elk_index = ?, elk_query = ?, elk_username = ?, elk_password = ?,
                    splunk_url = ?, splunk_query = ?, splunk_username = ?, splunk_password = ?, splunk_interval = ?,
                    graylog_url = ?, graylog_query = ?, graylog_username = ?, graylog_password = ?, graylog_interval = ?,
                    log_format = ?, log_pattern = ?, field_mapping = ?, filters = ?, batch_size = ?, processing_timeout = ?, enable_compression = ?,
                    enable_realtime = ?, realtime_buffer_size = ?, realtime_flush_interval = ?,
                    health_check_interval = ?, max_consecutive_errors = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                config.name, config.source_type, int(config.enabled), config.status,
                config.syslog_host, config.syslog_port, config.syslog_protocol, config.syslog_max_packet_size,
                config.file_path, config.file_format, config.file_encoding, config.file_poll_interval, config.file_max_lines, int(config.file_rotate_detection),
                config.api_url, config.api_method, config.api_headers, config.api_auth_type, config.api_auth_config, config.api_poll_interval, config.api_timeout, config.api_retries, config.api_retry_interval,
                config.webhook_secret, int(config.webhook_verify_signature), config.webhook_max_payload_size,
                config.kafka_bootstrap_servers, config.kafka_topic, config.kafka_group_id, config.kafka_auto_offset_reset, config.kafka_max_poll_records,
                config.redis_host, config.redis_port, config.redis_db, config.redis_password, config.redis_channel,
                config.elk_url, config.elk_index, config.elk_query, config.elk_username, config.elk_password,
                config.splunk_url, config.splunk_query, config.splunk_username, config.splunk_password, config.splunk_interval,
                config.graylog_url, config.graylog_query, config.graylog_username, config.graylog_password, config.graylog_interval,
                config.log_format, config.log_pattern, config.field_mapping, config.filters, config.batch_size, config.processing_timeout, int(config.enable_compression),
                int(config.enable_realtime), config.realtime_buffer_size, config.realtime_flush_interval,
                config.health_check_interval, config.max_consecutive_errors,
                source_id
            ))
            conn.commit()
            logger.info(f"数据源更新成功: ID {source_id}")
            return True
        finally:
            conn.close()
    
    def delete_data_source(self, source_id: int) -> bool:
        """删除数据源"""
        # 先停止数据源
        self.stop_data_source(source_id)
        
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM data_sources WHERE id = ?", (source_id,))
            conn.commit()
            logger.info(f"数据源删除成功: ID {source_id}")
            return True
        finally:
            conn.close()
    
    def get_data_source(self, source_id: int) -> Optional[DataSourceConfig]:
        """获取数据源配置"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM data_sources WHERE id = ?", (source_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_config(row)
            return None
        finally:
            conn.close()
    
    def get_all_data_sources(self) -> List[DataSourceConfig]:
        """获取所有数据源"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM data_sources ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [self._row_to_config(row) for row in rows]
        finally:
            conn.close()
    
    def _row_to_config(self, row: sqlite3.Row) -> DataSourceConfig:
        """将数据库行转换为配置对象"""
        # 将sqlite3.Row转换为字典
        row_dict = dict(row)
        
        return DataSourceConfig(
            id=row_dict.get('id', None),
            name=row_dict.get('name', ''),
            source_type=row_dict.get('source_type', 'syslog'),
            enabled=bool(row_dict.get('enabled', 1)),
            status=row_dict.get('status', 'inactive'),
            syslog_host=row_dict.get('syslog_host', '0.0.0.0'),
            syslog_port=row_dict.get('syslog_port', 1514),
            syslog_protocol=row_dict.get('syslog_protocol', 'udp'),
            syslog_max_packet_size=row_dict.get('syslog_max_packet_size', 8192),
            file_path=row_dict.get('file_path', ''),
            file_format=row_dict.get('file_format', 'auto'),
            file_encoding=row_dict.get('file_encoding', 'utf-8'),
            file_poll_interval=row_dict.get('file_poll_interval', 5),
            file_max_lines=row_dict.get('file_max_lines', 1000),
            file_rotate_detection=bool(row_dict.get('file_rotate_detection', 1)),
            api_url=row_dict.get('api_url', ''),
            api_method=row_dict.get('api_method', 'GET'),
            api_headers=row_dict.get('api_headers', ''),
            api_auth_type=row_dict.get('api_auth_type', 'none'),
            api_auth_config=row_dict.get('api_auth_config', ''),
            api_poll_interval=row_dict.get('api_poll_interval', 60),
            api_timeout=row_dict.get('api_timeout', 30),
            api_retries=row_dict.get('api_retries', 3),
            api_retry_interval=row_dict.get('api_retry_interval', 5),
            webhook_secret=row_dict.get('webhook_secret', ''),
            webhook_verify_signature=bool(row_dict.get('webhook_verify_signature', 0)),
            webhook_max_payload_size=row_dict.get('webhook_max_payload_size', 1048576),
            kafka_bootstrap_servers=row_dict.get('kafka_bootstrap_servers', 'localhost:9092'),
            kafka_topic=row_dict.get('kafka_topic', 'logs'),
            kafka_group_id=row_dict.get('kafka_group_id', 'network_attack_analyzer'),
            kafka_auto_offset_reset=row_dict.get('kafka_auto_offset_reset', 'latest'),
            kafka_max_poll_records=row_dict.get('kafka_max_poll_records', 100),
            redis_host=row_dict.get('redis_host', 'localhost'),
            redis_port=row_dict.get('redis_port', 6379),
            redis_db=row_dict.get('redis_db', 0),
            redis_password=row_dict.get('redis_password', ''),
            redis_channel=row_dict.get('redis_channel', 'logs'),
            elk_url=row_dict.get('elk_url', 'http://localhost:9200'),
            elk_index=row_dict.get('elk_index', 'logs-*'),
            elk_query=row_dict.get('elk_query', ''),
            elk_username=row_dict.get('elk_username', ''),
            elk_password=row_dict.get('elk_password', ''),
            splunk_url=row_dict.get('splunk_url', 'http://localhost:8089'),
            splunk_query=row_dict.get('splunk_query', 'search *'),
            splunk_username=row_dict.get('splunk_username', ''),
            splunk_password=row_dict.get('splunk_password', ''),
            splunk_interval=row_dict.get('splunk_interval', 60),
            graylog_url=row_dict.get('graylog_url', 'http://localhost:12900'),
            graylog_query=row_dict.get('graylog_query', '*'),
            graylog_username=row_dict.get('graylog_username', ''),
            graylog_password=row_dict.get('graylog_password', ''),
            graylog_interval=row_dict.get('graylog_interval', 60),
            log_format=row_dict.get('log_format', 'auto'),
            log_pattern=row_dict.get('log_pattern', ''),
            field_mapping=row_dict.get('field_mapping', ''),
            filters=row_dict.get('filters', ''),
            batch_size=row_dict.get('batch_size', 100),
            processing_timeout=row_dict.get('processing_timeout', 30),
            enable_compression=bool(row_dict.get('enable_compression', 0)),
            enable_realtime=bool(row_dict.get('enable_realtime', 1)),
            realtime_buffer_size=row_dict.get('realtime_buffer_size', 1000),
            realtime_flush_interval=row_dict.get('realtime_flush_interval', 1),
            health_check_interval=row_dict.get('health_check_interval', 60),
            max_consecutive_errors=row_dict.get('max_consecutive_errors', 5),
            created_at=row_dict.get('created_at', ''),
            updated_at=row_dict.get('updated_at', ''),
            last_error=row_dict.get('last_error', ''),
            last_connected_at=row_dict.get('last_connected_at', ''),
            last_log_received=row_dict.get('last_log_received', ''),
            last_source_ip=row_dict.get('last_source_ip', ''),
            total_logs_received=row_dict.get('total_logs_received', 0),
            total_logs_processed=row_dict.get('total_logs_processed', 0),
            total_errors=row_dict.get('total_errors', 0)
        )
    
    def start_data_source(self, source_id: int) -> bool:
        """启动数据源"""
        config = self.get_data_source(source_id)
        if not config:
            logger.error(f"数据源不存在: ID {source_id}")
            return False
        
        if not config.enabled:
            logger.warning(f"数据源已禁用: {config.name}")
            return False
        
        if source_id in self.active_connections:
            logger.warning(f"数据源已在运行: {config.name}")
            return True
        
        try:
            self._update_status(source_id, DataSourceStatus.CONNECTING.value)
            
            # 创建数据源实例
            data_source = DataSourceFactory.create_data_source(
                source_id, config, lambda log: self._on_log_received(source_id, log)
            )
            
            # 启动数据源
            data_source.start()
            
            # 添加到活动连接
            self.active_connections[source_id] = data_source
            
            # 更新状态
            self._update_status(source_id, DataSourceStatus.ACTIVE.value)
            
            logger.info(f"数据源已启动: {config.name} (类型: {config.source_type})")
            return True
            
        except Exception as e:
            logger.error(f"启动数据源失败: {e}")
            self._update_status(source_id, DataSourceStatus.ERROR.value, str(e))
            return False
    
    def stop_data_source(self, source_id: int) -> bool:
        """停止数据源"""
        if source_id not in self.active_connections:
            return True
        
        try:
            data_source = self.active_connections[source_id]
            data_source.stop()
            del self.active_connections[source_id]
            self._update_status(source_id, DataSourceStatus.INACTIVE.value)
            logger.info(f"数据源已停止: ID {source_id}")
            return True
        except Exception as e:
            logger.error(f"停止数据源失败: {e}")
            return False
    
    def _update_status(self, source_id: int, status: str, error: str = None):
        """更新数据源状态"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if error:
                cursor.execute('''
                    UPDATE data_sources 
                    SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (status, error, source_id))
            else:
                cursor.execute('''
                    UPDATE data_sources 
                    SET status = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (status, source_id))
            conn.commit()
        finally:
            conn.close()
    
    def _on_log_received(self, source_id: int, log_data: Dict[str, Any]):
        """接收到日志时的回调"""
        try:
            # 验证日志数据
            if not log_data or 'raw' not in log_data:
                logger.warning(f"接收到无效日志数据: {log_data}")
                return
            
            # 获取数据源配置
            config = self.get_data_source(source_id)
            if not config:
                logger.error(f"数据源不存在: ID {source_id}")
                return
            
            # IP一对一绑定验证：数据源的监听地址必须与发送日志的客户端IP匹配
            source_ip = log_data.get('source_ip', '')
            configured_host = getattr(config, 'syslog_host', None)
            
            # 如果数据源配置了syslog_host，则验证来源IP是否匹配
            if configured_host and configured_host != '0.0.0.0' and configured_host != '::':
                # 对于非0.0.0.0的配置地址，进行IP一对一绑定验证
                if source_ip and source_ip != configured_host:
                    logger.warning(f"数据源 {source_id} 的监听地址 ({configured_host}) 与日志来源IP ({source_ip}) 不匹配，拒绝接收")
                    return
            
            # 解析日志
            try:
                from .log_analyzer import LogAnalyzer
                analyzer = LogAnalyzer(attack_classifier=self.attack_classifier)
                analysis_result = analyzer.analyze_log(log_data)
                parsed_log = analysis_result.get('parsed_data', {})
                parsed_log_json = json.dumps(parsed_log)
            except Exception as e:
                logger.warning(f"解析日志失败: {e}")
                parsed_log_json = '{}'
            
            # 保存原始日志和解析结果到数据库
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                # 获取来源IP
                logger.info(f"日志数据: {log_data}")
                source_ip = log_data.get('source_ip', '')
                logger.info(f"提取的source_ip: {source_ip}")
                cursor.execute('''
                    INSERT INTO data_source_logs (source_id, raw_log, parsed_log, source_ip)
                    VALUES (?, ?, ?, ?)
                ''', (
                    source_id,
                    log_data.get('raw', ''),
                    parsed_log_json,
                    source_ip
                ))
                
                log_id = cursor.lastrowid
                
                # 更新统计信息
                cursor.execute('''
                    UPDATE data_sources 
                    SET total_logs_received = total_logs_received + 1,
                        last_connected_at = CURRENT_TIMESTAMP,
                        last_log_received = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (source_id,))
                
                # 记录来源IP到数据源表
                if source_ip and source_ip != '':
                    cursor.execute('''
                        UPDATE data_sources 
                        SET last_source_ip = ?
                        WHERE id = ?
                    ''', (source_ip, source_id))
                
                conn.commit()
                
                logger.debug(f"收到日志: 数据源ID {source_id}, 日志ID {log_id}, 来源IP {source_ip}")
                
            finally:
                conn.close()
            
        except Exception as e:
            logger.error(f"处理日志失败: {e}")
            self._update_status(source_id, DataSourceStatus.ERROR.value, f"日志处理错误: {str(e)}")
    
    def get_supported_source_types(self) -> List[Dict[str, Any]]:
        """获取支持的数据源类型"""
        return [
            {
                "value": DataSourceType.SYSLOG.value,
                "label": "Syslog",
                "description": "接收Syslog协议的日志"
            },
            {
                "value": DataSourceType.FILE.value,
                "label": "文件监控",
                "description": "监控本地日志文件"
            },
            {
                "value": DataSourceType.API.value,
                "label": "API轮询",
                "description": "通过API轮询获取日志"
            },
            {
                "value": DataSourceType.WEBHOOK.value,
                "label": "Webhook",
                "description": "通过Webhook接收日志"
            },
            {
                "value": DataSourceType.KAFKA.value,
                "label": "Kafka",
                "description": "从Kafka消息队列获取日志"
            },
            {
                "value": DataSourceType.REDIS.value,
                "label": "Redis",
                "description": "从Redis消息队列获取日志"
            },
            {
                "value": DataSourceType.ELK.value,
                "label": "ELK Stack",
                "description": "从ELK Stack获取日志"
            },
            {
                "value": DataSourceType.SPLUNK.value,
                "label": "Splunk",
                "description": "从Splunk获取日志"
            },
            {
                "value": DataSourceType.GRAYLOG.value,
                "label": "Graylog",
                "description": "从Graylog获取日志"
            }
        ]
    
    def test_data_source_connection(self, config: DataSourceConfig) -> Dict[str, Any]:
        """测试数据源连接"""
        try:
            if config.source_type == DataSourceType.SYSLOG.value:
                # 测试Syslog连接
                import socket
                # 检查端口是否在有效范围内
                if not (1 <= config.syslog_port <= 65535):
                    return {"success": False, "message": "端口必须在1-65535范围内"}
                
                # 检查主机地址是否有效
                try:
                    socket.gethostbyname(config.syslog_host)
                except socket.gaierror:
                    return {"success": False, "message": "无效的主机地址"}
                
                return {"success": True, "message": "Syslog配置测试成功"}
            
            elif config.source_type == DataSourceType.FILE.value:
                # 测试文件存在
                if os.path.exists(config.file_path):
                    return {"success": True, "message": "文件存在测试成功"}
                else:
                    return {"success": False, "message": "文件不存在"}
            
            elif config.source_type == DataSourceType.API.value:
                # 测试API连接
                import requests
                headers = json.loads(config.api_headers) if config.api_headers else {}
                auth = None
                if config.api_auth_type == 'basic':
                    auth_config = json.loads(config.api_auth_config) if config.api_auth_config else {}
                    auth = (auth_config.get('username'), auth_config.get('password'))
                elif config.api_auth_type == 'bearer':
                    auth_config = json.loads(config.api_auth_config) if config.api_auth_config else {}
                    headers['Authorization'] = f"Bearer {auth_config.get('token')}"
                elif config.api_auth_type == 'apikey':
                    auth_config = json.loads(config.api_auth_config) if config.api_auth_config else {}
                    apikey_header = auth_config.get('header', 'X-API-Key')
                    headers[apikey_header] = auth_config.get('key')
                
                response = requests.request(
                    method=config.api_method,
                    url=config.api_url,
                    headers=headers,
                    auth=auth,
                    timeout=10
                )
                if response.status_code < 400:
                    return {"success": True, "message": f"API连接测试成功，状态码: {response.status_code}"}
                else:
                    return {"success": False, "message": f"API连接测试失败，状态码: {response.status_code}"}
            
            else:
                # 其他数据源类型的测试
                return {"success": True, "message": "数据源类型不需要测试连接"}
                
        except Exception as e:
            return {"success": False, "message": f"测试失败: {str(e)}"}


# 单例实例
_data_source_manager_instance = None

def get_data_source_manager(attack_classifier=None):
    """获取数据源管理器实例（单例）"""
    global _data_source_manager_instance
    if _data_source_manager_instance is None:
        _data_source_manager_instance = DataSourceManager(attack_classifier=attack_classifier)
    return _data_source_manager_instance
