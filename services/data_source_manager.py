"""
数据源管理模块
支持多种日志数据源接入：Syslog、文件监控、第三方API等
"""

import os
import sys
import json
import sqlite3
import asyncio
import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataSourceType(Enum):
    """数据源类型"""
    SYSLOG = "syslog"
    FILE = "file"
    API = "api"
    WEBHOOK = "webhook"
    KAFKA = "kafka"
    REDIS = "redis"

class DataSourceStatus(Enum):
    """数据源状态"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    CONNECTING = "connecting"

@dataclass
class DataSourceConfig:
    """数据源配置"""
    id: Optional[int] = None
    name: str = ""
    source_type: str = ""
    enabled: bool = True
    status: str = "inactive"
    
    # Syslog配置
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp/tcp
    
    # 文件监控配置
    file_path: str = ""
    file_format: str = "auto"  # auto/apache/nginx/syslog/json
    file_encoding: str = "utf-8"
    file_poll_interval: int = 5  # 秒
    
    # API配置
    api_url: str = ""
    api_method: str = "GET"
    api_headers: str = ""  # JSON格式
    api_auth_type: str = "none"  # none/basic/bearer/apikey
    api_auth_config: str = ""  # JSON格式
    api_poll_interval: int = 60  # 秒
    
    # Webhook配置
    webhook_secret: str = ""
    webhook_verify_signature: bool = False
    
    # Kafka配置
    kafka_brokers: str = ""
    kafka_topic: str = ""
    kafka_group_id: str = ""
    
    # Redis配置
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_channel: str = ""
    
    # 通用配置
    log_format: str = "auto"  # auto/apache/nginx/syslog/json/custom
    log_pattern: str = ""  # 自定义日志格式正则
    field_mapping: str = ""  # 字段映射 JSON
    filters: str = ""  # 过滤规则 JSON
    
    created_at: str = ""
    updated_at: str = ""
    last_error: str = ""
    last_connected_at: str = ""
    total_logs_received: int = 0
    total_logs_processed: int = 0

class DataSourceManager:
    """数据源管理器"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'network_attack_analyzer.db')
        self.db_path = db_path
        self.active_connections: Dict[int, Any] = {}
        self.running = False
        self._init_database()
    
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
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS data_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'inactive',
                    
                    -- Syslog配置
                    syslog_host TEXT DEFAULT '0.0.0.0',
                    syslog_port INTEGER DEFAULT 514,
                    syslog_protocol TEXT DEFAULT 'udp',
                    
                    -- 文件监控配置
                    file_path TEXT,
                    file_format TEXT DEFAULT 'auto',
                    file_encoding TEXT DEFAULT 'utf-8',
                    file_poll_interval INTEGER DEFAULT 5,
                    
                    -- API配置
                    api_url TEXT,
                    api_method TEXT DEFAULT 'GET',
                    api_headers TEXT,
                    api_auth_type TEXT DEFAULT 'none',
                    api_auth_config TEXT,
                    api_poll_interval INTEGER DEFAULT 60,
                    
                    -- Webhook配置
                    webhook_secret TEXT,
                    webhook_verify_signature INTEGER DEFAULT 0,
                    
                    -- Kafka配置
                    kafka_brokers TEXT,
                    kafka_topic TEXT,
                    kafka_group_id TEXT,
                    
                    -- Redis配置
                    redis_host TEXT DEFAULT 'localhost',
                    redis_port INTEGER DEFAULT 6379,
                    redis_db INTEGER DEFAULT 0,
                    redis_channel TEXT,
                    
                    -- 通用配置
                    log_format TEXT DEFAULT 'auto',
                    log_pattern TEXT,
                    field_mapping TEXT,
                    filters TEXT,
                    
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_error TEXT,
                    last_connected_at TEXT,
                    total_logs_received INTEGER DEFAULT 0,
                    total_logs_processed INTEGER DEFAULT 0
                )
            ''')
            
            # 创建数据源日志接收表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS data_source_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER,
                    raw_log TEXT,
                    parsed_log TEXT,
                    received_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    processed INTEGER DEFAULT 0,
                    error_message TEXT,
                    FOREIGN KEY (source_id) REFERENCES data_sources (id)
                )
            ''')
            
            conn.commit()
            logger.info("数据源管理表初始化完成")
        finally:
            conn.close()
    
    def create_data_source(self, config: DataSourceConfig) -> int:
        """创建数据源"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO data_sources (
                    name, source_type, enabled, status,
                    syslog_host, syslog_port, syslog_protocol,
                    file_path, file_format, file_encoding, file_poll_interval,
                    api_url, api_method, api_headers, api_auth_type, api_auth_config, api_poll_interval,
                    webhook_secret, webhook_verify_signature,
                    kafka_brokers, kafka_topic, kafka_group_id,
                    redis_host, redis_port, redis_db, redis_channel,
                    log_format, log_pattern, field_mapping, filters
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                config.name, config.source_type, int(config.enabled), config.status,
                config.syslog_host, config.syslog_port, config.syslog_protocol,
                config.file_path, config.file_format, config.file_encoding, config.file_poll_interval,
                config.api_url, config.api_method, config.api_headers, config.api_auth_type, 
                config.api_auth_config, config.api_poll_interval,
                config.webhook_secret, int(config.webhook_verify_signature),
                config.kafka_brokers, config.kafka_topic, config.kafka_group_id,
                config.redis_host, config.redis_port, config.redis_db, config.redis_channel,
                config.log_format, config.log_pattern, config.field_mapping, config.filters
            ))
            conn.commit()
            source_id = cursor.lastrowid
            logger.info(f"数据源创建成功: {config.name} (ID: {source_id})")
            return source_id
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
                    syslog_host = ?, syslog_port = ?, syslog_protocol = ?,
                    file_path = ?, file_format = ?, file_encoding = ?, file_poll_interval = ?,
                    api_url = ?, api_method = ?, api_headers = ?, api_auth_type = ?, 
                    api_auth_config = ?, api_poll_interval = ?,
                    webhook_secret = ?, webhook_verify_signature = ?,
                    kafka_brokers = ?, kafka_topic = ?, kafka_group_id = ?,
                    redis_host = ?, redis_port = ?, redis_db = ?, redis_channel = ?,
                    log_format = ?, log_pattern = ?, field_mapping = ?, filters = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                config.name, config.source_type, int(config.enabled), config.status,
                config.syslog_host, config.syslog_port, config.syslog_protocol,
                config.file_path, config.file_format, config.file_encoding, config.file_poll_interval,
                config.api_url, config.api_method, config.api_headers, config.api_auth_type,
                config.api_auth_config, config.api_poll_interval,
                config.webhook_secret, int(config.webhook_verify_signature),
                config.kafka_brokers, config.kafka_topic, config.kafka_group_id,
                config.redis_host, config.redis_port, config.redis_db, config.redis_channel,
                config.log_format, config.log_pattern, config.field_mapping, config.filters,
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
        return DataSourceConfig(
            id=row['id'],
            name=row['name'],
            source_type=row['source_type'],
            enabled=bool(row['enabled']),
            status=row['status'],
            syslog_host=row['syslog_host'],
            syslog_port=row['syslog_port'],
            syslog_protocol=row['syslog_protocol'],
            file_path=row['file_path'],
            file_format=row['file_format'],
            file_encoding=row['file_encoding'],
            file_poll_interval=row['file_poll_interval'],
            api_url=row['api_url'],
            api_method=row['api_method'],
            api_headers=row['api_headers'],
            api_auth_type=row['api_auth_type'],
            api_auth_config=row['api_auth_config'],
            api_poll_interval=row['api_poll_interval'],
            webhook_secret=row['webhook_secret'],
            webhook_verify_signature=bool(row['webhook_verify_signature']),
            kafka_brokers=row['kafka_brokers'],
            kafka_topic=row['kafka_topic'],
            kafka_group_id=row['kafka_group_id'],
            redis_host=row['redis_host'],
            redis_port=row['redis_port'],
            redis_db=row['redis_db'],
            redis_channel=row['redis_channel'],
            log_format=row['log_format'],
            log_pattern=row['log_pattern'],
            field_mapping=row['field_mapping'],
            filters=row['filters'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            last_error=row['last_error'],
            last_connected_at=row['last_connected_at'],
            total_logs_received=row['total_logs_received'],
            total_logs_processed=row['total_logs_processed']
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
            if config.source_type == DataSourceType.SYSLOG.value:
                return self._start_syslog_source(source_id, config)
            elif config.source_type == DataSourceType.FILE.value:
                return self._start_file_source(source_id, config)
            elif config.source_type == DataSourceType.API.value:
                return self._start_api_source(source_id, config)
            elif config.source_type == DataSourceType.WEBHOOK.value:
                # Webhook不需要主动启动，由HTTP端点处理
                self._update_status(source_id, DataSourceStatus.ACTIVE.value)
                return True
            else:
                logger.error(f"不支持的数据源类型: {config.source_type}")
                return False
        except Exception as e:
            logger.error(f"启动数据源失败: {e}")
            self._update_status(source_id, DataSourceStatus.ERROR.value, str(e))
            return False
    
    def stop_data_source(self, source_id: int) -> bool:
        """停止数据源"""
        if source_id not in self.active_connections:
            return True
        
        try:
            connection = self.active_connections[source_id]
            if hasattr(connection, 'stop'):
                connection.stop()
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
    
    def _start_syslog_source(self, source_id: int, config: DataSourceConfig) -> bool:
        """启动Syslog数据源"""
        try:
            self._update_status(source_id, DataSourceStatus.CONNECTING.value)
            
            # 检查端口是否为特权端口
            if config.syslog_port < 1024:
                raise PermissionError(f"端口 {config.syslog_port} 是特权端口，需要管理员权限。请使用大于1024的端口。")
            
            if config.syslog_protocol == 'udp':
                listener = SyslogUDPListener(
                    host=config.syslog_host,
                    port=config.syslog_port,
                    callback=lambda log: self._on_log_received(source_id, log)
                )
            else:
                listener = SyslogTCPListener(
                    host=config.syslog_host,
                    port=config.syslog_port,
                    callback=lambda log: self._on_log_received(source_id, log)
                )
            
            listener.start()
            self.active_connections[source_id] = listener
            self._update_status(source_id, DataSourceStatus.ACTIVE.value)
            
            logger.info(f"Syslog数据源已启动: {config.name} ({config.syslog_host}:{config.syslog_port})")
            return True
            
        except PermissionError as e:
            logger.error(f"启动Syslog数据源失败: {e}")
            self._update_status(source_id, DataSourceStatus.ERROR.value, str(e))
            return False
        except Exception as e:
            logger.error(f"启动Syslog数据源失败: {e}")
            self._update_status(source_id, DataSourceStatus.ERROR.value, str(e))
            return False
    
    def _start_file_source(self, source_id: int, config: DataSourceConfig) -> bool:
        """启动文件监控数据源"""
        try:
            if not os.path.exists(config.file_path):
                raise FileNotFoundError(f"日志文件不存在: {config.file_path}")
            
            self._update_status(source_id, DataSourceStatus.CONNECTING.value)
            
            monitor = FileLogMonitor(
                file_path=config.file_path,
                callback=lambda log: self._on_log_received(source_id, log),
                poll_interval=config.file_poll_interval,
                encoding=config.file_encoding
            )
            
            monitor.start()
            self.active_connections[source_id] = monitor
            self._update_status(source_id, DataSourceStatus.ACTIVE.value)
            
            logger.info(f"文件监控数据源已启动: {config.name} ({config.file_path})")
            return True
            
        except Exception as e:
            logger.error(f"启动文件监控数据源失败: {e}")
            self._update_status(source_id, DataSourceStatus.ERROR.value, str(e))
            return False
    
    def _start_api_source(self, source_id: int, config: DataSourceConfig) -> bool:
        """启动API轮询数据源"""
        try:
            self._update_status(source_id, DataSourceStatus.CONNECTING.value)
            
            poller = APIPoller(
                url=config.api_url,
                method=config.api_method,
                headers=json.loads(config.api_headers) if config.api_headers else {},
                auth_type=config.api_auth_type,
                auth_config=json.loads(config.api_auth_config) if config.api_auth_config else {},
                poll_interval=config.api_poll_interval,
                callback=lambda log: self._on_log_received(source_id, log)
            )
            
            poller.start()
            self.active_connections[source_id] = poller
            self._update_status(source_id, DataSourceStatus.ACTIVE.value)
            
            logger.info(f"API数据源已启动: {config.name} ({config.api_url})")
            return True
            
        except Exception as e:
            logger.error(f"启动API数据源失败: {e}")
            self._update_status(source_id, DataSourceStatus.ERROR.value, str(e))
            return False
    
    def _on_log_received(self, source_id: int, log_data: Dict[str, Any]):
        """接收到日志时的回调"""
        try:
            # 保存原始日志到数据库
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO data_source_logs (source_id, raw_log, parsed_log)
                    VALUES (?, ?, ?)
                ''', (
                    source_id,
                    log_data.get('raw', ''),
                    json.dumps(log_data.get('parsed', {}))
                ))
                
                # 更新统计信息
                cursor.execute('''
                    UPDATE data_sources 
                    SET total_logs_received = total_logs_received + 1,
                        last_connected_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (source_id,))
                
                conn.commit()
            finally:
                conn.close()
            
            # TODO: 将日志转发到分析引擎
            logger.debug(f"收到日志: 数据源ID {source_id}")
            
        except Exception as e:
            logger.error(f"处理日志失败: {e}")


class SyslogUDPListener:
    """Syslog UDP监听器"""
    
    def __init__(self, host: str, port: int, callback: Callable):
        self.host = host
        self.port = port
        self.callback = callback
        self.socket = None
        self.running = False
        self.thread = None
    
    def start(self):
        """启动监听"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        self.thread = threading.Thread(target=self._listen)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """停止监听"""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def _listen(self):
        """监听循环"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                log_line = data.decode('utf-8', errors='ignore').strip()
                
                log_data = {
                    'raw': log_line,
                    'parsed': self._parse_syslog(log_line, addr[0]),
                    'source_ip': addr[0],
                    'received_at': datetime.now().isoformat()
                }
                
                self.callback(log_data)
                
            except Exception as e:
                if self.running:
                    logger.error(f"Syslog UDP监听错误: {e}")
    
    def _parse_syslog(self, log_line: str, source_ip: str) -> Dict[str, Any]:
        """解析Syslog格式"""
        # 这里可以实现更复杂的syslog解析逻辑
        return {
            'message': log_line,
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat()
        }


class SyslogTCPListener:
    """Syslog TCP监听器"""
    
    def __init__(self, host: str, port: int, callback: Callable):
        self.host = host
        self.port = port
        self.callback = callback
        self.socket = None
        self.running = False
        self.thread = None
        self.clients = []
    
    def start(self):
        """启动监听"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        
        self.thread = threading.Thread(target=self._listen)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """停止监听"""
        self.running = False
        if self.socket:
            self.socket.close()
        for client in self.clients:
            client.close()
    
    def _listen(self):
        """监听循环"""
        while self.running:
            try:
                self.socket.settimeout(1.0)
                try:
                    client, addr = self.socket.accept()
                except socket.timeout:
                    continue
                
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                self.clients.append(client)
                
            except Exception as e:
                if self.running:
                    logger.error(f"Syslog TCP监听错误: {e}")
    
    def _handle_client(self, client: socket.socket, addr: tuple):
        """处理客户端连接"""
        try:
            while self.running:
                data = client.recv(65535)
                if not data:
                    break
                
                log_line = data.decode('utf-8', errors='ignore').strip()
                log_data = {
                    'raw': log_line,
                    'parsed': self._parse_syslog(log_line, addr[0]),
                    'source_ip': addr[0],
                    'received_at': datetime.now().isoformat()
                }
                
                self.callback(log_data)
                
        except Exception as e:
            logger.error(f"处理Syslog TCP客户端错误: {e}")
        finally:
            client.close()
            if client in self.clients:
                self.clients.remove(client)
    
    def _parse_syslog(self, log_line: str, source_ip: str) -> Dict[str, Any]:
        """解析Syslog格式"""
        return {
            'message': log_line,
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat()
        }


class FileLogMonitor:
    """文件日志监控器"""
    
    def __init__(self, file_path: str, callback: Callable, poll_interval: int = 5, encoding: str = 'utf-8'):
        self.file_path = file_path
        self.callback = callback
        self.poll_interval = poll_interval
        self.encoding = encoding
        self.running = False
        self.thread = None
        self.last_position = 0
        self.last_size = 0
    
    def start(self):
        """启动监控"""
        # 获取文件当前大小
        if os.path.exists(self.file_path):
            self.last_size = os.path.getsize(self.file_path)
            self.last_position = self.last_size
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """停止监控"""
        self.running = False
    
    def _monitor(self):
        """监控循环"""
        while self.running:
            try:
                if not os.path.exists(self.file_path):
                    time.sleep(self.poll_interval)
                    continue
                
                current_size = os.path.getsize(self.file_path)
                
                # 文件被轮转（变小或重置）
                if current_size < self.last_size:
                    self.last_position = 0
                
                # 有新内容
                if current_size > self.last_position:
                    with open(self.file_path, 'r', encoding=self.encoding, errors='ignore') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                        self.last_position = f.tell()
                    
                    for line in new_lines:
                        line = line.strip()
                        if line:
                            log_data = {
                                'raw': line,
                                'parsed': self._parse_log(line),
                                'source_file': self.file_path,
                                'received_at': datetime.now().isoformat()
                            }
                            self.callback(log_data)
                
                self.last_size = current_size
                time.sleep(self.poll_interval)
                
            except Exception as e:
                logger.error(f"文件监控错误: {e}")
                time.sleep(self.poll_interval)
    
    def _parse_log(self, log_line: str) -> Dict[str, Any]:
        """解析日志格式"""
        # 这里可以实现更复杂的日志解析逻辑
        return {
            'message': log_line,
            'timestamp': datetime.now().isoformat()
        }


class APIPoller:
    """API轮询器"""
    
    def __init__(self, url: str, method: str, headers: Dict, auth_type: str, 
                 auth_config: Dict, poll_interval: int, callback: Callable):
        self.url = url
        self.method = method
        self.headers = headers
        self.auth_type = auth_type
        self.auth_config = auth_config
        self.poll_interval = poll_interval
        self.callback = callback
        self.running = False
        self.thread = None
    
    def start(self):
        """启动轮询"""
        self.running = True
        self.thread = threading.Thread(target=self._poll)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """停止轮询"""
        self.running = False
    
    def _poll(self):
        """轮询循环"""
        import requests
        
        while self.running:
            try:
                # 构建认证信息
                auth = None
                if self.auth_type == 'basic':
                    auth = (self.auth_config.get('username'), self.auth_config.get('password'))
                elif self.auth_type == 'bearer':
                    self.headers['Authorization'] = f"Bearer {self.auth_config.get('token')}"
                elif self.auth_type == 'apikey':
                    apikey_header = self.auth_config.get('header', 'X-API-Key')
                    self.headers[apikey_header] = self.auth_config.get('key')
                
                response = requests.request(
                    method=self.method,
                    url=self.url,
                    headers=self.headers,
                    auth=auth,
                    timeout=30
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # 假设API返回的是日志列表
                        if isinstance(data, list):
                            for log in data:
                                log_data = {
                                    'raw': json.dumps(log),
                                    'parsed': log,
                                    'source_api': self.url,
                                    'received_at': datetime.now().isoformat()
                                }
                                self.callback(log_data)
                        else:
                            log_data = {
                                'raw': response.text,
                                'parsed': data,
                                'source_api': self.url,
                                'received_at': datetime.now().isoformat()
                            }
                            self.callback(log_data)
                    except:
                        # 非JSON响应
                        log_data = {
                            'raw': response.text,
                            'parsed': {'content': response.text},
                            'source_api': self.url,
                            'received_at': datetime.now().isoformat()
                        }
                        self.callback(log_data)
                else:
                    logger.warning(f"API请求失败: {response.status_code}")
                
            except Exception as e:
                logger.error(f"API轮询错误: {e}")
            
            # 等待下一次轮询
            for _ in range(self.poll_interval):
                if not self.running:
                    break
                time.sleep(1)


# 全局数据源管理器实例
data_source_manager = None

def get_data_source_manager() -> DataSourceManager:
    """获取数据源管理器实例"""
    global data_source_manager
    if data_source_manager is None:
        data_source_manager = DataSourceManager()
    return data_source_manager


if __name__ == '__main__':
    # 测试代码
    manager = get_data_source_manager()
    
    # 创建一个测试用的Syslog数据源
    config = DataSourceConfig(
        name="测试Syslog",
        source_type="syslog",
        syslog_host="0.0.0.0",
        syslog_port=1514,
        syslog_protocol="udp"
    )
    
    source_id = manager.create_data_source(config)
    print(f"创建数据源成功，ID: {source_id}")
    
    # 启动数据源
    manager.start_data_source(source_id)
    
    try:
        print("按Ctrl+C停止...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop_data_source(source_id)
        print("已停止")
