"""数据源抽象基类"""

from abc import ABC, abstractmethod
from typing import Callable, Optional
from dataclasses import dataclass
from enum import Enum


class DataSourceType(Enum):
    """数据源类型"""
    SYSLOG = "syslog"
    FILE = "file"
    API = "api"
    WEBHOOK = "webhook"
    KAFKA = "kafka"
    REDIS = "redis"
    ELK = "elk"
    SPLUNK = "splunk"
    GRAYLOG = "graylog"


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
    syslog_port: int = 1514
    syslog_protocol: str = "udp"  # udp/tcp
    syslog_max_packet_size: int = 8192  # 最大数据包大小
    
    # 文件监控配置
    file_path: str = ""
    file_format: str = "auto"  # auto/apache/nginx/syslog/json/csv/custom
    file_encoding: str = "utf-8"
    file_poll_interval: int = 5  # 秒
    file_max_lines: int = 1000  # 每次读取最大行数
    file_rotate_detection: bool = True  # 检测文件轮转
    
    # API配置
    api_url: str = ""
    api_method: str = "GET"
    api_headers: str = ""  # JSON格式
    api_auth_type: str = "none"  # none/basic/bearer/apikey
    api_auth_config: str = ""  # JSON格式
    api_poll_interval: int = 60  # 秒
    api_timeout: int = 30  # 超时时间(秒)
    api_retries: int = 3  # 重试次数
    api_retry_interval: int = 5  # 重试间隔(秒)
    
    # Webhook配置
    webhook_secret: str = ""
    webhook_verify_signature: bool = False
    webhook_max_payload_size: int = 1048576  # 最大payload大小(1MB)
    
    # Kafka配置
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic: str = "logs"
    kafka_group_id: str = "network_attack_analyzer"
    kafka_auto_offset_reset: str = "latest"
    kafka_max_poll_records: int = 100
    
    # Redis配置
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    redis_channel: str = "logs"
    
    # ELK配置
    elk_url: str = "http://localhost:9200"
    elk_index: str = "logs-*"
    elk_query: str = ""
    elk_username: str = ""
    elk_password: str = ""
    
    # Splunk配置
    splunk_url: str = "http://localhost:8089"
    splunk_query: str = "search *"
    splunk_username: str = ""
    splunk_password: str = ""
    splunk_interval: int = 60  # 秒
    
    # Graylog配置
    graylog_url: str = "http://localhost:12900"
    graylog_query: str = "*"
    graylog_username: str = ""
    graylog_password: str = ""
    graylog_interval: int = 60  # 秒
    
    # 通用配置
    log_format: str = "auto"  # auto/apache/nginx/syslog/json/csv/custom
    log_pattern: str = ""  # 自定义日志格式正则
    field_mapping: str = ""  # 字段映射 JSON
    filters: str = ""  # 过滤规则 JSON
    batch_size: int = 100  # 批处理大小
    processing_timeout: int = 30  # 处理超时时间(秒)
    enable_compression: bool = False  # 启用压缩
    
    # 实时处理配置
    enable_realtime: bool = True  # 启用实时处理
    realtime_buffer_size: int = 1000  # 实时缓冲区大小
    realtime_flush_interval: int = 1  # 实时刷新间隔(秒)
    
    # 健康检查配置
    health_check_interval: int = 60  # 健康检查间隔(秒)
    max_consecutive_errors: int = 5  # 最大连续错误数
    
    created_at: str = ""
    updated_at: str = ""
    last_error: str = ""
    last_connected_at: str = ""
    last_log_received: str = ""
    last_source_ip: str = ""
    total_logs_received: int = 0
    total_logs_processed: int = 0
    total_errors: int = 0


class DataSource(ABC):
    """数据源抽象基类"""
    
    def __init__(self, source_id: int, config: DataSourceConfig, callback: Callable):
        self.source_id = source_id
        self.config = config
        self.callback = callback
        self.running = False
        self.thread = None
    
    @abstractmethod
    def start(self) -> bool:
        """启动数据源"""
        pass
    
    @abstractmethod
    def stop(self) -> bool:
        """停止数据源"""
        pass
    
    def is_running(self) -> bool:
        """检查数据源是否运行中"""
        return self.running
    
    def get_status(self) -> str:
        """获取数据源状态"""
        return self.config.status
    
    def set_status(self, status: str):
        """设置数据源状态"""
        self.config.status = status
