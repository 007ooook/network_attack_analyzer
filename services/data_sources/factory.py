"""数据源工厂"""

from typing import Callable
from .base import DataSource, DataSourceConfig, DataSourceType
from .syslog import SyslogDataSource
from .file import FileDataSource
from .api import APIDataSource
from .webhook import WebhookDataSource
from .kafka import KafkaDataSource
from .redis import RedisDataSource
from .elk import ELKDataSource
from .splunk import SplunkDataSource
from .graylog import GraylogDataSource


class DataSourceFactory:
    """数据源工厂"""
    
    @staticmethod
    def create_data_source(source_id: int, config: DataSourceConfig, callback: Callable) -> DataSource:
        """创建数据源实例"""
        source_type = config.source_type
        
        if source_type == DataSourceType.SYSLOG.value:
            return SyslogDataSource(source_id, config, callback)
        elif source_type == DataSourceType.FILE.value:
            return FileDataSource(source_id, config, callback)
        elif source_type == DataSourceType.API.value:
            return APIDataSource(source_id, config, callback)
        elif source_type == DataSourceType.WEBHOOK.value:
            return WebhookDataSource(source_id, config, callback)
        elif source_type == DataSourceType.KAFKA.value:
            return KafkaDataSource(source_id, config, callback)
        elif source_type == DataSourceType.REDIS.value:
            return RedisDataSource(source_id, config, callback)
        elif source_type == DataSourceType.ELK.value:
            return ELKDataSource(source_id, config, callback)
        elif source_type == DataSourceType.SPLUNK.value:
            return SplunkDataSource(source_id, config, callback)
        elif source_type == DataSourceType.GRAYLOG.value:
            return GraylogDataSource(source_id, config, callback)
        else:
            raise ValueError(f"不支持的数据源类型: {source_type}")
