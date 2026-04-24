"""Kafka数据源"""

from .base import DataSource, DataSourceConfig
import logging

logger = logging.getLogger(__name__)


class KafkaDataSource(DataSource):
    """Kafka数据源"""
    
    def start(self) -> bool:
        # Kafka不需要主动启动，由消息队列处理
        self.running = True
        return True
    
    def stop(self) -> bool:
        self.running = False
        return True
