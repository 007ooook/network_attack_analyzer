"""Graylog数据源"""

from .base import DataSource, DataSourceConfig
import logging

logger = logging.getLogger(__name__)


class GraylogDataSource(DataSource):
    """Graylog数据源"""
    
    def start(self) -> bool:
        # Graylog数据源逻辑
        self.running = True
        return True
    
    def stop(self) -> bool:
        self.running = False
        return True
