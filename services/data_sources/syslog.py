"""Syslog数据源"""

from .base import DataSource, DataSourceConfig
import logging

logger = logging.getLogger(__name__)


class SyslogDataSource(DataSource):
    """Syslog数据源"""
    
    def __init__(self, source_id: int, config: DataSourceConfig, callback):
        super().__init__(source_id, config, callback)
    
    def start(self) -> bool:
        try:
            # 验证端口范围
            if not (1 <= self.config.syslog_port <= 65535):
                raise ValueError(f"无效的端口号: {self.config.syslog_port}")
            
            # 验证主机地址
            if not self.config.syslog_host:
                self.config.syslog_host = '0.0.0.0'
            
            # Syslog数据源使用中心化的服务管理器监听
            # 不需要创建自己的监听器
            self.running = True
            logger.info(f"Syslog数据源已启动: ID {self.source_id}, 配置: {self.config.syslog_host}:{self.config.syslog_port}/{self.config.syslog_protocol}")
            return True
        except Exception as e:
            logger.error(f"启动Syslog数据源失败: {e}")
            raise
    
    def stop(self) -> bool:
        self.running = False
        return True
