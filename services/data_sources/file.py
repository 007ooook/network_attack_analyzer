"""文件数据源"""

import os
import time
import threading
from .base import DataSource, DataSourceConfig
import logging

logger = logging.getLogger(__name__)


class FileLogMonitor:
    """文件日志监控器"""
    
    def __init__(self, file_path: str, callback, poll_interval: int = 5, encoding: str = 'utf-8'):
        self.file_path = file_path
        self.callback = callback
        self.poll_interval = poll_interval
        self.encoding = encoding
        self.running = False
        self.thread = None
        self.file_position = 0
    
    def start(self):
        """启动监控"""
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"日志文件不存在: {self.file_path}")
            
            # 获取文件初始大小
            self.file_position = os.path.getsize(self.file_path)
            self.running = True
            
            self.thread = threading.Thread(target=self._monitor, daemon=True)
            self.thread.start()
            
            logger.info(f"文件监控已启动: {self.file_path}")
        except Exception as e:
            logger.error(f"启动文件监控失败: {e}")
            raise
    
    def stop(self):
        """停止监控"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _monitor(self):
        """监控循环"""
        while self.running:
            try:
                if not os.path.exists(self.file_path):
                    time.sleep(self.poll_interval)
                    continue
                
                current_size = os.path.getsize(self.file_path)
                
                # 文件被截断
                if current_size < self.file_position:
                    self.file_position = 0
                
                # 有新内容
                if current_size > self.file_position:
                    with open(self.file_path, 'r', encoding=self.encoding, errors='ignore') as f:
                        f.seek(self.file_position)
                        for line in f:
                            line = line.strip()
                            if line:
                                log_data = {
                                    'raw': line,
                                    'source_ip': 'localhost',
                                    'received_at': time.strftime('%Y-%m-%dT%H:%M:%S')
                                }
                                self.callback(log_data)
                    self.file_position = current_size
                
                time.sleep(self.poll_interval)
                
            except Exception as e:
                if self.running:
                    logger.error(f"文件监控错误: {e}")
                    time.sleep(self.poll_interval)


class FileDataSource(DataSource):
    """文件监控数据源"""
    
    def __init__(self, source_id: int, config: DataSourceConfig, callback):
        super().__init__(source_id, config, callback)
        self.monitor = None
    
    def start(self) -> bool:
        try:
            if not os.path.exists(self.config.file_path):
                raise FileNotFoundError(f"日志文件不存在: {self.config.file_path}")
            
            self.monitor = FileLogMonitor(
                file_path=self.config.file_path,
                callback=self.callback,
                poll_interval=self.config.file_poll_interval,
                encoding=self.config.file_encoding
            )
            
            self.monitor.start()
            self.running = True
            return True
        except Exception as e:
            logger.error(f"启动文件监控数据源失败: {e}")
            raise
    
    def stop(self) -> bool:
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        self.running = False
        return True
