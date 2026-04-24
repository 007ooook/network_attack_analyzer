"""日志处理器模块"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger('log_processor')


class LogProcessor:
    """日志处理器"""
    
    def __init__(self):
        self.data_source_manager = None
    
    def set_data_source_manager(self, data_source_manager):
        """设置数据源管理器"""
        self.data_source_manager = data_source_manager
    
    def process_syslog_message(self, log_data: Dict[str, Any]):
        """处理Syslog消息"""
        try:
            if not self.data_source_manager:
                logger.error("数据源管理器未初始化")
                return
            
            # 查找匹配的数据源
            data_sources = self.data_source_manager.get_all_data_sources()
            
            # 查找启用的 Syslog 数据源
            syslog_sources = [ds for ds in data_sources if ds.source_type == 'syslog' and ds.enabled]
            
            if syslog_sources:
                # 使用第一个匹配的 Syslog 数据源
                source_id = syslog_sources[0].id
                logger.info(f"将日志转发给数据源 ID {source_id}")
                
                # 调用数据源管理器的日志接收处理方法
                self.data_source_manager._on_log_received(source_id, log_data)
            else:
                logger.warning(f"没有找到启用的 Syslog 数据源，日志将被丢弃")
                
        except Exception as e:
            logger.error(f"处理Syslog消息失败: {e}")
            import traceback
            traceback.print_exc()
    
    def process_file_log(self, source_id: int, log_data: Dict[str, Any]):
        """处理文件日志"""
        try:
            if not self.data_source_manager:
                logger.error("数据源管理器未初始化")
                return
            
            # 调用数据源管理器的日志接收处理方法
            self.data_source_manager._on_log_received(source_id, log_data)
            
        except Exception as e:
            logger.error(f"处理文件日志失败: {e}")
            import traceback
            traceback.print_exc()
    
    def process_api_log(self, log_data: Dict[str, Any]):
        """处理API日志"""
        try:
            if not self.data_source_manager:
                logger.error("数据源管理器未初始化")
                return
            
            # 查找匹配的API数据源
            data_sources = self.data_source_manager.get_all_data_sources()
            
            # 查找启用的 API 数据源
            api_sources = [ds for ds in data_sources if ds.source_type == 'api' and ds.enabled]
            
            if api_sources:
                # 使用第一个匹配的 API 数据源
                source_id = api_sources[0].id
                logger.info(f"将API日志转发给数据源 ID {source_id}")
                
                # 调用数据源管理器的日志接收处理方法
                self.data_source_manager._on_log_received(source_id, log_data)
            else:
                logger.warning(f"没有找到启用的 API 数据源，日志将被丢弃")
                
        except Exception as e:
            logger.error(f"处理API日志失败: {e}")
            import traceback
            traceback.print_exc()


# 创建全局日志处理器实例
log_processor = LogProcessor()


def get_log_processor() -> LogProcessor:
    """获取日志处理器实例"""
    return log_processor
