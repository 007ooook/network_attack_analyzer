"""服务管理器"""

import threading
import logging
from typing import Dict, Optional

from .config import config
from .listeners.udp_listener import SyslogUDPListener
from .listeners.tcp_listener import SyslogTCPListener

logger = logging.getLogger(__name__)


class ServiceManager:
    """服务管理器"""
    
    def __init__(self):
        self.services: Dict[str, threading.Thread] = {}
        self.running = False
        self.syslog_udp_listener: Optional[SyslogUDPListener] = None
        self.syslog_tcp_listener: Optional[SyslogTCPListener] = None
    
    def start_all_services(self):
        """启动所有服务"""
        self.running = True
        try:
            # 启动Syslog UDP服务
            self.start_syslog_udp_service()
            
            # 启动Syslog TCP服务
            self.start_syslog_tcp_service()
            
            logger.info("所有服务启动完成")
        except Exception as e:
            logger.error(f"启动服务失败: {e}")
            self.stop_all_services()
    
    def stop_all_services(self):
        """停止所有服务"""
        self.running = False
        
        # 停止Syslog UDP服务
        if self.syslog_udp_listener:
            self.syslog_udp_listener.stop()
            self.syslog_udp_listener = None
        
        # 停止Syslog TCP服务
        if self.syslog_tcp_listener:
            self.syslog_tcp_listener.stop()
            self.syslog_tcp_listener = None
        
        # 停止所有线程服务
        for service_name, thread in self.services.items():
            if thread.is_alive():
                thread.join(timeout=5)
        
        self.services.clear()
        logger.info("所有服务已停止")
    
    def start_syslog_udp_service(self):
        """启动Syslog UDP服务"""
        try:
            self.syslog_udp_listener = SyslogUDPListener(
                host=config.host,
                port=config.syslog_udp_port,
                callback=self._on_syslog_message,
                source_id=None  # 中心化服务，由数据源管理器处理具体数据源
            )
            self.syslog_udp_listener.start()
            logger.info(f"Syslog UDP服务已启动: {config.host}:{config.syslog_udp_port}")
        except Exception as e:
            logger.error(f"启动Syslog UDP服务失败: {e}")
            raise
    
    def start_syslog_tcp_service(self):
        """启动Syslog TCP服务"""
        try:
            self.syslog_tcp_listener = SyslogTCPListener(
                host=config.host,
                port=config.syslog_tcp_port,
                callback=self._on_syslog_message,
                source_id=None  # 中心化服务，由数据源管理器处理具体数据源
            )
            self.syslog_tcp_listener.start()
            logger.info(f"Syslog TCP服务已启动: {config.host}:{config.syslog_tcp_port}")
        except Exception as e:
            logger.error(f"启动Syslog TCP服务失败: {e}")
            raise
    
    def _on_syslog_message(self, log_data):
        """处理Syslog消息"""
        # 这里应该将消息转发给日志处理器
        logger.info(f"收到Syslog消息: {log_data}")
        # 使用日志处理器处理消息，避免循环依赖
        try:
            from .log_processor import get_log_processor
            log_processor = get_log_processor()
            
            # 调用日志处理器处理消息
            log_processor.process_syslog_message(log_data)
            
        except ImportError as e:
            logger.error(f"导入日志处理器失败: {e}")
        except Exception as e:
            logger.error(f"处理Syslog消息失败: {e}")
            import traceback
            traceback.print_exc()
    
    def get_service_status(self):
        """获取服务状态"""
        status = {
            "syslog_udp": {
                "running": self.syslog_udp_listener is not None,
                "host": config.host,
                "port": config.syslog_udp_port
            },
            "syslog_tcp": {
                "running": self.syslog_tcp_listener is not None,
                "host": config.host,
                "port": config.syslog_tcp_port
            },
            "webhook": {
                "running": True,  # Webhook与主服务共用
                "host": config.host,
                "port": config.webhook_port
            }
        }
        return status


# 创建全局服务管理器实例
service_manager = ServiceManager()
