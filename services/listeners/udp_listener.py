"""Syslog UDP监听器"""

import socket
import threading
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class SyslogUDPListener:
    """Syslog UDP监听器"""
    
    def __init__(self, host: str, port: int, callback, source_id: int = None):
        self.host = host
        self.port = port
        self.callback = callback
        self.source_id = source_id
        self.socket = None
        self.running = False
        self.thread = None
    
    def start(self):
        """启动监听"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            self.thread = threading.Thread(target=self._listen, daemon=True)
            self.thread.start()
            
            logger.info(f"Syslog UDP监听器已启动: {self.host}:{self.port} (数据源ID: {self.source_id})")
        except socket.error as e:
            logger.error(f"启动Syslog UDP监听器失败: {e}")
            raise
        except Exception as e:
            logger.error(f"启动Syslog UDP监听器异常: {e}")
            raise
    
    def stop(self):
        """停止监听"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.error(f"关闭UDP socket失败: {e}")
            self.socket = None
    
    def _listen(self):
        """监听循环"""
        logger.debug(f"Syslog UDP监听线程开始: {self.host}:{self.port}")
        while self.running:
            try:
                self.socket.settimeout(1.0)
                try:
                    data, addr = self.socket.recvfrom(65535)
                    logger.debug(f"UDP收到数据来自 {addr}: {len(data)} bytes")
                except socket.timeout:
                    continue
                
                log_line = data.decode('utf-8', errors='ignore').strip()
                logger.debug(f"UDP解码后日志: {log_line[:100]}...")
                
                log_data = {
                    'raw': log_line,
                    'source_ip': addr[0],
                    'received_at': datetime.now().isoformat()
                }
                
                self.callback(log_data)
                logger.debug(f"UDP回调函数调用完成")
                
            except Exception as e:
                if self.running:
                    logger.error(f"Syslog UDP监听错误: {e}")
                    import traceback
                    traceback.print_exc()
