"""Syslog TCP监听器"""

import socket
import threading
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class SyslogTCPListener:
    """Syslog TCP监听器"""
    
    def __init__(self, host: str, port: int, callback, source_id: int = None):
        self.host = host
        self.port = port
        self.callback = callback
        self.source_id = source_id
        self.socket = None
        self.running = False
        self.thread = None
        self.clients = []
    
    def start(self):
        """启动监听"""
        try:
            logger.debug(f"正在启动TCP监听器: {self.host}:{self.port}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.debug(f"TCP socket创建成功")
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.debug(f"TCP socket选项设置成功")
            self.socket.bind((self.host, self.port))
            logger.debug(f"TCP socket绑定成功: {self.host}:{self.port}")
            self.socket.listen(5)
            logger.debug(f"TCP socket监听成功")
            self.running = True
            
            self.thread = threading.Thread(target=self._listen, daemon=True)
            self.thread.start()
            logger.debug(f"TCP监听线程已启动")
            
            logger.info(f"Syslog TCP监听器已启动: {self.host}:{self.port} (数据源ID: {self.source_id})")
        except socket.error as e:
            logger.error(f"启动Syslog TCP监听器失败: {e}")
            import traceback
            traceback.print_exc()
            raise
        except Exception as e:
            logger.error(f"启动Syslog TCP监听器异常: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def stop(self):
        """停止监听"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.error(f"关闭TCP socket失败: {e}")
            self.socket = None
        for client in self.clients:
            try:
                client.close()
            except Exception as e:
                logger.error(f"关闭客户端socket失败: {e}")
        self.clients.clear()
    
    def _listen(self):
        """监听循环"""
        logger.debug(f"Syslog TCP监听线程开始: {self.host}:{self.port}")
        while self.running:
            try:
                self.socket.settimeout(1.0)
                try:
                    client, addr = self.socket.accept()
                    logger.debug(f"TCP接受客户端连接: {addr}")
                except socket.timeout:
                    continue
                
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                self.clients.append(client)
                logger.debug(f"TCP客户端线程已启动，当前客户端数: {len(self.clients)}")
                
            except Exception as e:
                if self.running:
                    logger.error(f"Syslog TCP监听错误: {e}")
                    import traceback
                    traceback.print_exc()
    
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
