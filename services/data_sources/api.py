"""API数据源"""

import time
import threading
import requests
import json
from .base import DataSource, DataSourceConfig
import logging

logger = logging.getLogger(__name__)


class APIPoller:
    """API轮询器"""
    
    def __init__(self, url: str, method: str = 'GET', headers: dict = None, 
                 auth_type: str = 'none', auth_config: dict = None, 
                 poll_interval: int = 60, callback=None):
        self.url = url
        self.method = method
        self.headers = headers or {}
        self.auth_type = auth_type
        self.auth_config = auth_config or {}
        self.poll_interval = poll_interval
        self.callback = callback
        self.running = False
        self.thread = None
    
    def start(self):
        """启动轮询"""
        try:
            self.running = True
            self.thread = threading.Thread(target=self._poll, daemon=True)
            self.thread.start()
            logger.info(f"API轮询已启动: {self.url}")
        except Exception as e:
            logger.error(f"启动API轮询失败: {e}")
            raise
    
    def stop(self):
        """停止轮询"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _poll(self):
        """轮询循环"""
        while self.running:
            try:
                # 准备认证
                auth = None
                if self.auth_type == 'basic':
                    username = self.auth_config.get('username', '')
                    password = self.auth_config.get('password', '')
                    auth = (username, password)
                elif self.auth_type == 'bearer':
                    token = self.auth_config.get('token', '')
                    self.headers['Authorization'] = f'Bearer {token}'
                elif self.auth_type == 'apikey':
                    header = self.auth_config.get('header', 'X-API-Key')
                    key = self.auth_config.get('key', '')
                    self.headers[header] = key
                
                # 发送请求
                response = requests.request(
                    method=self.method,
                    url=self.url,
                    headers=self.headers,
                    auth=auth,
                    timeout=30
                )
                
                if response.status_code < 400:
                    # 处理响应数据
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for item in data:
                                log_data = {
                                    'raw': json.dumps(item),
                                    'source_ip': 'api',
                                    'received_at': time.strftime('%Y-%m-%dT%H:%M:%S')
                                }
                                self.callback(log_data)
                        else:
                            log_data = {
                                'raw': response.text,
                                'source_ip': 'api',
                                'received_at': time.strftime('%Y-%m-%dT%H:%M:%S')
                            }
                            self.callback(log_data)
                    except json.JSONDecodeError:
                        # 非JSON响应
                        log_data = {
                            'raw': response.text,
                            'source_ip': 'api',
                            'received_at': time.strftime('%Y-%m-%dT%H:%M:%S')
                        }
                        self.callback(log_data)
                else:
                    logger.warning(f"API请求失败: {response.status_code} - {response.text}")
                
                time.sleep(self.poll_interval)
                
            except Exception as e:
                if self.running:
                    logger.error(f"API轮询错误: {e}")
                    time.sleep(self.poll_interval)


class APIDataSource(DataSource):
    """API轮询数据源"""
    
    def __init__(self, source_id: int, config: DataSourceConfig, callback):
        super().__init__(source_id, config, callback)
        self.poller = None
    
    def start(self) -> bool:
        try:
            headers = json.loads(self.config.api_headers) if self.config.api_headers else {}
            auth_config = json.loads(self.config.api_auth_config) if self.config.api_auth_config else {}
            
            self.poller = APIPoller(
                url=self.config.api_url,
                method=self.config.api_method,
                headers=headers,
                auth_type=self.config.api_auth_type,
                auth_config=auth_config,
                poll_interval=self.config.api_poll_interval,
                callback=self.callback
            )
            
            self.poller.start()
            self.running = True
            return True
        except Exception as e:
            logger.error(f"启动API数据源失败: {e}")
            raise
    
    def stop(self) -> bool:
        if self.poller:
            self.poller.stop()
            self.poller = None
        self.running = False
        return True
