"""Webhook数据源"""

from .base import DataSource, DataSourceConfig
import logging

logger = logging.getLogger(__name__)


class WebhookDataSource(DataSource):
    """Webhook数据源"""
    
    def start(self) -> bool:
        # Webhook不需要主动启动，由HTTP端点处理
        self.running = True
        return True
    
    def stop(self) -> bool:
        self.running = False
        return True
    
    def process_webhook(self, data: dict) -> bool:
        """处理Webhook请求"""
        try:
            # 验证签名（如果启用）
            if self.config.webhook_verify_signature and self.config.webhook_secret:
                # 这里可以添加签名验证逻辑
                pass
            
            # 处理接收到的数据
            log_data = {
                'raw': str(data),
                'source_ip': 'webhook',
                'received_at': data.get('timestamp', '')
            }
            
            self.callback(log_data)
            return True
        except Exception as e:
            logger.error(f"处理Webhook数据失败: {e}")
            return False
