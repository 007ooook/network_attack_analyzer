"""安全中间件模块"""

import time
import hashlib
import secrets
from typing import Dict, Any, Optional, Set
import logging
from functools import wraps

from .config import config

logger = logging.getLogger('security')


class CSRFTokenManager:
    """CSRF令牌管理器"""
    
    def __init__(self):
        self.valid_tokens: Dict[str, float] = {}
        self.token_ttl = 3600  # 1小时
    
    def generate_token(self, session_id: str) -> str:
        """生成CSRF令牌"""
        raw_token = secrets.token_hex(32)
        token = f"{session_id}:{raw_token}"
        self.valid_tokens[token] = time.time()
        return token
    
    def verify_token(self, token: str, session_id: str) -> bool:
        """验证CSRF令牌"""
        if not token:
            return False
        
        current_time = time.time()
        
        # 清理过期令牌
        expired_tokens = [
            t for t, ts in self.valid_tokens.items()
            if current_time - ts > self.token_ttl
        ]
        for t in expired_tokens:
            del self.valid_tokens[t]
        
        # 验证令牌
        if token in self.valid_tokens:
            token_session_id, _ = token.split(':', 1)
            if token_session_id == session_id:
                return True
        
        return False
    
    def invalidate_token(self, token: str):
        """使令牌失效"""
        if token in self.valid_tokens:
            del self.valid_tokens[token]


class RateLimiter:
    """速率限制器"""
    
    def __init__(self):
        self.requests: Dict[str, list] = {}
    
    def check_rate_limit(self, client_ip: str) -> bool:
        """检查速率限制"""
        if not config.rate_limit_enabled:
            return True
        
        current_time = time.time()
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # 清理过期的请求记录
        self.requests[client_ip] = [t for t in self.requests[client_ip] if current_time - t < 60]
        
        # 检查是否超过限制
        if len(self.requests[client_ip]) >= config.rate_limit_per_minute:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False
        
        # 记录新请求
        self.requests[client_ip].append(current_time)
        return True
    
    def clear_expired(self):
        """清理所有过期的请求记录"""
        current_time = time.time()
        for client_ip in list(self.requests.keys()):
            self.requests[client_ip] = [t for t in self.requests[client_ip] if current_time - t < 60]
            if not self.requests[client_ip]:
                del self.requests[client_ip]


class InputValidator:
    """输入验证器"""
    
    @staticmethod
    def validate_request_size(content_length: int) -> bool:
        """验证请求大小"""
        return content_length <= config.max_request_size
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """验证IP地址格式"""
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, ip))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """验证URL格式"""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False


class SecurityManager:
    """安全管理器"""
    
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.input_validator = InputValidator()
        self.csrf_manager = CSRFTokenManager()
    
    def check_security(self, client_ip: str, content_length: int) -> Dict[str, Any]:
        """检查安全状态"""
        # 检查速率限制
        if not self.rate_limiter.check_rate_limit(client_ip):
            return {
                'allowed': False,
                'error': 'Rate limit exceeded',
                'status_code': 429
            }
        
        # 检查请求大小
        if not self.input_validator.validate_request_size(content_length):
            return {
                'allowed': False,
                'error': 'Request too large',
                'status_code': 413
            }
        
        return {'allowed': True}
    
    def get_allowed_origins(self) -> list:
        """获取允许的CORS来源"""
        return config.allowed_origins
    
    def is_origin_allowed(self, origin: str) -> bool:
        """检查来源是否允许"""
        if not config.cors_enabled:
            return False
        return origin in config.allowed_origins


# 创建全局安全管理器实例
security_manager = SecurityManager()


def get_security_manager() -> SecurityManager:
    """获取安全管理器实例"""
    return security_manager


def secure_route(func):
    """安全路由装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # 这里可以添加安全检查逻辑
        # 例如：验证CSRF令牌、检查权限等
        return func(*args, **kwargs)
    return wrapper
