"""服务配置模块"""

import os
import secrets
from dataclasses import dataclass, field
from typing import Optional


def _generate_secret_key() -> str:
    """生成安全的随机密钥"""
    return secrets.token_hex(32)


@dataclass
class ServerConfig:
    """服务器配置"""
    # 主服务配置
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    
    # 数据存储配置
    db_path: str = "data/network_attack_analyzer.db"
    
    # 日志配置
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # 监听服务配置
    syslog_udp_port: int = 1514
    syslog_tcp_port: int = 1514
    webhook_port: int = 5000  # 与主服务共用
    
    # 安全配置
    secret_key: str = field(default_factory=lambda: os.environ.get("APP_SECRET_KEY", _generate_secret_key()))
    allowed_origins: list = None
    cors_enabled: bool = True
    https_enabled: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    
    # 认证配置
    auth_enabled: bool = True
    jwt_secret: str = field(default_factory=lambda: os.environ.get("JWT_SECRET", _generate_secret_key()))
    jwt_expiration: int = 3600  # 1小时
    default_admin_username: str = "admin"
    default_admin_password: str = field(default_factory=lambda: os.environ.get("ADMIN_PASSWORD", "admin123"))
    
    # 账号安全配置
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15分钟
    session_timeout: int = 3600  # 1小时
    password_history_count: int = 3  # 记住最近N次密码
    
    # 速率限制配置
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 100
    
    # 输入验证配置
    max_request_size: int = 1048576  # 1MB
    
    def __post_init__(self):
        if self.allowed_origins is None:
            env_origins = os.environ.get("ALLOWED_ORIGINS")
            if env_origins:
                self.allowed_origins = [o.strip() for o in env_origins.split(",")]
            else:
                self.allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
        
        # 确保数据库路径存在
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)


# 创建全局配置实例
config = ServerConfig()
