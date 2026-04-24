"""JWT认证模块"""

import jwt
import time
import re
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from .config import config


class PasswordComplexityError(Exception):
    """密码复杂度验证异常"""
    pass


def validate_password_complexity(password: str) -> List[str]:
    """
    验证密码复杂度，返回错误信息列表
    如果列表为空，则密码符合要求
    """
    errors = []
    
    if len(password) < config.password_min_length:
        errors.append(f'密码长度至少为{config.password_min_length}个字符')
    
    if config.password_require_uppercase and not re.search(r'[A-Z]', password):
        errors.append('密码必须包含大写字母')
    
    if config.password_require_lowercase and not re.search(r'[a-z]', password):
        errors.append('密码必须包含小写字母')
    
    if config.password_require_digit and not re.search(r'[0-9]', password):
        errors.append('密码必须包含数字')
    
    if config.password_require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append('密码必须包含特殊字符')
    
    return errors


class AuthManager:
    """JWT认证管理器"""
    
    def __init__(self):
        self.secret = config.jwt_secret
        self.expiration = config.jwt_expiration
        self.blacklisted_tokens: set = set()
        self.users: Dict[str, Dict[str, Any]] = {}
        self.login_attempts: Dict[str, int] = {}
        self.locked_accounts: Dict[str, float] = {}
        self.password_history: Dict[str, List[str]] = {}
        self._init_default_admin()
    
    def _init_default_admin(self):
        """初始化默认管理员账户"""
        admin_username = config.default_admin_username
        admin_password = config.default_admin_password
        password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        
        self.users[admin_username] = {
            'username': admin_username,
            'password_hash': password_hash,
            'role': 'admin',
            'created_at': datetime.now().isoformat()
        }
    
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """验证用户凭据，返回JWT令牌"""
        user = self.users.get(username)
        if not user:
            return None
        
        if self.is_account_locked(username):
            return None
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user['password_hash'] != password_hash:
            self.record_failed_login(username)
            return None
        
        self.reset_failed_login_attempts(username)
        return self.generate_token(username, user['role'])
    
    def is_account_locked(self, username: str) -> bool:
        """检查账户是否被锁定"""
        lock_time = self.locked_accounts.get(username)
        if lock_time is None:
            return False
        
        if time.time() - lock_time > config.lockout_duration:
            del self.locked_accounts[username]
            self.login_attempts[username] = 0
            return False
        
        return True
    
    def record_failed_login(self, username: str):
        """记录失败的登录尝试"""
        attempts = self.login_attempts.get(username, 0) + 1
        self.login_attempts[username] = attempts
        
        if attempts >= config.max_login_attempts:
            self.locked_accounts[username] = time.time()
    
    def reset_failed_login_attempts(self, username: str):
        """重置失败登录计数"""
        self.login_attempts[username] = 0
        if username in self.locked_accounts:
            del self.locked_accounts[username]
    
    def get_account_lock_info(self, username: str) -> Dict[str, Any]:
        """获取账户锁定信息"""
        lock_time = self.locked_accounts.get(username)
        if lock_time is None:
            return {'locked': False}
        
        remaining = config.lockout_duration - (time.time() - lock_time)
        if remaining <= 0:
            return {'locked': False}
        
        return {
            'locked': True,
            'remaining_seconds': int(remaining)
        }
    
    def generate_token(self, username: str, role: str) -> str:
        """生成JWT令牌"""
        now = datetime.utcnow()
        payload = {
            'sub': username,
            'role': role,
            'iat': now,
            'exp': now + timedelta(seconds=self.expiration)
        }
        
        token = jwt.encode(payload, self.secret, algorithm='HS256')
        return token
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """验证JWT令牌，返回载荷信息"""
        if token in self.blacklisted_tokens:
            return None
        
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def logout(self, token: str) -> bool:
        """注销令牌（加入黑名单）"""
        if token:
            self.blacklisted_tokens.add(token)
            return True
        return False
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Dict[str, Any]:
        """修改密码"""
        user = self.users.get(username)
        if not user:
            return {'success': False, 'error': '用户不存在'}
        
        old_hash = hashlib.sha256(old_password.encode()).hexdigest()
        if user['password_hash'] != old_hash:
            return {'success': False, 'error': '旧密码不正确'}
        
        errors = validate_password_complexity(new_password)
        if errors:
            return {'success': False, 'error': '密码不符合要求', 'details': errors}
        
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        history = self.password_history.get(username, [])
        if new_hash in history:
            return {'success': False, 'error': '不能使用最近使用过的密码'}
        
        history.append(new_hash)
        if len(history) > config.password_history_count:
            history = history[-config.password_history_count:]
        self.password_history[username] = history
        
        user['password_hash'] = new_hash
        return {'success': True}
    
    def add_user(self, username: str, password: str, role: str = 'user') -> Dict[str, Any]:
        """添加新用户"""
        if username in self.users:
            return {'success': False, 'error': '用户名已存在'}
        
        errors = validate_password_complexity(password)
        if errors:
            return {'success': False, 'error': '密码不符合要求', 'details': errors}
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {
            'username': username,
            'password_hash': password_hash,
            'role': role,
            'created_at': datetime.now().isoformat()
        }
        return {'success': True}
    
    def get_security_config(self) -> Dict[str, Any]:
        """获取账号安全配置"""
        return {
            'password_min_length': config.password_min_length,
            'password_require_uppercase': config.password_require_uppercase,
            'password_require_lowercase': config.password_require_lowercase,
            'password_require_digit': config.password_require_digit,
            'password_require_special': config.password_require_special,
            'max_login_attempts': config.max_login_attempts,
            'lockout_duration': config.lockout_duration,
            'session_timeout': config.session_timeout,
            'password_history_count': config.password_history_count,
        }
    
    def update_security_config(self, config_data: Dict[str, Any]) -> bool:
        """更新账号安全配置"""
        global_config = config
        if 'password_min_length' in config_data:
            global_config.password_min_length = int(config_data['password_min_length'])
        if 'password_require_uppercase' in config_data:
            global_config.password_require_uppercase = bool(config_data['password_require_uppercase'])
        if 'password_require_lowercase' in config_data:
            global_config.password_require_lowercase = bool(config_data['password_require_lowercase'])
        if 'password_require_digit' in config_data:
            global_config.password_require_digit = bool(config_data['password_require_digit'])
        if 'password_require_special' in config_data:
            global_config.password_require_special = bool(config_data['password_require_special'])
        if 'max_login_attempts' in config_data:
            global_config.max_login_attempts = int(config_data['max_login_attempts'])
        if 'lockout_duration' in config_data:
            global_config.lockout_duration = int(config_data['lockout_duration'])
        if 'session_timeout' in config_data:
            global_config.session_timeout = int(config_data['session_timeout'])
        if 'password_history_count' in config_data:
            global_config.password_history_count = int(config_data['password_history_count'])
        return True


# 全局认证管理器实例
auth_manager = AuthManager()
