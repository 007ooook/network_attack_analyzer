"""统一错误处理模块"""

import traceback
import logging
from typing import Dict, Any, Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/error.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('error_handler')


class AppError(Exception):
    """应用程序错误基类"""
    def __init__(self, message: str, error_code: int = 500, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class DatabaseError(AppError):
    """数据库错误"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 500, details)


class AnalysisError(AppError):
    """分析错误"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 500, details)


class ValidationError(AppError):
    """验证错误"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 400, details)


class NotFoundError(AppError):
    """资源未找到错误"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 404, details)


class AuthenticationError(AppError):
    """认证错误"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 401, details)


class AuthorizationError(AppError):
    """授权错误"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 403, details)


def handle_error(error: Exception) -> Dict[str, Any]:
    """处理错误并返回标准化的错误响应
    
    Args:
        error: 异常对象
        
    Returns:
        标准化的错误响应字典
    """
    if isinstance(error, AppError):
        # 处理应用程序自定义错误
        error_response = {
            'error': {
                'code': error.error_code,
                'message': error.message,
                'details': error.details
            }
        }
        logger.error(f"AppError: {error.message} (code: {error.error_code})")
        if error.details:
            logger.error(f"Details: {error.details}")
    else:
        # 处理未预期的错误
        error_response = {
            'error': {
                'code': 500,
                'message': 'Internal Server Error',
                'details': {
                    'type': type(error).__name__,
                    'message': str(error)
                }
            }
        }
        logger.error(f"Unexpected error: {type(error).__name__}: {error}")
        logger.error(traceback.format_exc())
    
    return error_response


def safe_execute(func, *args, **kwargs):
    """安全执行函数，捕获并处理所有异常
    
    Args:
        func: 要执行的函数
        *args: 函数参数
        **kwargs: 函数关键字参数
        
    Returns:
        函数执行结果或错误响应
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        return handle_error(e)


def log_error(error: Exception, context: Optional[str] = None):
    """记录错误
    
    Args:
        error: 异常对象
        context: 错误上下文
    """
    context_str = f"[{context}] " if context else ""
    logger.error(f"{context_str}Error: {type(error).__name__}: {error}")
    logger.error(traceback.format_exc())
