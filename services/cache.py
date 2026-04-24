import functools
import time
from typing import Dict, Any, Optional, Callable
import threading
import pickle
import os

class CacheManager:
    """缓存管理器，用于缓存频繁访问的数据"""
    
    def __init__(self, cache_dir: str = None, default_ttl: int = 3600, max_size: int = 1000):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        self.cache_dir = cache_dir
        self.lock = threading.RLock()
        self.max_size = max_size  # 缓存最大容量
        self.access_times: Dict[str, float] = {}  # 记录缓存项的访问时间
        
        # 如果指定了缓存目录，确保目录存在
        if self.cache_dir:
            os.makedirs(self.cache_dir, exist_ok=True)
            self._load_from_disk()
        
        # 启动定期清理线程
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """启动定期清理线程"""
        def cleanup_task():
            while True:
                time.sleep(300)  # 每5分钟清理一次
                self._cleanup_expired()
                self._save_to_disk()
        
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        with self.lock:
            if key in self.cache:
                item = self.cache[key]
                # 检查是否过期
                if time.time() < item['expires_at']:
                    # 更新访问时间
                    self.access_times[key] = time.time()
                    return item['value']
                else:
                    # 过期，删除缓存
                    del self.cache[key]
                    if key in self.access_times:
                        del self.access_times[key]
                    # 不需要立即保存到磁盘，定期清理线程会处理
        return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """设置缓存值"""
        ttl = ttl or self.default_ttl
        with self.lock:
            # 检查缓存大小是否超过限制
            if len(self.cache) >= self.max_size and key not in self.cache:
                # 删除最久未使用的缓存项
                if self.access_times:
                    lru_key = min(self.access_times, key=lambda k: self.access_times.get(k, 0))
                    if lru_key in self.cache:
                        del self.cache[lru_key]
                    if lru_key in self.access_times:
                        del self.access_times[lru_key]
            
            # 设置缓存值
            self.cache[key] = {
                'value': value,
                'expires_at': time.time() + ttl
            }
            # 更新访问时间
            self.access_times[key] = time.time()
            # 不需要立即保存到磁盘，定期清理线程会处理
    
    def delete(self, key: str) -> None:
        """删除缓存值"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
                # 不需要立即保存到磁盘，定期清理线程会处理
    
    def clear(self) -> None:
        """清空缓存"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            # 不需要立即保存到磁盘，定期清理线程会处理
    
    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        with self.lock:
            total = len(self.cache)
            expired = 0
            current_time = time.time()
            
            for item in self.cache.values():
                if current_time >= item['expires_at']:
                    expired += 1
            
            return {
                'total_items': total,
                'expired_items': expired,
                'active_items': total - expired,
                'max_size': self.max_size,
                'access_times_count': len(self.access_times)
            }
    
    def _cleanup_expired(self) -> None:
        """清理过期的缓存项"""
        with self.lock:
            current_time = time.time()
            expired_keys = [k for k, v in self.cache.items() if current_time >= v['expires_at']]
            
            for key in expired_keys:
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
            
            # 如果缓存大小仍然超过限制，继续删除最久未使用的项
            while len(self.cache) > self.max_size:
                if self.access_times:
                    lru_key = min(self.access_times, key=lambda k: self.access_times.get(k, 0))
                    if lru_key in self.cache:
                        del self.cache[lru_key]
                    if lru_key in self.access_times:
                        del self.access_times[lru_key]
                else:
                    # 如果没有访问时间记录，删除第一个项
                    if self.cache:
                        first_key = next(iter(self.cache))
                        del self.cache[first_key]
    
    def _save_to_disk(self) -> None:
        """将缓存保存到磁盘"""
        if self.cache_dir:
            try:
                cache_file = os.path.join(self.cache_dir, 'cache.pkl')
                with open(cache_file, 'wb') as f:
                    pickle.dump({
                        'cache': self.cache,
                        'access_times': self.access_times
                    }, f)
            except Exception as e:
                print(f"保存缓存到磁盘失败: {e}")
    
    def _load_from_disk(self) -> None:
        """从磁盘加载缓存"""
        if self.cache_dir:
            try:
                cache_file = os.path.join(self.cache_dir, 'cache.pkl')
                if os.path.exists(cache_file):
                    with open(cache_file, 'rb') as f:
                        data = pickle.load(f)
                        if isinstance(data, dict) and 'cache' in data:
                            self.cache = data['cache']
                            # 加载访问时间记录
                            if 'access_times' in data:
                                self.access_times = data['access_times']
                            else:
                                # 兼容旧版本的缓存文件
                                self.access_times = {}
                        else:
                            # 兼容旧版本的缓存文件
                            self.cache = data
                            self.access_times = {}
                    
                    # 清理过期的缓存
                    current_time = time.time()
                    expired_keys = [k for k, v in self.cache.items() if current_time >= v['expires_at']]
                    for key in expired_keys:
                        del self.cache[key]
                        if key in self.access_times:
                            del self.access_times[key]
            except Exception as e:
                print(f"从磁盘加载缓存失败: {e}")

# 创建全局缓存管理器实例
CACHE_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'cache')
cache_manager = CacheManager(cache_dir=CACHE_DIR, default_ttl=3600)

def cached(ttl: int = None):
    """缓存装饰器，用于缓存函数结果"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # 生成缓存键
            key_parts = [func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = "_".join(key_parts)
            
            # 尝试从缓存获取
            cached_value = cache_manager.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # 执行函数
            result = func(*args, **kwargs)
            
            # 缓存结果
            cache_manager.set(cache_key, result, ttl)
            
            return result
        return wrapper
    return decorator

# 缓存键生成辅助函数
def generate_cache_key(prefix: str, **kwargs) -> str:
    """生成缓存键"""
    parts = [prefix]
    parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
    return "_".join(parts)