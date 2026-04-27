"""系统监控模块"""

import os
import time
import psutil
import sqlite3
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger('monitoring')


class SystemMonitor:
    """系统监控类"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'data', 'network_attack_analyzer.db'
        )
        self.metrics = {}
        self.start_time = time.time()
        self.init_metrics_table()
    
    def init_metrics_table(self):
        """初始化监控指标表"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建监控指标表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    metric_name TEXT,
                    metric_value REAL,
                    metric_unit TEXT,
                    category TEXT
                )
            ''')
            
            # 创建索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_metrics_name ON system_metrics (metric_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_metrics_category ON system_metrics (category)')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"初始化监控指标表失败: {e}")
    
    def collect_system_metrics(self) -> Dict[str, Any]:
        """收集系统指标"""
        metrics = {}
        
        try:
            # CPU 使用率
            metrics['cpu_usage'] = psutil.cpu_percent(interval=1)
            
            # 内存使用率
            memory = psutil.virtual_memory()
            metrics['memory_usage'] = memory.percent
            metrics['memory_used'] = memory.used / (1024 * 1024 * 1024)  # GB
            metrics['memory_total'] = memory.total / (1024 * 1024 * 1024)  # GB
            
            # 磁盘使用率
            disk = psutil.disk_usage('/')
            metrics['disk_usage'] = disk.percent
            metrics['disk_used'] = disk.used / (1024 * 1024 * 1024)  # GB
            metrics['disk_total'] = disk.total / (1024 * 1024 * 1024)  # GB
            
            # 网络流量
            net_io = psutil.net_io_counters()
            metrics['network_sent'] = net_io.bytes_sent / (1024 * 1024)  # MB
            metrics['network_recv'] = net_io.bytes_recv / (1024 * 1024)  # MB
            
            # 系统启动时间
            metrics['uptime'] = time.time() - self.start_time
            
        except Exception as e:
            logger.error(f"收集系统指标失败: {e}")
        
        return metrics
    
    def collect_database_metrics(self) -> Dict[str, Any]:
        """收集数据库指标"""
        metrics = {}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 表大小
            tables = ['logs', 'analysis_results', 'threat_intel', 'predictions', 'alerts']
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    metrics[f'db_{table}_count'] = count
                except Exception as e:
                    logger.error(f"获取表 {table} 大小失败: {e}")
            
            conn.close()
            
        except Exception as e:
            logger.error(f"收集数据库指标失败: {e}")
        
        return metrics
    
    def collect_analysis_metrics(self) -> Dict[str, Any]:
        """收集分析引擎指标"""
        metrics = {}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 攻击类型分布
            cursor.execute('''
                SELECT attack_type, COUNT(*) as count 
                FROM analysis_results 
                WHERE attack_type != 'Normal' 
                GROUP BY attack_type
            ''')
            attack_types = cursor.fetchall()
            for attack_type, count in attack_types:
                metrics[f'attack_{attack_type.lower().replace(" ", "_")}'] = count
            
            # 威胁等级分布
            cursor.execute('''
                SELECT threat_level, COUNT(*) as count 
                FROM analysis_results 
                GROUP BY threat_level
            ''')
            threat_levels = cursor.fetchall()
            for threat_level, count in threat_levels:
                metrics[f'threat_{threat_level.lower()}'] = count
            
            conn.close()
            
        except Exception as e:
            logger.error(f"收集分析引擎指标失败: {e}")
        
        return metrics
    
    def collect_all_metrics(self) -> Dict[str, Any]:
        """收集所有指标"""
        metrics = {}
        metrics.update(self.collect_system_metrics())
        metrics.update(self.collect_database_metrics())
        metrics.update(self.collect_analysis_metrics())
        return metrics
    
    def save_metrics(self, metrics: Dict[str, Any]):
        """保存指标到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for metric_name, metric_value in metrics.items():
                # 确定指标类别和单位
                category = 'system'
                unit = ''
                
                if metric_name.startswith('cpu_'):
                    unit = '%'
                elif metric_name.startswith('memory_'):
                    if 'percent' in metric_name:
                        unit = '%'
                    else:
                        unit = 'GB'
                elif metric_name.startswith('disk_'):
                    if 'percent' in metric_name:
                        unit = '%'
                    else:
                        unit = 'GB'
                elif metric_name.startswith('network_'):
                    unit = 'MB'
                elif metric_name.startswith('uptime'):
                    unit = 'seconds'
                elif metric_name.startswith('db_'):
                    category = 'database'
                    unit = 'count'
                elif metric_name.startswith('attack_') or metric_name.startswith('threat_'):
                    category = 'analysis'
                    unit = 'count'
                
                # 插入指标
                cursor.execute('''
                    INSERT INTO system_metrics (metric_name, metric_value, metric_unit, category)
                    VALUES (?, ?, ?, ?)
                ''', (metric_name, metric_value, unit, category))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"保存指标失败: {e}")
    
    def get_metrics_summary(self, hours: int = 24) -> Dict[str, Any]:
        """获取指标摘要"""
        summary = {}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 计算时间范围
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            # 获取系统指标平均值
            cursor.execute('''
                SELECT metric_name, AVG(metric_value) as avg_value, MAX(metric_value) as max_value
                FROM system_metrics
                WHERE category = 'system' AND timestamp >= ?
                GROUP BY metric_name
            ''', (cutoff_time,))
            system_metrics = cursor.fetchall()
            summary['system'] = {}
            for metric_name, avg_value, max_value in system_metrics:
                summary['system'][metric_name] = {
                    'average': avg_value,
                    'maximum': max_value
                }
            
            # 获取分析指标
            cursor.execute('''
                SELECT metric_name, SUM(metric_value) as total_value
                FROM system_metrics
                WHERE category = 'analysis' AND timestamp >= ?
                GROUP BY metric_name
            ''', (cutoff_time,))
            analysis_metrics = cursor.fetchall()
            summary['analysis'] = {}
            for metric_name, total_value in analysis_metrics:
                summary['analysis'][metric_name] = total_value
            
            conn.close()
            
        except Exception as e:
            logger.error(f"获取指标摘要失败: {e}")
        
        return summary
    
    def cleanup_old_metrics(self, days: int = 7):
        """清理旧的指标数据"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 计算时间范围
            cutoff_time = (datetime.now() - timedelta(days=days)).isoformat()
            
            # 删除旧数据
            cursor.execute('''
                DELETE FROM system_metrics WHERE timestamp < ?
            ''', (cutoff_time,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"清理了 {days} 天前的指标数据")
        except Exception as e:
            logger.error(f"清理旧指标数据失败: {e}")


# 导入 timedelta
from datetime import timedelta


# 全局监控实例
monitor = None


def get_monitor() -> SystemMonitor:
    """获取监控实例"""
    global monitor
    if monitor is None:
        monitor = SystemMonitor()
    return monitor


def collect_and_save_metrics():
    """收集并保存指标"""
    try:
        monitor = get_monitor()
        metrics = monitor.collect_all_metrics()
        monitor.save_metrics(metrics)
        logger.info("成功收集并保存系统指标")
    except Exception as e:
        logger.error(f"收集并保存指标失败: {e}")


def get_metrics_summary(hours: int = 24) -> Dict[str, Any]:
    """获取指标摘要"""
    try:
        monitor = get_monitor()
        return monitor.get_metrics_summary(hours)
    except Exception as e:
        logger.error(f"获取指标摘要失败: {e}")
        return {}


def cleanup_metrics(days: int = 7):
    """清理旧的指标数据"""
    try:
        monitor = get_monitor()
        monitor.cleanup_old_metrics(days)
    except Exception as e:
        logger.error(f"清理指标数据失败: {e}")
