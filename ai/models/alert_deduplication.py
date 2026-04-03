import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'data', 'network_attack_analyzer.db')

class AlertDeduplicator:
    """告警去重器，用于识别和过滤重复告警"""
    
    def __init__(self, dedup_window_minutes: int = 30):
        self.dedup_window = timedelta(minutes=dedup_window_minutes)
        self.alert_cache = defaultdict(list)
        
    def _generate_alert_hash(self, alert: Dict[str, Any]) -> str:
        """生成告警的唯一哈希值"""
        hash_data = {
            'alert_type': alert.get('alert_type'),
            'source_ip': alert.get('source_ip'),
            'target_ip': alert.get('target_ip'),
            'attack_type': alert.get('attack_type'),
            'severity': alert.get('severity'),
            'signature': alert.get('signature', '')
        }
        
        hash_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.md5(hash_str.encode()).hexdigest()
    
    def is_duplicate(self, alert: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """检查告警是否为重复告警"""
        alert_hash = self._generate_alert_hash(alert)
        current_time = datetime.now()
        
        if alert_hash in self.alert_cache:
            cached_alerts = self.alert_cache[alert_hash]
            
            for cached_alert in cached_alerts:
                time_diff = current_time - cached_alert['timestamp']
                if time_diff < self.dedup_window:
                    return True, cached_alert
        
        return False, None
    
    def add_alert(self, alert: Dict[str, Any]) -> None:
        """添加告警到缓存"""
        alert_hash = self._generate_alert_hash(alert)
        current_time = datetime.now()
        
        alert_with_timestamp = {
            **alert,
            'timestamp': current_time,
            'hash': alert_hash
        }
        
        self.alert_cache[alert_hash].append(alert_with_timestamp)
        
        self._cleanup_old_alerts()
    
    def _cleanup_old_alerts(self) -> None:
        """清理过期的告警缓存"""
        current_time = datetime.now()
        
        for alert_hash in list(self.alert_cache.keys()):
            self.alert_cache[alert_hash] = [
                alert for alert in self.alert_cache[alert_hash]
                if current_time - alert['timestamp'] < self.dedup_window
            ]
            
            if not self.alert_cache[alert_hash]:
                del self.alert_cache[alert_hash]


class AlertAggregator:
    """告警聚合器，将相似告警聚合在一起"""
    
    def __init__(self, aggregation_window_minutes: int = 5):
        self.aggregation_window = timedelta(minutes=aggregation_window_minutes)
        self.alert_groups = defaultdict(list)
        
    def _should_aggregate(self, alert1: Dict[str, Any], alert2: Dict[str, Any]) -> bool:
        """判断两个告警是否应该聚合"""
        if alert1.get('alert_type') != alert2.get('alert_type'):
            return False
            
        if alert1.get('attack_type') != alert2.get('attack_type'):
            return False
            
        if alert1.get('severity') != alert2.get('severity'):
            return False
            
        if alert1.get('source_ip') and alert2.get('source_ip'):
            if alert1['source_ip'] != alert2['source_ip']:
                return False
        
        return True
    
    def aggregate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """聚合告警列表"""
        if not alerts:
            return []
        
        aggregated = []
        groups = []
        
        for alert in alerts:
            added_to_group = False
            
            for group in groups:
                if self._should_aggregate(group[0], alert):
                    group.append(alert)
                    added_to_group = True
                    break
            
            if not added_to_group:
                groups.append([alert])
        
        for group in groups:
            if len(group) == 1:
                aggregated.append(group[0])
            else:
                aggregated_alert = self._create_aggregated_alert(group)
                aggregated.append(aggregated_alert)
        
        return aggregated
    
    def _create_aggregated_alert(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """创建聚合告警"""
        base_alert = alerts[0].copy()
        
        base_alert['count'] = len(alerts)
        base_alert['first_seen'] = min(alert['timestamp'] for alert in alerts)
        base_alert['last_seen'] = max(alert['timestamp'] for alert in alerts)
        base_alert['is_aggregated'] = True
        
        unique_ips = set(alert.get('source_ip') for alert in alerts if alert.get('source_ip'))
        base_alert['unique_source_ips'] = list(unique_ips)
        
        return base_alert


class AlertPrioritizer:
    """告警优先级排序器，根据严重程度和影响范围排序"""
    
    SEVERITY_SCORES = {
        'Critical': 100,
        'High': 80,
        'Medium': 60,
        'Low': 40,
        'Info': 20
    }
    
    ATTACK_TYPE_SCORES = {
        'SQL Injection': 90,
        'XSS': 85,
        'DDoS': 95,
        'Brute Force': 75,
        'Malware': 88,
        'Phishing': 80,
        'Ransomware': 92,
        'Command Injection': 87,
        'Path Traversal': 82,
        'CSRF': 70
    }
    
    def calculate_priority_score(self, alert: Dict[str, Any]) -> float:
        """计算告警的优先级分数"""
        score = 0.0
        
        severity = alert.get('severity', 'Low')
        score += self.SEVERITY_SCORES.get(severity, 30)
        
        attack_type = alert.get('attack_type', 'Unknown')
        score += self.ATTACK_TYPE_SCORES.get(attack_type, 50)
        
        if alert.get('is_aggregated'):
            score += alert.get('count', 1) * 2
        
        if alert.get('confidence'):
            score *= alert['confidence']
        
        return score
    
    def prioritize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """对告警列表进行优先级排序"""
        for alert in alerts:
            alert['priority_score'] = self.calculate_priority_score(alert)
        
        return sorted(alerts, key=lambda x: x['priority_score'], reverse=True)


class AlertNoiseReducer:
    """告警降噪器，整合去重、聚合和优先级排序功能"""
    
    def __init__(
        self,
        dedup_window_minutes: int = 30,
        aggregation_window_minutes: int = 5
    ):
        self.deduplicator = AlertDeduplicator(dedup_window_minutes)
        self.aggregator = AlertAggregator(aggregation_window_minutes)
        self.prioritizer = AlertPrioritizer()
        
    def process_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """处理告警列表，执行去重、聚合和优先级排序"""
        if not alerts:
            return []
        
        filtered_alerts = []
        
        for alert in alerts:
            is_duplicate, original_alert = self.deduplicator.is_duplicate(alert)
            
            if not is_duplicate:
                self.deduplicator.add_alert(alert)
                filtered_alerts.append(alert)
            else:
                alert['is_duplicate'] = True
                alert['original_alert'] = original_alert
        
        aggregated_alerts = self.aggregator.aggregate_alerts(filtered_alerts)
        
        prioritized_alerts = self.prioritizer.prioritize_alerts(aggregated_alerts)
        
        return prioritized_alerts
    
    def process_single_alert(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """处理单个告警"""
        is_duplicate, original_alert = self.deduplicator.is_duplicate(alert)
        
        if is_duplicate:
            alert['is_duplicate'] = True
            alert['original_alert'] = original_alert
            return None
        
        self.deduplicator.add_alert(alert)
        
        return alert


class AlertManager:
    """告警管理器，负责告警的存储、查询和管理"""
    
    def __init__(self):
        self.noise_reducer = AlertNoiseReducer()
        
    def save_alert(self, alert: Dict[str, Any]) -> bool:
        """保存告警到数据库"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO alerts (
                alert_type, source_ip, target_ip, attack_type, severity,
                confidence, description, signature, is_duplicate, is_aggregated,
                count, priority_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.get('alert_type'),
                alert.get('source_ip'),
                alert.get('target_ip'),
                alert.get('attack_type'),
                alert.get('severity'),
                alert.get('confidence'),
                alert.get('description'),
                alert.get('signature'),
                alert.get('is_duplicate', False),
                alert.get('is_aggregated', False),
                alert.get('count', 1),
                alert.get('priority_score', 0),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving alert: {e}")
            return False
    
    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """获取告警列表"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM alerts WHERE 1=1'
            params = []
            
            if severity:
                query += ' AND severity = ?'
                params.append(severity)
            
            if start_date:
                query += ' AND created_at >= ?'
                params.append(start_date)
            
            if end_date:
                query += ' AND created_at <= ?'
                params.append(end_date)
            
            query += ' ORDER BY priority_score DESC, created_at DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            alerts = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return alerts
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """获取告警统计信息"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) as total FROM alerts')
            total = cursor.fetchone()['total']
            
            cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM alerts 
            GROUP BY severity
            ''')
            severity_breakdown = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM alerts 
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
            ''')
            top_source_ips = [{'ip': row['source_ip'], 'count': row['count']} for row in cursor.fetchall()]
            
            cursor.execute('''
            SELECT is_duplicate, COUNT(*) as count 
            FROM alerts 
            WHERE is_duplicate = 1
            GROUP BY is_duplicate
            ''')
            duplicate_result = cursor.fetchone()
            duplicate_alerts = duplicate_result['count'] if duplicate_result else 0
            
            cursor.execute('''
            SELECT is_aggregated, COUNT(*) as count 
            FROM alerts 
            WHERE is_aggregated = 1
            GROUP BY is_aggregated
            ''')
            aggregated_result = cursor.fetchone()
            aggregated_alerts = aggregated_result['count'] if aggregated_result else 0
            
            cursor.execute('''
            SELECT COUNT(DISTINCT source_ip) as count FROM alerts
            ''')
            unique_ips_result = cursor.fetchone()
            unique_source_ips = unique_ips_result['count'] if unique_ips_result else 0
            
            conn.close()
            
            return {
                'total_alerts': total,
                'severity_breakdown': severity_breakdown,
                'top_source_ips': top_source_ips,
                'duplicate_alerts': duplicate_alerts,
                'aggregated_alerts': aggregated_alerts,
                'unique_source_ips': unique_source_ips,
                'trend_data': []
            }
        except Exception as e:
            print(f"Error getting alert statistics: {e}")
            return {
                'total_alerts': 0,
                'severity_breakdown': {},
                'top_source_ips': [],
                'duplicate_alerts': 0,
                'aggregated_alerts': 0,
                'unique_source_ips': 0,
                'trend_data': []
            }