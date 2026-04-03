from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import sqlite3
import os
import json

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'data', 'network_attack_analyzer.db')

class AlertRule:
    """告警规则类"""
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str,
        enabled: bool = True,
        conditions: Optional[Dict[str, Any]] = None,
        actions: Optional[List[str]] = None
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = enabled
        self.conditions = conditions or {}
        self.actions = actions or []
    
    def evaluate(self, log_entry: Dict[str, Any], analysis_result: Dict[str, Any]) -> bool:
        """评估日志条目是否满足规则条件"""
        if not self.enabled:
            return False
        
        if not self.conditions:
            return True
        
        for field, condition in self.conditions.items():
            if field == 'attack_type':
                attack_types = condition.get('in', [])
                if analysis_result.get('attack_type') not in attack_types:
                    return False
            
            elif field == 'severity':
                severities = condition.get('in', [])
                if analysis_result.get('severity') not in severities:
                    return False
            
            elif field == 'confidence':
                min_confidence = condition.get('min', 0)
                if analysis_result.get('confidence', 0) < min_confidence:
                    return False
            
            elif field == 'anomaly_score':
                min_score = condition.get('min', 0)
                if analysis_result.get('anomaly_score', 0) < min_score:
                    return False
            
            elif field == 'ip':
                ips = condition.get('in', [])
                if log_entry.get('ip') not in ips:
                    return False
            
            elif field == 'path':
                paths = condition.get('contains', [])
                path = log_entry.get('path', '')
                if not any(p in path for p in paths):
                    return False
            
            elif field == 'status_code':
                codes = condition.get('in', [])
                if log_entry.get('status') not in codes:
                    return False
            
            elif field == 'time_range':
                start_time = condition.get('start')
                end_time = condition.get('end')
                current_time = datetime.now().time()
                if start_time and end_time:
                    if not (start_time <= current_time <= end_time):
                        return False
        
        return True


class AlertRuleEngine:
    """告警规则引擎"""
    
    def __init__(self):
        self.rules: Dict[str, AlertRule] = {}
        self.load_rules_from_database()
    
    def add_rule(self, rule: AlertRule) -> None:
        """添加规则"""
        self.rules[rule.rule_id] = rule
        self.save_rule_to_database(rule)
    
    def remove_rule(self, rule_id: str) -> bool:
        """移除规则"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.delete_rule_from_database(rule_id)
            return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """获取规则"""
        return self.rules.get(rule_id)
    
    def get_all_rules(self) -> List[AlertRule]:
        """获取所有规则"""
        return list(self.rules.values())
    
    def enable_rule(self, rule_id: str) -> bool:
        """启用规则"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            self.update_rule_in_database(self.rules[rule_id])
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """禁用规则"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            self.update_rule_in_database(self.rules[rule_id])
            return True
        return False
    
    def evaluate_rules(
        self,
        log_entry: Dict[str, Any],
        analysis_result: Dict[str, Any]
    ) -> List[AlertRule]:
        """评估所有规则，返回匹配的规则列表"""
        matched_rules = []
        
        for rule in self.rules.values():
            if rule.evaluate(log_entry, analysis_result):
                matched_rules.append(rule)
        
        return matched_rules
    
    def load_rules_from_database(self) -> None:
        """从数据库加载规则"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM alert_rules')
            rows = cursor.fetchall()
            
            for row in rows:
                rule = AlertRule(
                    rule_id=row['rule_id'],
                    name=row['name'],
                    description=row['description'],
                    severity=row['severity'],
                    enabled=bool(row['enabled']),
                    conditions=json.loads(row['conditions']) if row['conditions'] else {},
                    actions=json.loads(row['actions']) if row['actions'] else []
                )
                self.rules[rule.rule_id] = rule
            
            conn.close()
            print(f"加载了 {len(self.rules)} 个告警规则")
        except Exception as e:
            print(f"加载告警规则时出错: {e}")
    
    def save_rule_to_database(self, rule: AlertRule) -> bool:
        """保存规则到数据库"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT OR REPLACE INTO alert_rules (
                rule_id, name, description, severity, enabled, conditions, actions, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule.rule_id,
                rule.name,
                rule.description,
                rule.severity,
                int(rule.enabled),
                json.dumps(rule.conditions),
                json.dumps(rule.actions),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"保存告警规则时出错: {e}")
            return False
    
    def delete_rule_from_database(self, rule_id: str) -> bool:
        """从数据库删除规则"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM alert_rules WHERE rule_id = ?', (rule_id,))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"删除告警规则时出错: {e}")
            return False
    
    def update_rule_in_database(self, rule: AlertRule) -> bool:
        """更新数据库中的规则"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            UPDATE alert_rules SET 
                name = ?, description = ?, severity = ?, enabled = ?, 
                conditions = ?, actions = ?, updated_at = ?
            WHERE rule_id = ?
            ''', (
                rule.name,
                rule.description,
                rule.severity,
                int(rule.enabled),
                json.dumps(rule.conditions),
                json.dumps(rule.actions),
                datetime.now().isoformat(),
                rule.rule_id
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"更新告警规则时出错: {e}")
            return False
    
    def create_default_rules(self) -> None:
        """创建默认的告警规则"""
        default_rules = [
            AlertRule(
                rule_id='rule_001',
                name='高危攻击检测',
                description='检测高危类型的攻击行为',
                severity='Critical',
                enabled=True,
                conditions={
                    'attack_type': {
                        'in': ['SQL Injection', 'DDoS', 'Ransomware', 'Command Injection']
                    },
                    'confidence': {'min': 0.7}
                },
                actions=['alert', 'block_ip', 'notify_admin']
            ),
            AlertRule(
                rule_id='rule_002',
                name='中等风险检测',
                description='检测中等风险的安全事件',
                severity='High',
                enabled=True,
                conditions={
                    'attack_type': {
                        'in': ['XSS', 'Brute Force', 'Malware', 'Phishing']
                    },
                    'confidence': {'min': 0.6}
                },
                actions=['alert', 'notify_admin']
            ),
            AlertRule(
                rule_id='rule_003',
                name='异常行为检测',
                description='检测异常的访问行为',
                severity='Medium',
                enabled=True,
                conditions={
                    'anomaly_score': {'min': 0.7},
                    'confidence': {'min': 0.5}
                },
                actions=['alert']
            ),
            AlertRule(
                rule_id='rule_004',
                name='敏感路径访问',
                description='检测对敏感路径的访问',
                severity='High',
                enabled=True,
                conditions={
                    'path': {
                        'contains': ['/admin', '/api', '/config', '/backup']
                    },
                    'attack_type': {
                        'in': ['SQL Injection', 'XSS', 'Path Traversal']
                    }
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='rule_005',
                name='高频错误检测',
                description='检测高频错误请求',
                severity='Medium',
                enabled=True,
                conditions={
                    'status_code': {'in': [400, 401, 403, 404, 500]},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'monitor']
            )
        ]
        
        for rule in default_rules:
            if rule.rule_id not in self.rules:
                self.add_rule(rule)
        
        print(f"创建了 {len(default_rules)} 个默认告警规则")


class AlertPolicyManager:
    """告警策略管理器"""
    
    def __init__(self):
        self.rule_engine = AlertRuleEngine()
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.load_policies_from_database()
    
    def add_policy(self, policy_id: str, policy_config: Dict[str, Any]) -> bool:
        """添加策略"""
        self.policies[policy_id] = policy_config
        self.save_policy_to_database(policy_id, policy_config)
        return True
    
    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """获取策略"""
        return self.policies.get(policy_id)
    
    def get_all_policies(self) -> Dict[str, Dict[str, Any]]:
        """获取所有策略"""
        return self.policies
    
    def update_policy(self, policy_id: str, policy_config: Dict[str, Any]) -> bool:
        """更新策略"""
        if policy_id in self.policies:
            self.policies[policy_id] = policy_config
            self.save_policy_to_database(policy_id, policy_config)
            return True
        return False
    
    def delete_policy(self, policy_id: str) -> bool:
        """删除策略"""
        if policy_id in self.policies:
            del self.policies[policy_id]
            self.delete_policy_from_database(policy_id)
            return True
        return False
    
    def load_policies_from_database(self) -> None:
        """从数据库加载策略"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM alert_policies')
            rows = cursor.fetchall()
            
            for row in rows:
                policy_config = json.loads(row['config'])
                self.policies[row['policy_id']] = policy_config
            
            conn.close()
            print(f"加载了 {len(self.policies)} 个告警策略")
        except Exception as e:
            print(f"加载告警策略时出错: {e}")
    
    def save_policy_to_database(self, policy_id: str, policy_config: Dict[str, Any]) -> bool:
        """保存策略到数据库"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT OR REPLACE INTO alert_policies (policy_id, name, description, enabled, config, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                policy_id,
                policy_config.get('name', ''),
                policy_config.get('description', ''),
                int(policy_config.get('enabled', False)),
                json.dumps(policy_config),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"保存告警策略时出错: {e}")
            return False
    
    def delete_policy_from_database(self, policy_id: str) -> bool:
        """从数据库删除策略"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM alert_policies WHERE policy_id = ?', (policy_id,))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"删除告警策略时出错: {e}")
            return False
    
    def create_default_policies(self) -> None:
        """创建默认的告警策略"""
        default_policies = {
            'policy_001': {
                'name': '严格安全策略',
                'description': '对所有可疑行为都进行告警',
                'enabled': True,
                'alert_threshold': 0.3,
                'dedup_window_minutes': 15,
                'aggregation_window_minutes': 3
            },
            'policy_002': {
                'name': '平衡安全策略',
                'description': '平衡安全性和误报率',
                'enabled': True,
                'alert_threshold': 0.5,
                'dedup_window_minutes': 30,
                'aggregation_window_minutes': 5
            },
            'policy_003': {
                'name': '宽松安全策略',
                'description': '只对高风险行为进行告警',
                'enabled': False,
                'alert_threshold': 0.7,
                'dedup_window_minutes': 60,
                'aggregation_window_minutes': 10
            }
        }
        
        for policy_id, policy_config in default_policies.items():
            if policy_id not in self.policies:
                self.add_policy(policy_id, policy_config)
        
        print(f"创建了 {len(default_policies)} 个默认告警策略")