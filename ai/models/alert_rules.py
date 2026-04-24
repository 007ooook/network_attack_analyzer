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
    
    def _generate_rule_id(self, name: str = None) -> str:
        """生成规则ID"""
        import re
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM alert_rules')
            count = cursor.fetchone()[0] + 1
            conn.close()
        except:
            count = len(self.rules) + 1
        
        if name:
            prefix = re.sub(r'[^a-zA-Z0-9]', '', name[:8]).upper()
            if not prefix:
                prefix = 'RULE'
        else:
            prefix = 'RULE'
        
        return f"{prefix}-{count:04d}"

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
        """创建默认的告警规则 - 覆盖系统所有攻击类型"""
        default_rules = [
            # === Critical 级别 ===
            AlertRule(
                rule_id='SQLI-0001',
                name='SQL注入攻击检测',
                description='检测SQL注入攻击，包括UNION注入、盲注、时间盲注等',
                severity='Critical',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['SQL Injection']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin', 'log_detailed']
            ),
            AlertRule(
                rule_id='CMDI-0002',
                name='命令注入攻击检测',
                description='检测操作系统命令注入攻击，包括管道符、反引号等注入方式',
                severity='Critical',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Command Injection']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin', 'incident_response']
            ),
            AlertRule(
                rule_id='RCE-0003',
                name='远程代码执行检测',
                description='检测远程代码执行攻击，包括eval、exec等危险函数调用',
                severity='Critical',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['RCE']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin', 'incident_response']
            ),
            AlertRule(
                rule_id='SSTI-0004',
                name='服务端模板注入检测',
                description='检测服务端模板注入攻击，包括Jinja2、Twig、Freemarker等',
                severity='Critical',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['SSTI']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin', 'log_detailed']
            ),
            AlertRule(
                rule_id='AUTHBY-0005',
                name='认证绕过攻击检测',
                description='检测认证绕过攻击，包括权限提升、会话劫持等',
                severity='Critical',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Authentication Bypass']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin', 'incident_response']
            ),
            AlertRule(
                rule_id='MALW-0006',
                name='恶意软件感染检测',
                description='检测恶意软件上传和感染，包括webshell、后门程序等',
                severity='Critical',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Malware Infection']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'block_ip', 'notify_admin', 'incident_response']
            ),
            # === High 级别 ===
            AlertRule(
                rule_id='XSS-0007',
                name='跨站脚本攻击检测',
                description='检测XSS攻击，包括反射型、存储型和DOM型XSS',
                severity='High',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['XSS']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin']
            ),
            AlertRule(
                rule_id='PATHT-0008',
                name='路径遍历攻击检测',
                description='检测目录遍历攻击，包括../绕过、编码绕过等',
                severity='High',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Path Traversal']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'log_detailed']
            ),
            AlertRule(
                rule_id='SSRF-0009',
                name='服务端请求伪造检测',
                description='检测SSRF攻击，包括内网探测、云元数据访问等',
                severity='High',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['SSRF']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin']
            ),
            AlertRule(
                rule_id='UPLOAD-0010',
                name='文件上传漏洞检测',
                description='检测恶意文件上传攻击，包括webshell上传、可执行文件上传等',
                severity='High',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['File Upload']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin']
            ),
            AlertRule(
                rule_id='EXFIL-0011',
                name='数据泄露检测',
                description='检测数据外泄行为，包括批量导出、数据库下载等',
                severity='High',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Data Exfiltration']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin', 'incident_response']
            ),
            # === Medium 级别 ===
            AlertRule(
                rule_id='CSRF-0012',
                name='跨站请求伪造检测',
                description='检测CSRF攻击，包括伪造表单提交、恶意链接等',
                severity='Medium',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['CSRF']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='BRUTE-0013',
                name='暴力破解攻击检测',
                description='检测暴力破解攻击，包括字典攻击、凭证填充等',
                severity='Medium',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Brute Force']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'block_ip', 'notify_admin']
            ),
            AlertRule(
                rule_id='IDOR-0014',
                name='不安全的直接对象引用检测',
                description='检测IDOR攻击，包括越权访问、水平/垂直权限提升等',
                severity='Medium',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['IDOR']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='SESSFIX-0015',
                name='会话固定攻击检测',
                description='检测会话固定攻击，包括会话ID劫持、会话重放等',
                severity='Medium',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Session Fixation']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='OPENRED-0016',
                name='开放重定向攻击检测',
                description='检测开放重定向攻击，包括钓鱼链接构造等',
                severity='Medium',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Open Redirect']},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='APIABU-0017',
                name='API滥用检测',
                description='检测API滥用行为，包括速率限制绕过、批量请求等',
                severity='Medium',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['API Abuse']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'rate_limit', 'monitor']
            ),
            # === Low 级别 ===
            AlertRule(
                rule_id='DOS-0018',
                name='拒绝服务攻击检测',
                description='检测DoS/DDoS攻击，包括慢速攻击、洪水攻击、反射放大攻击等',
                severity='Low',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['DoS/DDoS']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'rate_limit', 'monitor']
            ),
            AlertRule(
                rule_id='PARPOL-0019',
                name='参数污染攻击检测',
                description='检测HTTP参数污染攻击，包括重复参数、参数覆盖等',
                severity='Low',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Parameter Pollution']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'monitor']
            ),
            AlertRule(
                rule_id='HDRINJ-0020',
                name='HTTP头注入攻击检测',
                description='检测HTTP头注入攻击，包括CRLF注入、头覆盖等',
                severity='Low',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Header Injection']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='CRLF-0021',
                name='CRLF注入攻击检测',
                description='检测CRLF注入攻击，包括HTTP响应拆分、头注入等',
                severity='Low',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['CRLF Injection']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='HOSTINJ-0022',
                name='Host头注入攻击检测',
                description='检测Host头注入攻击，包括密码重置劫持、缓存投毒等',
                severity='Low',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Host Header Injection']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='PROTO-0023',
                name='协议降级攻击检测',
                description='检测协议降级攻击，包括TLS降级、HTTP降级等',
                severity='Low',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Protocol Downgrade']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'monitor']
            ),
            AlertRule(
                rule_id='SCRAP-0024',
                name='Web爬虫/抓取检测',
                description='检测恶意Web爬虫和数据抓取行为',
                severity='Low',
                enabled=True,
                conditions={
                    'attack_type': {'in': ['Web Scraping']},
                    'confidence': {'min': 0.4}
                },
                actions=['alert', 'rate_limit', 'monitor']
            ),
            # === 通用/行为规则 ===
            AlertRule(
                rule_id='ANOMALY-0025',
                name='异常行为检测',
                description='基于行为分析的异常检测，覆盖未知攻击模式',
                severity='Medium',
                enabled=True,
                conditions={
                    'anomaly_score': {'min': 0.7},
                    'confidence': {'min': 0.5}
                },
                actions=['alert', 'monitor']
            ),
            AlertRule(
                rule_id='SENSPATH-0026',
                name='敏感路径访问检测',
                description='检测对敏感路径的未授权访问，包括管理后台、配置文件等',
                severity='High',
                enabled=True,
                conditions={
                    'path': {
                        'contains': ['/admin', '/manager', '/config', '/backup', '/.env', '/.git', '/wp-admin', '/phpmyadmin']
                    },
                    'status_code': {'in': [200, 403]}
                },
                actions=['alert', 'log_detailed']
            ),
            AlertRule(
                rule_id='ERRFREQ-0027',
                name='高频错误请求检测',
                description='检测高频错误请求，可能表示扫描或探测行为',
                severity='Medium',
                enabled=True,
                conditions={
                    'status_code': {'in': [400, 401, 403, 404, 500]},
                    'confidence': {'min': 0.3}
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