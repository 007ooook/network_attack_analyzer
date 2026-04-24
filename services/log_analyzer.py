import re
import json
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from collections import defaultdict
import logging
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """日志分析器 - 负责解析第三方日志、提取威胁指标、调用AI分析"""
    
    def __init__(self, threat_intel_callback: Optional[Callable] = None, attack_classifier: Optional[Any] = None):
        """初始化日志分析器
        
        Args:
            threat_intel_callback: 威胁情报查询回调函数
            attack_classifier: 攻击分类器实例
        """
        self.threat_intel_callback = threat_intel_callback
        self.attack_classifier = attack_classifier
        self._init_attack_classifier()
        
        # IP地址正则表达式
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # 域名正则表达式
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        # URL正则表达式
        self.url_pattern = re.compile(r'https?://[^\s<>"\']+')
        # 文件路径正则表达式
        self.file_path_pattern = re.compile(r'[a-zA-Z]:\\[^\s<>"\']*|/[^\s<>"\']*')
        # email正则表达式
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        # 哈希值正则表达式 (MD5, SHA1, SHA256)
        self.hash_pattern = re.compile(r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b')
        # 端口号正则表达式
        self.port_pattern = re.compile(r'\b\d{1,5}\b')
        # 进程ID正则表达式
        self.pid_pattern = re.compile(r'\bpid=\d+\b|\bprocess id=\d+\b', re.IGNORECASE)
        # 错误码正则表达式
        self.error_code_pattern = re.compile(r'\berror code=\d+\b|\berr=\d+\b', re.IGNORECASE)
        
        # 日志格式解析器
        self.log_parsers = {
            'apache': self._parse_apache_log,
            'nginx': self._parse_nginx_log,
            'iis': self._parse_iis_log,
            'syslog': self._parse_syslog,
            'windows': self._parse_windows_log,
            'custom': self._parse_custom_log
        }
        
        # 高级分析规则
        self.analysis_rules = [
            self._rule_sql_injection,
            self._rule_xss,
            self._rule_command_injection,
            self._rule_buffer_overflow,
            self._rule_brute_force,
            self._rule_dos_attack,
            self._rule_malware_download,
            self._rule_abnormal_access_pattern,
            self._rule_php_config_injection,
            self._rule_ssrf,
            self._rule_directory_traversal,
            self._rule_file_inclusion,
            self._rule_xxe,
        ]
        
        # 已查询的威胁指标缓存
        self.threat_cache = {}
        self.max_cache_size = 10000
        
        # 日志格式检测模式
        self.log_format_patterns = {
            'syslog': r'^<\d+>\S+ \S+ \S+ \S+ \S+:',
            'apache': r'^\S+ \S+ \S+ \[.*?\] "\S+ \S+ \S+" \d+ \d+',
            'nginx': r'^\S+ - - \[.*?\] "\S+ \S+ \S+" \d+ \d+',
            'iis': r'^\S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+',
            'windows': r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+'
        }
    
    def _init_attack_classifier(self):
        """初始化攻击分类器（如果未提供）"""
        if self.attack_classifier is None:
            try:
                from ai.models.attack_classifier import EnhancedAttackClassifier
                self.attack_classifier = EnhancedAttackClassifier()
                logger.info("攻击分类器初始化成功")
            except Exception as e:
                logger.error(f"攻击分类器初始化失败: {e}")
                self.attack_classifier = None
    
    def analyze_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析日志数据
        
        Args:
            log_data: 原始日志数据
            
        Returns:
            分析结果，包含威胁指标、攻击类型、严重程度等
        """
        result = {
            'raw_log': log_data.get('raw', ''),
            'source_ip': log_data.get('source_ip', ''),
            'received_at': log_data.get('received_at', datetime.now().isoformat()),
            'threat_indicators': [],
            'attack_analysis': None,
            'rule_analysis': [],
            'log_format': 'unknown',
            'parsed_data': {},
            'is_threat': False,
            'severity': 'Low'
        }
        
        try:
            # 1. 检测日志格式
            raw_log = log_data.get('raw', '')
            if not raw_log and isinstance(log_data, str):
                raw_log = log_data
            log_format = self.detect_log_format(raw_log)
            result['log_format'] = log_format
            
            # 2. 解析日志
            parser = self.log_parsers.get(log_format, self._parse_custom_log)
            logger.debug("选择的解析器: %s, 日志格式: %s", parser.__name__, log_format)
            parsed_data = parser(raw_log)
            logger.debug("解析结果: %s", parsed_data)
            result['parsed_data'] = parsed_data
            
            # 3. 提取威胁指标
            indicators = self._extract_threat_indicators(log_data)
            result['threat_indicators'] = indicators
            
            # 4. 查询威胁情报
            threat_info = self._query_threat_intel(indicators)
            result['threat_info'] = threat_info
            
            # 5. 调用AI分析
            attack_analysis = self._analyze_with_ai(log_data)
            result['attack_analysis'] = attack_analysis
            
            # 6. 使用规则分析
            rule_results = self.analyze_with_rules(log_data)
            result['rule_analysis'] = rule_results
            
            # 7. 综合判断是否为威胁
            threat_sources = []
            
            if threat_info.get('is_threat'):
                threat_sources.append('threat_intel')
            
            if attack_analysis and attack_analysis.get('attack_type') != 'Normal':
                threat_sources.append('ai_analysis')
            
            if rule_results:
                threat_sources.append('rule_analysis')
            
            if threat_sources:
                result['is_threat'] = True
                result['threat_sources'] = threat_sources
                
                # 确定严重程度 - 简化版本，取最高严重程度
                severity_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
                
                # 收集所有严重程度
                all_severities = []
                
                # AI分析严重程度
                if attack_analysis:
                    ai_severity = attack_analysis.get('severity', 'Low')
                    all_severities.append(ai_severity)
                
                # 威胁情报严重程度
                if threat_info.get('max_severity'):
                    ti_severity = threat_info.get('max_severity', 'Low')
                    all_severities.append(ti_severity)
                
                # 规则分析严重程度
                if rule_results:
                    for rule_result in rule_results:
                        severity = rule_result.get('severity', 'Low')
                        all_severities.append(severity)
                
                # 如果没有检测到任何严重程度，默认为Low
                if not all_severities:
                    result['severity'] = 'Low'
                else:
                    # 找出最高严重程度
                    max_severity_value = 0
                    max_severity_name = 'Low'
                    
                    for severity_name in all_severities:
                        severity_value = severity_order.get(severity_name, 1)
                        if severity_value > max_severity_value:
                            max_severity_value = severity_value
                            max_severity_name = severity_name
                    
                    # 根据规则置信度微调严重程度
                    if rule_results:
                        high_confidence_count = sum(1 for r in rule_results if r.get('confidence') == 'high')
                        critical_rules = [r for r in rule_results if r.get('severity') == 'Critical']
                        
                        # 如果有高置信度的Critical规则，保持Critical
                        if max_severity_name == 'Critical' and high_confidence_count > 0:
                            result['severity'] = 'Critical'
                        # 如果有多个高置信度规则，提升一级严重程度
                        elif high_confidence_count >= 2 and max_severity_name != 'Critical':
                            if max_severity_name == 'Low':
                                result['severity'] = 'Medium'
                            elif max_severity_name == 'Medium':
                                result['severity'] = 'High'
                            elif max_severity_name == 'High':
                                result['severity'] = 'Critical'
                        else:
                            result['severity'] = max_severity_name
                    else:
                        result['severity'] = max_severity_name
            
            # 8. 添加分析时间戳
            result['analyzed_at'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"日志分析失败: {e}")
            result['error'] = str(e)
        
        return result
    
    def _extract_threat_indicators(self, log_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取威胁指标
        
        Args:
            log_data: 原始日志数据
            
        Returns:
            威胁指标列表
        """
        indicators = []
        content = str(log_data.get('raw', ''))
        
        # 提取IP地址
        ips = self.ip_pattern.findall(content)
        for ip in ips:
            indicators.append({
                'type': 'ip',
                'value': ip,
                'context': 'ip_address'
            })
        
        # 提取域名
        domains = self.domain_pattern.findall(content)
        for domain in domains:
            indicators.append({
                'type': 'domain',
                'value': domain,
                'context': 'domain'
            })
        
        # 提取URL
        urls = self.url_pattern.findall(content)
        for url in urls:
            indicators.append({
                'type': 'url',
                'value': url,
                'context': 'url'
            })
            
            # 从URL中提取域名
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.netloc:
                    domain = parsed.netloc.split(':')[0]
                    if domain not in [d['value'] for d in indicators if d['type'] == 'domain']:
                        indicators.append({
                            'type': 'domain',
                            'value': domain,
                            'context': 'url_domain'
                        })
            except:
                pass
        
        # 提取文件路径
        file_paths = self.file_path_pattern.findall(content)
        for path in file_paths:
            indicators.append({
                'type': 'file_path',
                'value': path,
                'context': 'file_path'
            })
        
        # 提取email
        emails = self.email_pattern.findall(content)
        for email in emails:
            indicators.append({
                'type': 'email',
                'value': email,
                'context': 'email'
            })
        
        # 去重
        seen = set()
        unique_indicators = []
        for indicator in indicators:
            key = (indicator['type'], indicator['value'])
            if key not in seen:
                seen.add(key)
                unique_indicators.append(indicator)
        
        return unique_indicators
    
    def _query_threat_intel(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """查询威胁情报
        
        Args:
            indicators: 威胁指标列表
            
        Returns:
            威胁情报结果
        """
        result = {
            'is_threat': False,
            'matched_indicators': [],
            'max_severity': 'Low',
            'threat_types': []
        }
        
        if not self.threat_intel_callback:
            return result
        
        for indicator in indicators:
            indicator_value = indicator['value']
            
            # 检查缓存
            if indicator_value in self.threat_cache:
                threat_info = self.threat_cache[indicator_value]
            else:
                # 查询威胁情报
                try:
                    threat_info = self.threat_intel_callback(indicator_value, indicator['type'])
                    if len(self.threat_cache) >= self.max_cache_size:
                        self.threat_cache.clear()
                    self.threat_cache[indicator_value] = threat_info
                except Exception as e:
                    logger.error(f"查询威胁情报失败: {e}")
                    threat_info = None
            
            if threat_info and threat_info.get('is_threat'):
                result['is_threat'] = True
                result['matched_indicators'].append({
                    'type': indicator['type'],
                    'value': indicator_value,
                    'threat_type': threat_info.get('threat_type', 'Unknown'),
                    'severity': threat_info.get('severity', 'Low'),
                    'description': threat_info.get('description', '')
                })
                
                # 更新最大严重程度
                severity_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
                current_max = severity_order.get(result['max_severity'], 1)
                new_severity = severity_order.get(threat_info.get('severity', 'Low'), 1)
                if new_severity > current_max:
                    result['max_severity'] = threat_info.get('severity', 'Low')
                
                # 收集威胁类型
                if threat_info.get('threat_type') and threat_info['threat_type'] not in result['threat_types']:
                    result['threat_types'].append(threat_info['threat_type'])
        
        return result
    
    def _analyze_with_ai(self, log_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """使用AI分析日志
        
        Args:
            log_data: 原始日志数据
            
        Returns:
            AI分析结果
        """
        if not self.attack_classifier:
            logger.warning("攻击分类器未初始化")
            return None
        
        try:
            # 准备日志数据
            analyzed_log = {
                'raw_log': log_data.get('raw', ''),
                'source_ip': log_data.get('source_ip', ''),
                'received_at': log_data.get('received_at', '')
            }
            
            # 如果有解析后的数据，合并进去
            parsed = log_data.get('parsed', {})
            if isinstance(parsed, dict):
                analyzed_log.update(parsed)
            
            # 调用AI分类器
            result = self.attack_classifier.classify(analyzed_log)
            
            return {
                'attack_type': result.get('attack_type', 'Normal'),
                'confidence': result.get('confidence', 0),
                'severity': result.get('severity', 'Low'),
                'detection_methods': result.get('detection_methods', []),
                'details': result.get('details', {})
            }
            
        except Exception as e:
            logger.error(f"AI分析失败: {e}")
            return None
    
    def detect_log_format(self, log_content: str) -> str:
        """检测日志格式
        
        Args:
            log_content: 日志内容
            
        Returns:
            检测到的日志格式名称
        """
        for format_name, pattern in self.log_format_patterns.items():
            if re.match(pattern, log_content):
                logger.debug("检测到日志格式: %s, 日志内容: %s...", format_name, log_content[:50])
                return format_name
        logger.debug("未检测到匹配的日志格式，使用 custom，日志内容: %s...", log_content[:50])
        return 'custom'
    
    def _parse_apache_log(self, log_content: str) -> Dict[str, Any]:
        """解析Apache日志"""
        pattern = r'^(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'  # noqa: E501
        match = re.match(pattern, log_content)
        if match:
            return {
                'ip': match.group(1),
                'user': match.group(2),
                'timestamp': match.group(4),
                'method': match.group(5),
                'path': match.group(6),
                'protocol': match.group(7),
                'status': int(match.group(8)),
                'size': int(match.group(9))
            }
        return {}
    
    def _parse_nginx_log(self, log_content: str) -> Dict[str, Any]:
        """解析Nginx日志"""
        pattern = r'^(\S+) - (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'  # noqa: E501
        match = re.match(pattern, log_content)
        if match:
            return {
                'ip': match.group(1),
                'user': match.group(2),
                'timestamp': match.group(3),
                'method': match.group(4),
                'path': match.group(5),
                'protocol': match.group(6),
                'status': int(match.group(7)),
                'size': int(match.group(8))
            }
        return {}
    
    def _parse_iis_log(self, log_content: str) -> Dict[str, Any]:
        """解析IIS日志"""
        parts = log_content.split(' ')
        if len(parts) >= 9:
            return {
                'date': parts[0],
                'time': parts[1],
                's-ip': parts[2],
                'cs-method': parts[3],
                'cs-uri-stem': parts[4],
                'cs-uri-query': parts[5],
                's-port': parts[6],
                'cs-username': parts[7],
                'c-ip': parts[8]
            }
        return {}
    
    def _parse_syslog(self, log_content: str) -> Dict[str, Any]:
        """解析Syslog日志"""
        pattern = r'^<(\d+)>(\S+) (\S+) (\S+:\S+:\S+) (\S+) (\S+):(.*)$'  # noqa: E501
        match = re.match(pattern, log_content)
        if match:
            return {
                'priority': int(match.group(1)),
                'month': match.group(2),
                'day': match.group(3),
                'time': match.group(4),
                'host': match.group(5),
                'process': match.group(6),
                'message': match.group(7).strip()
            }
        return {}
    
    def _parse_windows_log(self, log_content: str) -> Dict[str, Any]:
        """解析Windows事件日志"""
        parts = log_content.split(' ')
        if len(parts) >= 10:
            return {
                'date': parts[0],
                'time': parts[1],
                'level': parts[2],
                'source': parts[3],
                'eventid': parts[4],
                'task': parts[5],
                'keywords': parts[6],
                'computer': parts[7],
                'user': parts[8],
                'message': ' '.join(parts[9:])
            }
        return {}
    
    def _parse_custom_log(self, log_content: str) -> Dict[str, Any]:
        """解析自定义格式日志"""
        # 尝试提取常见字段
        result = {}
        
        # 提取IP地址
        ips = self.ip_pattern.findall(log_content)
        if ips:
            result['ip'] = ips[0]
        
        # 提取时间戳
        timestamp_pattern = re.compile(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?')
        timestamps = timestamp_pattern.findall(log_content)
        if timestamps:
            result['timestamp'] = timestamps[0]
        
        # 提取HTTP方法和路径
        http_pattern = re.compile(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)')
        http_match = http_pattern.search(log_content)
        if http_match:
            result['method'] = http_match.group(1)
            result['path'] = http_match.group(2)
        
        # 提取状态码 - 只提取有效的HTTP状态码（100-599），避免提取IP地址中的数字
        status_pattern = re.compile(r'(?<![\.\d])\b([1-5]\d{2})\b(?!\.)')
        status_codes = status_pattern.findall(log_content)
        if status_codes:
            # 取第一个匹配的状态码
            result['status'] = int(status_codes[0])
        
        # 尝试解析URL格式的内容
        # 如果内容包含://，尝试解析为URL
        if '://' in log_content:
            try:
                parsed_url = urlparse(log_content)
                if parsed_url.scheme:
                    result['url_scheme'] = parsed_url.scheme
                if parsed_url.netloc:
                    result['url_host'] = parsed_url.netloc
                    # 从主机中提取端口
                    if ':' in parsed_url.netloc:
                        host, port = parsed_url.netloc.split(':', 1)
                        result['url_hostname'] = host
                        result['url_port'] = port
                    else:
                        result['url_hostname'] = parsed_url.netloc
                if parsed_url.path:
                    result['url_path'] = parsed_url.path
                if parsed_url.query:
                    result['url_query'] = parsed_url.query
                    # 解析查询参数
                    query_params = {}
                    
                    # 特殊处理PHP-CGI的%add格式
                    if '%add' in parsed_url.query:
                        # 按%add分割查询字符串
                        parts = parsed_url.query.split('%add')
                        for part in parts:
                            part = part.strip()
                            if not part:
                                continue
                            # 尝试解析为键值对
                            if '=' in part:
                                key, value = part.split('=', 1)
                                key = key.strip()
                                value = value.strip()
                                query_params[key] = [value]
                    else:
                        # 使用标准解析
                        query_params = parse_qs(parsed_url.query)
                    
                    if query_params:
                        result['query_params'] = query_params
                if parsed_url.fragment:
                    result['url_fragment'] = parsed_url.fragment
            except Exception as e:
                logger.debug(f"URL解析失败: {e}")
        
        # 如果未提取到方法但提取到URL路径，则设置默认方法为GET
        if 'method' not in result and 'url_path' in result:
            result['method'] = 'GET'
            result['path'] = result['url_path']
        
        return result
    
    def _rule_sql_injection(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """SQL注入检测规则 - 优化版本，增加上下文判断"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # 提取查询参数部分，SQL注入通常出现在参数值中
        query_content = str(log_data.get('url_query', ''))
        
        # 高可信度的SQL注入模式 - 在参数值中检测
        high_confidence_patterns = [
            # SQL语句片段
            r'(?:SELECT|INSERT|UPDATE|DELETE).*(?:FROM|INTO|SET|WHERE).*\b(?:SELECT|INSERT|UPDATE|DELETE)',
            r'UNION\s+(?:ALL\s+)?SELECT',
            r'\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\b(?:FROM|INTO|SET)\b.*[\'"\s](?:OR|AND)\s+[\'"\s]*\d+\s*=\s*\d+',
            
            # SQL注释攻击
            r'--\s*[\w\s]*$',
            r'/\*.*\*/',
            
            # 永真条件
            r'[\'"\s](?:OR|AND)\s+[\'"\s]*\d+\s*=\s*\d+[\'"\s]',
            r'[\'"\s](?:OR|AND)\s+[\'"\s]*["\']?["\']?\s*=\s*["\']?["\']?',
            r"[\'\"]\s*(?:OR|AND)\s+['\"]?['\"]?\s*=\s*['\"]?['\"]?",
            
            # 堆叠查询
            r';\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)',
            
            # 盲注模式
            r'(?:SELECT|INSERT|UPDATE|DELETE).*SLEEP\s*\(\d+\)',
            r'(?:SELECT|INSERT|UPDATE|DELETE).*BENCHMARK\s*\(\d+',
            r'WAITFOR\s+DELAY\s+[\'"]00:00:\d+[\'"]',
        ]
        
        # 中可信度的SQL注入模式
        medium_confidence_patterns = [
            # 常见的SQL关键字组合
            r'\bSELECT\b.*\bFROM\b',
            r'\bINSERT\b.*\bINTO\b',
            r'\bUPDATE\b.*\bSET\b',
            r'\bDELETE\b.*\bFROM\b',
            r'\bDROP\b.*\b(?:TABLE|DATABASE)\b',
            r'\bCREATE\b.*\b(?:TABLE|DATABASE)\b',
            r'\bALTER\b.*\bTABLE\b',
            
            # 可疑的字符
            r"['\"]\s*(?:OR|AND)\s*['\"]",
            r'[\'"][^,\'"]*--[^,\'"]*[\'"]',
        ]
        
        # 检查查询参数中的SQL注入（最高优先级）
        if query_content:
            for pattern in high_confidence_patterns:
                if re.search(pattern, query_content, re.IGNORECASE):
                    return {
                        'rule_name': 'SQL注入检测',
                        'match': pattern,
                        'severity': 'Critical',
                        'description': '在查询参数中检测到高可信度的SQL注入攻击尝试',
                        'confidence': 'high',
                        'context': 'query_parameters'
                    }
            
            for pattern in medium_confidence_patterns:
                if re.search(pattern, query_content, re.IGNORECASE):
                    return {
                        'rule_name': 'SQL注入检测',
                        'match': pattern,
                        'severity': 'High',
                        'description': '在查询参数中检测到可能的SQL注入攻击尝试',
                        'confidence': 'medium',
                        'context': 'query_parameters'
                    }
        
        # 检查完整内容中的SQL注入（作为后备）
        for pattern in high_confidence_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': 'SQL注入检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到SQL注入攻击尝试',
                    'confidence': 'medium',
                    'context': 'full_content'
                }
        
        return {}
    
    def _rule_xss(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """XSS攻击检测规则 - 优化版本，增加更多检测模式"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # 提取查询参数部分，XSS通常出现在参数值中
        query_content = str(log_data.get('url_query', ''))
        
        # 高可信度的XSS模式
        high_confidence_patterns = [
            # 完整的script标签
            r'<script\b[^>]*>.*?</script>',
            r'<script\b[^>]*/>',
            
            # 事件处理器
            r'on\w+\s*=\s*["\'][^"\']*["\']',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            
            # javascript伪协议
            r'javascript:\s*[^;\s]*\s*\([^)]*\)',
            r'data:\s*text/html',
            r'vbscript:',
            
            # 恶意HTML标签
            r'<iframe\b[^>]*>',
            r'<embed\b[^>]*>',
            r'<object\b[^>]*>',
            r'<svg\b[^>]*>.*?<script',
            
            # 编码的XSS
            r'%3Cscript%3E',
            r'%3Ciframe%3E',
            r'&#x3C;script&#x3E;',
        ]
        
        # 中可信度的XSS模式
        medium_confidence_patterns = [
            # 可疑的HTML标签片段
            r'<script',
            r'<iframe',
            r'<object',
            r'<embed',
            r'<svg',
            
            # 可疑的属性
            r'src\s*=\s*["\']javascript:',
            r'href\s*=\s*["\']javascript:',
            
            # 事件处理器名称
            r'on\w+\s*=',
            
            # 编码的字符
            r'&lt;script&gt;',
            r'&lt;iframe&gt;',
            
            # XSS尝试的常见模式
            r'"><script>',
            r'"></script><script>',
            r'"+alert\(',
            r'`+alert\(',
        ]
        
        # 检查查询参数中的XSS（最高优先级）
        if query_content:
            for pattern in high_confidence_patterns:
                if re.search(pattern, query_content, re.IGNORECASE):
                    return {
                        'rule_name': 'XSS攻击检测',
                        'match': pattern,
                        'severity': 'High',
                        'description': '在查询参数中检测到高可信度的XSS攻击尝试',
                        'confidence': 'high',
                        'context': 'query_parameters'
                    }
            
            for pattern in medium_confidence_patterns:
                if re.search(pattern, query_content, re.IGNORECASE):
                    return {
                        'rule_name': 'XSS攻击检测',
                        'match': pattern,
                        'severity': 'Medium',
                        'description': '在查询参数中检测到可能的XSS攻击尝试',
                        'confidence': 'medium',
                        'context': 'query_parameters'
                    }
        
        # 检查完整内容中的XSS（作为后备）
        for pattern in high_confidence_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': 'XSS攻击检测',
                    'match': pattern,
                    'severity': 'Medium',
                    'description': '检测到XSS攻击尝试',
                    'confidence': 'medium',
                    'context': 'full_content'
                }
        
        return {}
    
    def _rule_command_injection(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """命令注入检测规则 - 优化版本，减少误报"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # 提取查询参数部分，命令注入通常出现在参数值中
        query_content = str(log_data.get('url_query', '')) + str(log_data.get('path', ''))
        
        # 高可信度的命令注入模式 - 在参数值中检测特定命令
        high_confidence_patterns = [
            # 系统命令执行
            r'(?:;|\|\|?|&&?|`)\s*(?:sh|bash|cmd|powershell|python|perl|ruby|php)\b',
            r'(?:;|\|\|?|&&?|`)\s*(?:cat\s+/etc/passwd|ls\s+-la|whoami|id|uname\s+-a)',
            r'(?:;|\|\|?|&&?|`)\s*(?:rm\s+-rf|del\s+/f|format\s+)',
            r'(?:;|\|\|?|&&?|`)\s*(?:wget|curl|nc|netcat|telnet)\s+',
            r'(?:;|\|\|?|&&?|`)\s*(?:echo\s+.+?>|>>\s+.+)',
            
            # 特定系统文件访问
            r'cat\s+/etc/(?:passwd|shadow|hosts|group)',
            r'type\s+[a-z]:\\windows\\system32\\',
            r'dir\s+[a-z]:\\windows\\',
            
            # 命令执行函数
            r'\b(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*\$',
            r'\beval\s*\([^)]*\$',
            
            # 反弹shell模式
            r'(?:bash|sh|cmd)\s+-i\s*>&\s*/dev/',
            r'(?:python|perl|ruby|php)\s+-c\s+["\'].*socket.*connect',
            r'n[ce]?\s+-[le]\s+/bin/(?:bash|sh)',
        ]
        
        # 中可信度的命令注入模式 - 需要更多上下文
        medium_confidence_patterns = [
            # 在参数值中的可疑模式
            r'[?&][^=]+=(?:;|\|\|?|&&?|`)',
            r'(?:cmd|command|exec|run)=[^&]*[;|&`]',
            
            # 可疑的命令片段
            r'\b(?:/bin/(?:sh|bash)|/usr/bin/(?:python|perl))\b',
            r'\b(?:cmd\.exe|powershell\.exe|wscript\.exe)\b',
            
            # 常见的命令注入尝试
            r'127\.0\.0\.1\s*;\s*\w+',
            r'localhost\s*&\s*\w+',
        ]
        
        # 首先检查高可信度模式
        for pattern in high_confidence_patterns:
            if re.search(pattern, query_content, re.IGNORECASE):
                return {
                    'rule_name': '命令注入检测',
                    'match': pattern,
                    'severity': 'Critical',
                    'description': '检测到高可信度的命令注入攻击尝试',
                    'confidence': 'high'
                }
        
        # 检查中可信度模式
        for pattern in medium_confidence_patterns:
            if re.search(pattern, query_content, re.IGNORECASE):
                return {
                    'rule_name': '命令注入检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到可能的命令注入攻击尝试',
                    'confidence': 'medium'
                }
        
        # 检查原始内容中的明显命令执行（作为后备）
        for pattern in [
            r'\bcat\s+/etc/passwd\b',
            r'\brm\s+-rf\s+/\b',
            r'\bformat\s+[a-z]:\b',
            r'\bwget\s+http://.*\.(?:exe|sh|bat)\b',
        ]:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': '命令注入检测',
                    'match': pattern,
                    'severity': 'Critical',
                    'description': '检测到明显的命令注入攻击尝试',
                    'confidence': 'high'
                }
        
        return {}
    
    def _rule_buffer_overflow(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """缓冲区溢出检测规则 - 优化版本，增加更多检测模式"""
        content = str(log_data.get('raw', ''))
        path = str(log_data.get('path', ''))
        query = str(log_data.get('url_query', ''))
        
        # 检测异常长的字符串
        if len(content) > 10000:
            return {
                'rule_name': '缓冲区溢出检测',
                'match': '超长字符串',
                'severity': 'Critical',
                'description': '检测到可能的缓冲区溢出攻击（超长内容）',
                'confidence': 'medium'
            }
        
        # 检测超长的查询参数值（典型的缓冲区溢出目标）
        if query:
            # 查找参数值长度超过500字符的情况
            param_pattern = r'[?&]([^=]+)=([^&]*)'
            for param_name, param_value in re.findall(param_pattern, query):
                if len(param_value) > 500:
                    return {
                        'rule_name': '缓冲区溢出检测',
                        'match': f'超长参数值: {param_name}',
                        'severity': 'High',
                        'description': f'检测到超长的参数值（{len(param_value)}字符），可能是缓冲区溢出攻击尝试',
                        'confidence': 'medium'
                    }
        
        # 检测路径遍历中的超长路径
        if len(path) > 500:
            return {
                'rule_name': '缓冲区溢出检测',
                'match': '超长路径',
                'severity': 'High',
                'description': '检测到超长路径，可能是缓冲区溢出攻击尝试',
                'confidence': 'medium'
            }
        
        # 检测大量重复字符（典型的缓冲区溢出模式）
        if re.search(r'(.)\1{100,}', content):
            return {
                'rule_name': '缓冲区溢出检测',
                'match': '大量重复字符',
                'severity': 'Medium',
                'description': '检测到大量重复字符，可能是缓冲区溢出攻击尝试',
                'confidence': 'low'
            }
        
        # 检测常见的缓冲区溢出攻击模式
        buffer_overflow_patterns = [
            r'A{100,}',  # 大量的'A'字符
            r'\x90{50,}',  # NOP sled
            r'/bin/sh\x00',  # shellcode片段
            r'eip.*ebp.*esp',  # 寄存器操作
            r'0x[0-9a-f]{8}',  # 内存地址
        ]
        
        for pattern in buffer_overflow_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': '缓冲区溢出检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到缓冲区溢出攻击的典型模式',
                    'confidence': 'medium'
                }
        
        return {}
    
    def _rule_brute_force(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """暴力破解检测规则 - 改进版本，添加基本模式检测"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # 暴力破解常见模式
        brute_force_patterns = [
            # 登录失败相关
            r'(?:failed|invalid|incorrect|wrong).*(?:password|login|authentication|credential)',
            r'(?:password|login|auth).*(?:failed|invalid|incorrect|wrong)',
            r'user.*not.*found|account.*locked|too.*many.*attempts',
            
            # 常见的暴力破解路径
            r'/wp-login\.php',
            r'/admin/login',
            r'/administrator/index\.php',
            r'/user/login',
            r'/api/login',
            r'/oauth/token',
            
            # 暴力破解工具特征
            r'hydra|medusa|ncrack|patator|bruteforce',
            r'username=.*&password=.*',
            r'login\.php.*POST.*username=.*password=',
            
            # 爆破参数
            r'[?&](?:user|username|login|email)=[^&]*&(?:pass|password|pwd)=[^&]*',
            r'[?&]attempt=[0-9]+',
            r'[?&]retry=[0-9]+',
        ]
        
        # 检查状态码为401/403的认证失败
        status_code = log_data.get('status_code', '')
        if status_code in ['401', '403']:
            # 结合路径判断是否是认证端点
            path = str(log_data.get('path', '')).lower()
            auth_endpoints = ['/login', '/auth', '/signin', '/wp-login.php', '/admin']
            for endpoint in auth_endpoints:
                if endpoint in path:
                    return {
                        'rule_name': '暴力破解检测',
                        'match': f'认证失败: {path} (状态码: {status_code})',
                        'severity': 'Medium',
                        'description': '检测到认证端点上的失败请求，可能是暴力破解尝试',
                        'confidence': 'medium'
                    }
        
        # 检查暴力破解模式
        for pattern in brute_force_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': '暴力破解检测',
                    'match': pattern,
                    'severity': 'Medium',
                    'description': '检测到暴力破解攻击的特征模式',
                    'confidence': 'low'
                }
        
        return {}
    
    def _rule_dos_attack(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """DDoS攻击检测规则 - 改进版本，添加基本模式检测"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # DDoS攻击常见模式
        dos_patterns = [
            # 慢速攻击模式
            r'slowloris|slowhttptest|r-u-dead-yet',
            r'keep-alive.*timeout.*[0-9]{4,}',
            r'content-length.*[0-9]{7,}',
            
            # 洪水攻击相关
            r'flood|overload|excessive.*request',
            r'too.*many.*request|rate.*limit.*exceeded',
            
            # 反射放大攻击
            r'ntp.*monlist|dns.*amplification|snmp.*bulk',
            r'chargen|qotd|memcached.*udp',
            
            # 应用层DDoS特征
            r'user-agent:.*(?:python|curl|wget|scan|bot|crawler)',
            r'referer:.*\.(?:cn|ru|br)',
            r'x-forwarded-for:.*\d+\.\d+\.\d+\.\d+,\d+\.\d+\.\d+\.\d+',
            
            # 可疑的请求模式
            r'GET.*/.*\..*\.\.\.\.\.',  # 重复的点
            r'GET.*/.*\?.*&.*&.*&.*&.*&',  # 大量参数
            r'POST.*/.*content-length:.*0',
        ]
        
        # 检查异常的请求特征
        method = log_data.get('method', '')
        user_agent = str(log_data.get('user_agent', '')).lower()
        
        # 检测常见的DDoS工具用户代理
        ddos_tools = ['slowhttptest', 'goldeneye', 'hulk', 'loic', 'hoic', 'xerxes']
        for tool in ddos_tools:
            if tool in user_agent:
                return {
                    'rule_name': 'DDoS攻击检测',
                    'match': f'DDoS工具用户代理: {tool}',
                    'severity': 'High',
                    'description': f'检测到DDoS攻击工具"{tool}"的用户代理',
                    'confidence': 'high'
                }
        
        # 检测可疑的HTTP方法组合
        if method in ['GET', 'POST']:
            path = str(log_data.get('path', ''))
            # 检测对同一路径的大量不同查询参数（模拟）
            if '?' in path and len(path.split('&')) > 10:
                return {
                    'rule_name': 'DDoS攻击检测',
                    'match': '大量查询参数',
                    'severity': 'Medium',
                    'description': '检测到带有大量查询参数的请求，可能是DDoS攻击尝试',
                    'confidence': 'low'
                }
        
        # 检查DDoS模式
        for pattern in dos_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': 'DDoS攻击检测',
                    'match': pattern,
                    'severity': 'Medium',
                    'description': '检测到DDoS攻击的特征模式',
                    'confidence': 'medium'
                }
        
        return {}
    
    def _rule_malware_download(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """恶意软件下载检测规则 - 优化版本，增加更多检测模式"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # 提取路径部分，恶意软件下载通常出现在路径中
        path_content = str(log_data.get('path', ''))
        
        # 高可信度的恶意软件模式
        high_confidence_patterns = [
            # 可疑的可执行文件下载
            r'\.(?:exe|msi|scr|pif|com|bat|cmd|vbs|js|jar|apk|dmg)\b.*\bdownload\b',
            r'\bdownload\b.*\.(?:exe|msi|scr|pif|com|bat|cmd|vbs|js|jar|apk|dmg)\b',
            
            # Webshell文件
            r'\.(?:php|asp|aspx|jsp|cfm)\b.*\b(?:shell|backdoor|cmd|webshell|wso|b374k)\b',
            r'\b(?:shell|backdoor|cmd|webshell|wso|b374k)\b.*\.(?:php|asp|aspx|jsp|cfm)\b',
            
            # 恶意脚本
            r'\.(?:js|vbs|ps1|sh|bash)\b.*\b(?:malware|virus|trojan|worm|ransomware)\b',
            r'\b(?:malware|virus|trojan|worm|ransomware)\b.*\.(?:js|vbs|ps1|sh|bash)\b',
            
            # 编码/混淆的恶意软件
            r'base64_decode.*\.(?:exe|dll|php|asp)',
            r'eval\s*\(.*base64_decode',
            r'gzinflate\s*\(.*base64_decode',
            
            # 远程下载执行
            r'wget\s+.*\.(?:exe|sh|bin|elf)',
            r'curl\s+.*\.(?:exe|sh|bin|elf)',
            r'powershell\s+.*download',
            r'certutil\s+.*urlcache',
        ]
        
        # 中可信度的恶意软件模式
        medium_confidence_patterns = [
            # 可疑的文件扩展名（在可疑上下文中）
            r'/[^/]*\.(?:exe|dll|sys|drv|vxd|ocx|cpl|scr|pif|hta|msi|msp|mst)\b',
            r'/[^/]*\.(?:php|asp|aspx|jsp|cfm)\?[^=]*=.*(?:cmd|exec|system|shell)',
            r'/[^/]*\.(?:php|asp|aspx|jsp|cfm)\?.*\.(?:exe|dll|bin)',
            
            # 常见的恶意软件名称
            r'/(?:mimikatz|empire|metasploit|meterpreter|cobaltstrike|beacon)',
            r'/(?:nc\.exe|netcat|plink|putty|nmap|sqlmap|hydra|john)',
            
            # 可疑的下载路径
            r'/uploads/.*\.(?:php|asp|aspx|jsp|exe|dll)',
            r'/tmp/.*\.(?:php|sh|pl|py|rb)',
            r'/var/www/.*\.(?:php|asp|aspx|jsp)\.(?:bak|old|tmp)',
        ]
        
        # 低可信度的恶意软件模式（仅扩展名检测）
        low_confidence_patterns = [
            r'\.exe\b',
            r'\.dll\b',
            r'\.bat\b',
            r'\.cmd\b',
            r'\.ps1\b',
            r'\.vbs\b',
            r'\.js\b',
            r'\.php\b.*\b(?:system|exec|shell_exec|passthru)\b',
        ]
        
        # 检查高可信度模式
        for pattern in high_confidence_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': '恶意软件下载检测',
                    'match': pattern,
                    'severity': 'Critical',
                    'description': '检测到高可信度的恶意软件下载尝试',
                    'confidence': 'high'
                }
        
        # 检查中可信度模式
        for pattern in medium_confidence_patterns:
            if re.search(pattern, path_content, re.IGNORECASE):
                return {
                    'rule_name': '恶意软件下载检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到可能的恶意软件下载尝试',
                    'confidence': 'medium'
                }
        
        # 检查低可信度模式（仅作为后备）
        for pattern in low_confidence_patterns:
            if re.search(pattern, path_content, re.IGNORECASE):
                return {
                    'rule_name': '恶意软件下载检测',
                    'match': pattern,
                    'severity': 'Medium',
                    'description': '检测到可疑的文件下载',
                    'confidence': 'low'
                }
        
        return {}
    
    def _rule_abnormal_access_pattern(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """异常访问模式检测规则 - 改进版本，减少误报"""
        content = str(log_data.get('raw', ''))
        
        # 如果方法为空，不进行检测（避免误报）
        method = log_data.get('method', '')
        if not method:
            return {}
        
        method = method.upper()
        
        # 允许的HTTP方法列表
        allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE']
        
        if method not in allowed_methods:
            # 检查是否是已知但可疑的方法
            suspicious_methods = ['DEBUG', 'TRACK', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
            
            if method in suspicious_methods:
                return {
                    'rule_name': '异常访问模式检测',
                    'match': f'可疑HTTP方法: {method}',
                    'severity': 'Medium',
                    'description': '检测到可疑的HTTP方法',
                    'confidence': 'medium'
                }
            else:
                return {
                    'rule_name': '异常访问模式检测',
                    'match': f'未知HTTP方法: {method}',
                    'severity': 'Low',
                    'description': '检测到未知的HTTP方法',
                    'confidence': 'low'
                }
        
        return {}
    
    def _rule_php_config_injection(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """PHP配置注入检测规则"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # PHP-CGI参数注入模式 (CVE-2012-1823等)
        php_config_patterns = [
            r'cgi\.force_redirect\s*=\s*[01]',
            r'allow_url_include\s*=\s*[01]',
            r'auto_prepend_file\s*=\s*php://',
            r'auto_append_file\s*=\s*php://',
            r'%add\s+cgi\.',
            r'cgi\.redirect_status_env',
            r'php-cgi\.exe\?%add',
            r'php_value\s+',
            r'php_flag\s+',
            r'php_admin_value\s+',
            r'php_admin_flag\s+'
        ]
        
        for pattern in php_config_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': 'PHP配置注入检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到PHP配置注入攻击尝试（CVE-2012-1823等）',
                    'confidence': 'high'
                }
        return {}
    
    def _rule_ssrf(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """SSRF（服务器端请求伪造）检测规则"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # SSRF攻击模式
        ssrf_patterns = [
            # 内部地址访问
            r'url\s*=\s*["\']?(?:http://|https://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)',
            r'url\s*=\s*["\']?(?:http://|https://)?(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)',
            r'url\s*=\s*["\']?(?:http://|https://)?169\.254\.',
            r'url\s*=\s*["\']?(?:http://|https://)?metadata\.google\.internal',
            r'url\s*=\s*["\']?(?:http://|https://)?169\.254\.169\.254',  # AWS元数据服务
            
            # 可疑的URL参数
            r'[?&](?:url|uri|path|file|src|dest|redirect|proxy|api)=[^&]*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)',
            r'[?&](?:url|uri|path|file|src|dest|redirect|proxy|api)=[^&]*(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)',
            
            # 文件协议滥用
            r'file:///(?:etc/passwd|etc/hosts|proc/self|windows/win\.ini)',
            r'gopher://|dict://|sftp://',
            
            # AWS/Azure/GCP元数据端点
            r'169\.254\.169\.254',
            r'metadata\.google\.internal',
            r'169\.254\.169\.254/latest/meta-data',
            r'metadata\.azure\.com',
        ]
        
        for pattern in ssrf_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': 'SSRF攻击检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到SSRF（服务器端请求伪造）攻击尝试',
                    'confidence': 'medium'
                }
        return {}
    
    def _rule_directory_traversal(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """目录遍历/路径遍历检测规则"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # 目录遍历攻击模式
        traversal_patterns = [
            # 经典的目录遍历
            r'\.\./\.\./',
            r'\.\.\\\.\.\\',
            r'\.\.%2f\.\.%2f',
            r'\.\.%5c\.\.%5c',
            
            # 绝对路径遍历
            r'/etc/passwd',
            r'/etc/shadow',
            r'/etc/hosts',
            r'/proc/self',
            r'/var/log',
            r'C:\\windows\\win\.ini',
            r'C:\\windows\\system32',
            
            # 编码的目录遍历
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'\.\.%00/',
            r'\.\.%0a/',
            
            # 参数中的目录遍历
            r'[?&][^=]+=.*\.\./',
            r'[?&]file=.*\.\./',
            r'[?&]path=.*\.\./',
            r'[?&]filename=.*\.\./',
            
            # 常见的敏感文件访问
            r'\.\./\.\./etc/passwd',
            r'\.\./\.\./windows/win\.ini',
            r'\.\./\.\./\.\./etc/shadow',
        ]
        
        for pattern in traversal_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': '目录遍历攻击检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到目录遍历/路径遍历攻击尝试',
                    'confidence': 'medium'
                }
        return {}
    
    def _rule_file_inclusion(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """文件包含（LFI/RFI）检测规则"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # 文件包含攻击模式
        inclusion_patterns = [
            # 本地文件包含
            r'[?&][^=]+=.*\.\./.*\.(?:php|asp|aspx|jsp|cfm|inc)',
            r'[?&](?:page|file|module|template)=.*\.\./',
            r'[?&](?:page|file|module|template)=.*/etc/passwd',
            r'[?&](?:page|file|module|template)=.*php://',
            
            # 远程文件包含
            r'[?&][^=]+=https?://',
            r'[?&](?:page|file|module|template)=https?://',
            r'[?&][^=]+=ftp://',
            r'[?&][^=]+=data:text/html',
            
            # PHP包装器
            r'php://input',
            r'php://filter',
            r'data://',
            r'expect://',
            r'zip://',
            
            # 编码的文件包含
            r'%2fetc%2fpasswd',
            r'%2fvar%2fwww',
            r'http%3a%2f%2f',
        ]
        
        for pattern in inclusion_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': '文件包含攻击检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到文件包含（LFI/RFI）攻击尝试',
                    'confidence': 'medium'
                }
        return {}
    
    def _rule_xxe(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """XXE（XML外部实体注入）检测规则"""
        content = str(log_data.get('raw', '')) + str(log_data.get('path', '')) + str(log_data.get('url_query', ''))
        
        # XXE攻击模式
        xxe_patterns = [
            # XML外部实体声明
            r'<!ENTITY.*SYSTEM.*["\']',
            r'<!DOCTYPE.*\[.*<!ENTITY',
            r'%[^;]+;',
            
            # 外部实体引用
            r'&[^;]+;',
            r'file:///',
            r'http://internal',
            
            # XXE攻击载荷
            r'<!DOCTYPE.*\[.*<!ENTITY.*file.*SYSTEM.*["\']file:///',
            r'<!DOCTYPE.*\[.*<!ENTITY.*xxe.*SYSTEM.*["\']http://',
            r'<!DOCTYPE.*\[.*<!ENTITY.*%[^;]+;',
            
            # 盲注XXE
            r'<!ENTITY.*%[^;]+;.*<!ENTITY.*%[^;]+;',
            r'http://.*\?.*=.*&[^;]+;',
        ]
        
        for pattern in xxe_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'rule_name': 'XXE攻击检测',
                    'match': pattern,
                    'severity': 'High',
                    'description': '检测到XXE（XML外部实体注入）攻击尝试',
                    'confidence': 'medium'
                }
        return {}
    
    def analyze_with_rules(self, log_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """使用规则分析日志 - 优化版本，添加规则优先级和置信度处理
        
        Args:
            log_data: 日志数据
            
        Returns:
            规则匹配结果列表（按置信度和优先级排序）
        """
        results = []
        
        # 规则优先级映射（数值越高优先级越高）
        rule_priority = {
            '命令注入检测': 100,
            'SQL注入检测': 95,
            '缓冲区溢出检测': 90,
            'PHP配置注入检测': 85,
            '恶意软件下载检测': 80,
            'SSRF攻击检测': 75,
            '目录遍历攻击检测': 70,
            '文件包含攻击检测': 65,
            'XXE攻击检测': 60,
            'XSS攻击检测': 55,
            '暴力破解检测': 50,
            'DDoS攻击检测': 45,
            '异常访问模式检测': 40,
        }
        
        # 置信度权重映射
        confidence_weights = {
            'high': 1.0,
            'medium': 0.7,
            'low': 0.3,
        }
        
        # 收集所有规则结果
        for rule in self.analysis_rules:
            result = rule(log_data)
            if result:
                # 计算规则得分（优先级 × 置信度权重）
                rule_name = result.get('rule_name', '未知规则')
                confidence = result.get('confidence', 'medium')
                priority = rule_priority.get(rule_name, 50)
                weight = confidence_weights.get(confidence, 0.5)
                
                # 添加计算得分
                result['priority_score'] = priority * weight
                result['confidence_weight'] = weight
                
                results.append(result)
        
        # 按优先级得分排序（降序）
        results.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
        
        # 如果存在高置信度结果，过滤掉低置信度的重复检测
        if results:
            high_confidence_results = [r for r in results if r.get('confidence') == 'high']
            if len(high_confidence_results) >= 2:
                # 如果有多个高置信度结果，保留前3个
                results = results[:3]
            elif len(results) > 5:
                # 如果结果太多，只保留前5个
                results = results[:5]
        
        return results
    
    def get_threat_intel_summary(self) -> Dict[str, Any]:
        """获取威胁情报摘要"""
        return {
            'cache_size': len(self.threat_cache),
            'attack_classifier_available': self.attack_classifier is not None,
            'supported_log_formats': list(self.log_parsers.keys()),
            'analysis_rules_count': len(self.analysis_rules)
        }


# 全局日志分析器实例
_log_analyzer: Optional[LogAnalyzer] = None
_log_analyzer_lock = threading.Lock()


def get_log_analyzer(threat_intel_callback: Optional[Callable] = None, attack_classifier: Optional[Any] = None) -> LogAnalyzer:
    """获取全局日志分析器实例
    
    Args:
        threat_intel_callback: 威胁情报查询回调函数
        attack_classifier: 攻击分类器实例
        
    Returns:
        LogAnalyzer实例
    """
    global _log_analyzer
    
    if _log_analyzer is None:
        with _log_analyzer_lock:
            if _log_analyzer is None:
                _log_analyzer = LogAnalyzer(threat_intel_callback, attack_classifier)
    
    return _log_analyzer


def clear_log_analyzer():
    """清除全局日志分析器实例"""
    global _log_analyzer
    with _log_analyzer_lock:
        _log_analyzer = None
