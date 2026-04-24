import os
import json
import re
import math
import numpy as np
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

class EnhancedAttackClassifier:
    def __init__(self, model_path: Optional[str] = None):
        """初始化增强型攻击分类器"""
        self.model_path = model_path
        self.is_trained = False
        
        # 攻击类型定义
        self.attack_types = {
            0: 'Normal',
            1: 'SQL Injection',
            2: 'XSS',
            3: 'CSRF',
            4: 'DoS/DDoS',
            5: 'Brute Force',
            6: 'Path Traversal',
            7: 'Command Injection',
            8: 'SSRF',
            9: 'RCE',
            10: 'SSTI',
            11: 'IDOR',
            12: 'File Upload',
            13: 'Session Fixation',
            14: 'Parameter Pollution',
            15: 'Header Injection',
            16: 'CRLF Injection',
            17: 'Open Redirect',
            18: 'Host Header Injection',
            19: 'Protocol Downgrade',
            20: 'Authentication Bypass',
            21: 'API Abuse',
            22: 'Web Scraping',
            23: 'Data Exfiltration',
            24: 'Malware Infection'
        }
        
        # 攻击严重程度等级
        self.severity_levels = {
            'Critical': ['SQL Injection', 'RCE', 'Command Injection', 'SSTI', 'Authentication Bypass', 'Malware Infection'],
            'High': ['XSS', 'Path Traversal', 'SSRF', 'File Upload', 'RCE', 'Data Exfiltration'],
            'Medium': ['CSRF', 'Brute Force', 'IDOR', 'Session Fixation', 'Open Redirect', 'API Abuse'],
            'Low': ['DoS/DDoS', 'Header Injection', 'CRLF Injection', 'Parameter Pollution', 
                   'Host Header Injection', 'Protocol Downgrade', 'Web Scraping']
        }
        
        # 机器学习参数
        self.ml_params = {
            'anomaly_threshold': 0.7,
            'confidence_threshold': 0.5,
            'behavior_window': 300,
            'attack_probability_threshold': 0.6
        }
        
        # 增强的攻击特征模式库
        self.attack_patterns = self._build_enhanced_patterns()
        
        # 历史记录（用于行为分析）
        self.history = defaultdict(list)
        self.max_history_size = 5000
        
        # 统计信息
        self.statistics = {
            'total_classifications': 0,
            'attack_counts': Counter(),
            'cache_hits': 0,
            'cache_misses': 0,
            'processing_times': [],
            'average_processing_time': 0.0
        }
        
        # 缓存机制
        self.cache = {}
        self.cache_size = 10000
        self.cache_keys = []  # 用于LRU缓存管理
        
        # 威胁情报库
        self.threat_intel = self._build_threat_intel()
        
        # 模型版本信息
        self.model_info = {
            'version': '2.1',
            'features': 52,
            'classifiers': len(self.attack_types),
            'last_trained': None,
            'performance': {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'confusion_matrix': None
            }
        }
        
        # 机器学习模型
        self.scaler = StandardScaler()
        self.ml_model = RandomForestClassifier(
            n_estimators=300,  # 增加树的数量以提高准确率
            max_depth=25,  # 增加树深度以捕获更复杂的模式
            min_samples_split=4,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1,
            bootstrap=True,
            max_features='sqrt',
            class_weight='balanced'  # 处理不平衡数据
        )
        self.feature_names = []
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def load_history_from_database(self, db_path: str = None):
        """从数据库加载历史记录"""
        try:
            import sqlite3
            if db_path is None:
                # 默认数据库路径
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                db_path = os.path.join(project_root, 'data', 'network_attack_analyzer.db')
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # 查询所有日志记录
            cursor.execute('''
                SELECT ip, timestamp, path, method, status, size, user_agent
                FROM logs
                ORDER BY timestamp DESC
                LIMIT 5000
            ''')
            
            rows = cursor.fetchall()
            
            # 按IP分组并加载到历史记录中
            for row in rows:
                ip, timestamp_str, path, method, status, size, user_agent = row
                
                # 解析时间戳
                try:
                    if timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        # 移除时区信息，确保所有时间戳都是naive datetime
                        if timestamp.tzinfo is not None:
                            timestamp = timestamp.replace(tzinfo=None)
                    else:
                        timestamp = datetime.now()
                except:
                    timestamp = datetime.now()
                
                # 计算UA哈希
                ua_hash = hashlib.md5((user_agent or '').encode()).hexdigest()[:8]
                
                # 添加到历史记录
                self.history[ip].append({
                    'timestamp': timestamp,
                    'path': path or '',
                    'method': method or '',
                    'status': status or 200,
                    'ua_hash': ua_hash,
                    'size': size or 0
                })
                
                # 限制历史记录大小
                if len(self.history[ip]) > self.max_history_size:
                    self.history[ip] = self.history[ip][-self.max_history_size:]
            
            conn.close()
            print(f"Loaded {len(rows)} log entries from database for {len(self.history)} unique IPs")
            return True
            
        except Exception as e:
            print(f"Error loading history from database: {e}")
            return False
    
    def _build_enhanced_patterns(self) -> Dict[str, Dict[str, Any]]:
        """构建增强的攻击特征模式库"""
        patterns = {
            'SQL Injection': {
                'patterns': [
                    r'(?i)(\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b)',
                    r'(?i)(\bunion\b.*\bselect\b|\bunion\s+all\s+select\b)',
                    r'(?i)(\b1\s*=\s*1\b|\b1\s*=\s*2\b)',
                    r'(?i)(--\s|#\s|/\*.*\*/)',
                    r'(?i)(\bwaitfor\b\s*\bfor\b|\bdelay\b|\bsleep\s*\()',
                    r'(?i)(\bexec\b|\bexecute\b|\bsp_executesql)',
                    r'(?i)(\binformation_schema\b|\bsys\.tables\b)',
                    r'(?i)(\b@@version\b|\buser\s*\(\s*\)|\bdatabase\s*\(\s*\))',
                    r'(?i)(\bor\s+1\s*=\s*1|\band\s+1\s*=\s*1|\bor\s+1\s*=\s*2|\band\s+1\s*=\s*2)'
                ],
                'keywords': ['sql', 'injection', 'database', 'query', 'table', 'select', 'union'],
                'threshold': 2,
                'severity': 'Critical',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'XSS': {
                'patterns': [
                    r'(?i)(<script[^>]*>.*?</script>|<script[^>]*>)',
                    r'(?i)(javascript:|vbscript:|data:text/html)',
                    r'(?i)(on\w+\s*=\s*["\']?\s*(javascript:|alert\s*\())',
                    r'(?i)(<iframe[^>]*>|<object[^>]*>|<embed[^>]*>)',
                    r'(?i)(document\.cookie|document\.location|window\.location)',
                    r'(?i)(eval\s*\(|expression\s*\()',
                    r'(?i)(<img[^>]*\s+onerror\s*=|<svg[^>]*\s+onload\s*=)'
                ],
                'keywords': ['xss', 'script', 'javascript', 'html', 'injection', 'cross-site'],
                'threshold': 2,
                'severity': 'High',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': True
                }
            },
            'CSRF': {
                'patterns': [
                    r'(?i)(\bcsrf\b|\bx-csrf-token\b|\bcsrf-token\b|\banti-csrf\b)',
                    r'(?i)(\breferer\b.*\bexternal\b|\borigin\b.*\bdifferent\b)',
                    r'(?i)(\bcookie\b.*\bsession\b|\bsessionid\b|\bphpsessid\b)',
                    r'(?i)(\banti-forgery\b|\banti-request-forgery\b)',
                    r'(?i)(\bcsrfmiddlewaretoken\b|\bauthenticity_token\b)',
                    r'(?i)(/transfer|/payment|/change-password|/update-profile|/delete-account|/withdraw|/deposit)'
                ],
                'keywords': ['csrf', 'token', 'session', 'cookie', 'forgery', 'cross-site'],
                'threshold': 1,
                'severity': 'Medium',
                'context_rules': {
                    'path_sensitive': False,
                    'param_sensitive': True,
                    'header_sensitive': True
                }
            },
            'DoS/DDoS': {
                'patterns': [
                    r'(?i)(\bslowloris\b|\bsyn\s+flood\b|\budp\s+flood\b)',
                    r'(?i)(\bget\b.*\blarge\b.*\bfile\b|\brequest\b.*\bflood\b)',
                    r'(?i)(\bcpu\s+exhaustion\b|\bmemory\s+exhaustion\b)',
                    r'(?i)(\binfinite\s+loop\b|\brecursive\b.*\brequest\b)',
                    r'(?i)(\bhttp\s+flood\b|\bhttps\s+flood\b)',
                    r'(?i)(\bbandwidth\s+exhaustion\b|\bconnection\s+exhaustion\b)',
                    r'(?i)(\bslow\s+post\b|\bslow\s+loris\b)'
                ],
                'keywords': ['dos', 'ddos', 'flood', 'exhaustion', 'denial', 'slowloris'],
                'threshold': 1,
                'severity': 'Low',
                'context_rules': {
                    'path_sensitive': False,
                    'param_sensitive': False,
                    'header_sensitive': False
                }
            },
            'Brute Force': {
                'patterns': [
                    r'(?i)(\blogin\b.*\bfail\b|\bauth\b.*\bfail\b|\bpassword\b.*\bincorrect\b)',
                    r'(?i)(\bmultiple\s+login\s+attempts\b|\brapid\s+authentication\b)',
                    r'(?i)(\bdictionary\s+attack\b|\bcredential\s+stuffing\b)',
                    r'(?i)(\b401\b|\b403\b|\bauthentication\s+required\b)',
                    r'(?i)(\baccount\s+lockout\b|\btoo\s+many\s+attempts\b)',
                    r'(?i)(\bbrute\s+force\b|\bpassword\s+cracking\b)',
                    r'(?i)(\binvalid\s+username\b|\binvalid\s+password\b)'
                ],
                'keywords': ['brute', 'force', 'login', 'password', 'credential', 'auth', 'cracking'],
                'threshold': 2,
                'severity': 'Medium',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'Path Traversal': {
                'patterns': [
                    r'(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)',
                    r'(?i)(/etc/passwd|/etc/shadow|/etc/group|/etc/hosts)',
                    r'(?i)(/windows/system32|boot\.ini|win\.ini)',
                    r'(?i)(file://|php://|data://|expect://)',
                    r'(?i)(/proc/self|/var/log|/usr/local|/root/|/tmp/)',
                    r'(?i)(\.\.%2f|\.\.%5c|%252e%252e%252f)'
                ],
                'keywords': ['path', 'traversal', 'directory', 'file', 'access', 'lfi', 'rfi'],
                'threshold': 1,
                'severity': 'High',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'Command Injection': {
                'patterns': [
                    r'(?i)(\bping\b\s+-|\bls\b\s+-|\bcat\b\s+)',
                    r'(?i)(\bexec\b.*\(|\bsystem\b.*\(|\bshell_exec\b.*\(|\bpassthru\b.*\()',
                    r'(?i)(\brm\s+-rf\b|\bdel\s+/f\b|\bformat\b)',
                    r'(?i)(\bchmod\b\s+|chown\b\s+|sudo\b\s+-)',
                    r'(?i)(\bnohup\b\s+|screen\b\s+-|tmux\b\s+-)',
                    r'(?i)(\bid\b|\buname\b\s+-|env\b)',
                    r'(?i)(\bcrontab\b|\bat\b|\bbatch\b)',
                    r'(?i)(;\s*\bls\b|;\s*\bcat\b|;\s*\bwhoami\b|;\s*\bping\b)'
                ],
                'keywords': ['command', 'injection', 'shell', 'execution', 'os', 'rce', 'code'],
                'threshold': 1,
                'severity': 'Critical',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'SSRF': {
                'patterns': [
                    r'(?i)(url\s*=\s*http|url\s*=\s*https|url\s*=\s*file|url\s*=\s*ftp)',
                    r'(?i)(dest\s*=\s*http|dest\s*=\s*https|dest\s*=\s*file)',
                    r'(?i)(redirect\s*=\s*http|redirect\s*=\s*https|redirect\s*=\s*file)',
                    r'(?i)(\bssrf\b|\bserver\s+side\s+request\s+forgery\b)',
                    r'(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.16\.)',
                    r'(?i)(\binternal\b.*\burl\b|\bprivate\b.*\bip\b|\blocal\b.*\bhost\b)',
                    r'(?i)(\bgopher\b.*\b:\s*//|\bdict\b.*\b:\s*//|\bfile\b.*\b:\s*//)'
                ],
                'keywords': ['ssrf', 'server-side', 'request', 'forgery', 'internal', 'private', 'local'],
                'threshold': 1,
                'severity': 'High',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'RCE': {
                'patterns': [
                    r'(?i)(\bexec\b.*\(|\bsystem\b.*\(|\bshell_exec\b.*\(|\bpassthru\b.*\()',
                    r'(?i)(\bexec\b\s+\S+\s+\|\s+\S+|\bsystem\b\s+\S+\s+\|\s+\S+)',
                    r'(?i)(\bwhoami\b|\bwho\b|\busers\b|\benv\b)',
                    r'(?i)(\bnetstat\b.*\b-an\b|\bifconfig\b.*\b-a\b)',
                    r'(?i)(\bls\b.*\b-la\b|\bdir\b.*\b/s\b|\bcat\b.*\b/etc/passwd\b)',
                    r'(?i)(\bwget\b.*\b-o\b|\bcurl\b.*\b-o\b)',
                    r'(?i)(\bnc\b.*\b-e\b|\bnetcat\b.*\b-e\b|\bnc\b.*\b-l\b)'
                ],
                'keywords': ['rce', 'remote', 'code', 'execution', 'shell', 'command', 'system', 'exec'],
                'threshold': 2,
                'severity': 'Critical',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'SSTI': {
                'patterns': [
                    r'(?i)(\{\{[^}]*\}\}|{%[^%]*%}|{#[^#]*#}|\$\{[^}]*\})',
                    r'(?i)(\{\{\s*config\s*\}\}|\{\{\s*self\s*\}\}|\{\{\s*request\s*\}\})',
                    r'(?i)(\{\{\s*__class__\s*\}\}|\{\{\s*__mro__\s*\}\}|\{\{\s*__subclasses__\s*\}\})',
                    r'(?i)(\{\{\s*__globals__\s*\}\}|\{\{\s*__builtins__\s*\}\}|\{\{\s*__import__\s*\}\})',
                    r'(?i)(\bjinja2\b|\btwig\b|\bsmarty\b|\bhandlebars\b|\bmustache\b)',
                    r'(?i)(\brender\b.*\btemplate\b|\btemplate\b.*\brender\b)',
                    r'(?i)(\b__import__\s*\(\s*["\']os["\']|\b__import__\s*\(\s*["\']subprocess["\']\))'
                ],
                'keywords': ['ssti', 'server-side', 'template', 'injection', 'jinja2', 'twig', 'smarty'],
                'threshold': 1,
                'severity': 'High',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'IDOR': {
                'patterns': [
                    r'(?i)(\bid\s*=\s*\d+|\bid\s*=\s*\d+.*\bid\s*=\s*\d+)',
                    r'(?i)(\buser_id\s*=\s*\d+|\buser_id\s*=\s*\d+.*\buser_id\s*=\s*\d+)',
                    r'(?i)(\baccount_id\s*=\s*\d+|\baccount_id\s*=\s*\d+.*\baccount_id\s*=\s*\d+)',
                    r'(?i)(\bprofile_id\s*=\s*\d+|\bprofile_id\s*=\s*\d+.*\bprofile_id\s*=\s*\d+)',
                    r'(?i)(\bdocument_id\s*=\s*\d+|\bdocument_id\s*=\s*\d+.*\bdocument_id\s*=\s*\d+)',
                    r'(?i)(\bfile_id\s*=\s*\d+|\bfile_id\s*=\s*\d+.*\bfile_id\s*=\s*\d+)',
                    r'(?i)(\brecord_id\s*=\s*\d+|\brecord_id\s*=\s*\d+.*\brecord_id\s*=\s*\d+)',
                    r'(?i)(/api/users/\d+|/users/\d+|/user/\d+|/api/accounts/\d+|/accounts/\d+|/account/\d+|/api/profiles/\d+|/profiles/\d+|/profile/\d+|/api/documents/\d+|/documents/\d+|/document/\d+|/api/files/\d+|/files/\d+|/file/\d+|/api/records/\d+|/records/\d+|/record/\d+)'
                ],
                'keywords': ['idor', 'insecure', 'direct', 'object', 'reference', 'id'],
                'threshold': 1,
                'severity': 'Medium',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'File Upload': {
                'patterns': [
                    r'(?i)(\bupload\b.*\bfile\b|\bfile\b.*\bupload\b)',
                    r'(?i)(\bupload\b.*\bphp\b|\bupload\b.*\baspx\b|\bupload\b.*\bexe\b)',
                    r'(?i)(\.php\b|\.aspx\b|\.exe\b|\.bat\b|\.sh\b|\.ps1\b)',
                    r'(?i)(\bphar\b.*\b:\s*//|\bdata\b.*\b:\s*//|\bexpect\b.*\b:\s*//)',
                    r'(?i)(\bmove_uploaded_file\b|\bfile_put_contents\b|\bcopy\b)',
                    r'(?i)(\bwebshell\b|\bbackdoor\b|\bmalicious\b.*\bfile\b)',
                    r'(?i)(\bupload\b.*\bshell\b|\bshell\b.*\bupload\b)'
                ],
                'keywords': ['file', 'upload', 'php', 'webshell', 'malware', 'executable', 'shell'],
                'threshold': 2,
                'severity': 'High',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'Session Fixation': {
                'patterns': [
                    r'(?i)(\bsession_id\s*=\s*\w+|\bsessionid\s*=\s*\w+)',
                    r'(?i)(\bPHPSESSID\s*=\s*\w+|\bJSESSIONID\s*=\s*\w+)',
                    r'(?i)(\bsetcookie\b.*\bsession\b|\bsession\b.*\bcookie\b)',
                    r'(?i)(\bsession\b.*\bregenerate\b|\bregenerate\b.*\bsession\b)',
                    r'(?i)(\bsession\s+fixation\b|\bsession\s+hijacking\b)',
                    r'(?i)(\bcookie\b.*\bsession\b.*\bset\b)',
                    r'(?i)(\bURL\s+session\b.*\bfixation\b)'
                ],
                'keywords': ['session', 'fixation', 'hijacking', 'cookie', 'token', 'predefined'],
                'threshold': 2,
                'severity': 'Medium',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': True
                }
            },
            'Parameter Pollution': {
                'patterns': [
                    r'(?i)(\bparameter\s+pollution\b|\bhttp\s+parameter\s+pollution\b)',
                    r'(?i)(\bparam\b.*\bduplicate\b|\bparameter\b.*\bduplicate\b)',
                    r'(?i)(\bquery\s+string\b.*\bduplicate\b|\burl\s+param\b.*\bduplicate\b)',
                    r'(?i)(\bid=.*&id=|\bname=.*&name=|\buser=.*&user=)',
                    r'(?i)(\bparam\s+pollution\b|\bpp\s+attack\b)',
                    r'(?i)(\barray\s+parameter\b|\blist\s+parameter\b)',
                    r'(?i)(\bmultiple\s+values\b|\bduplicate\s+values\b)'
                ],
                'keywords': ['parameter', 'pollution', 'duplicate', 'http', 'param', 'override'],
                'threshold': 2,
                'severity': 'Low',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'Header Injection': {
                'patterns': [
                    r'(?i)(\bheader\s+injection\b|\bhttp\s+header\s+injection\b)',
                    r'(?i)(%0d%0a|%0D%0A|\r\n|\n\r|%0a|%0d)',
                    r'(?i)(\bCRLF\b.*\binjection\b|\bcarriage\s+return\b.*\bline\s+feed\b)',
                    r'(?i)(\bLocation\b.*%0d%0a|\bSet-Cookie\b.*%0d%0a)',
                    r'(?i)(\bresponse\s+splitting\b|\bheader\s+splitting\b)',
                    r'(?i)(\bdouble\s+CR\b|\bdouble\s+LF\b)',
                    r'(?i)(\bX-Forwarded-For\b.*\binjection\b|\bX-Real-IP\b.*\binjection\b)'
                ],
                'keywords': ['header', 'injection', 'crlf', 'response', 'splitting', 'carriage'],
                'threshold': 2,
                'severity': 'Low',
                'context_rules': {
                    'path_sensitive': False,
                    'param_sensitive': False,
                    'header_sensitive': True
                }
            },
            'Open Redirect': {
                'patterns': [
                    r'(?i)(\bredirect\s*=\s*http|\bredirect\s*=\s*https)',
                    r'(?i)(\burl\s*=\s*http|\burl\s*=\s*https)',
                    r'(?i)(\bnext\s*=\s*http|\bnext\s*=\s*https)',
                    r'(?i)(\breturn\s*=\s*http|\breturn\s*=\s*https)',
                    r'(?i)(\breturnurl\s*=\s*http|\breturnurl\s*=\s*https)',
                    r'(?i)(\bredirect_uri\s*=\s*http|\bredirect_uri\s*=\s*https)',
                    r'(?i)(\bforward\s*=\s*http|\bforward\s*=\s*https)'
                ],
                'keywords': ['open', 'redirect', 'url', 'location', 'forward', 'external'],
                'threshold': 2,
                'severity': 'Medium',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'Host Header Injection': {
                'patterns': [
                    r'(?i)(\bhost\s+header\b.*\binjection\b|\bhost\s+header\s+attack\b)',
                    r'(?i)(Host\s*:\s*[^:]+:\d+|Host\s*:\s*[^:]+\.\w+.*\.\w+)',
                    r'(?i)(X-Forwarded-Host\s*:|X-Original-Host\s*:|X-Host\s*:)',
                    r'(?i)(\bhost\s*=\s*http|\bhost\s*=\s*https)',
                    r'(?i)(\bcache\s+poisoning\b.*\bhost\b|\bweb\s+cache\s+poisoning\b)',
                    r'(?i)(\bpassword\s+reset\b.*\bhost\b|\bemail\s+verification\b.*\bhost\b)'
                ],
                'keywords': ['host', 'header', 'injection', 'cache', 'poisoning', 'forwarded'],
                'threshold': 2,
                'severity': 'Low',
                'context_rules': {
                    'path_sensitive': False,
                    'param_sensitive': False,
                    'header_sensitive': True
                }
            },
            'Protocol Downgrade': {
                'patterns': [
                    r'(?i)(\bprotocol\s+downgrade\b|\bssl\s+downgrade\b|\btls\s+downgrade\b)',
                    r'(?i)(\bSSLv2\b|\bSSLv3\b|\bTLS\s+1\.0\b|\bTLS\s+1\.1\b)',
                    r'(?i)(\bno\s+ssl\b|\bno\s+tls\b|\bno\s+encryption\b)',
                    r'(?i)(\bclear\s+text\b|\bhttp\b.*\binstead\b.*\bhttps\b)'
                ],
                'keywords': ['protocol', 'downgrade', 'ssl', 'tls', 'encryption', 'security'],
                'threshold': 1,
                'severity': 'Low',
                'context_rules': {
                    'path_sensitive': False,
                    'param_sensitive': False,
                    'header_sensitive': True
                }
            },
            'Authentication Bypass': {
                'patterns': [
                    r'(?i)(\bauth\s+bypass\b|\bauthentication\s+bypass\b)',
                    r'(?i)(\bbypass\s+auth\b|\bbypass\s+login\b|\bbypass\s+security\b)',
                    r'(?i)(\badmin\b.*\btrue\b|\bis_admin\s*=\s*true\b)',
                    r'(?i)(\blogin\s+as\b|\blogin\s+with\b|\bimpersonate\b)',
                    r'(?i)(\bsession\s+hijack\b|\bsession\s+takeover\b)',
                    r'(?i)(\bprivilege\s+escalation\b|\bescalate\s+privilege\b)'
                ],
                'keywords': ['auth', 'bypass', 'authentication', 'privilege', 'escalation', 'hijack'],
                'threshold': 1,
                'severity': 'Critical',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': True
                }
            },
            'API Abuse': {
                'patterns': [
                    r'(?i)(\bapi\s+abuse\b|\bapi\s+abuse\b)',
                    r'(?i)(\brate\s+limit\b|\bthrottling\b)',
                    r'(?i)(\bbulk\s+request\b|\bmass\s+request\b)',
                    r'(?i)(\bapi\s+flood\b|\bendpoint\s+flood\b)',
                    r'(?i)(\bbrute\s+force\b.*\bapi\b|\bcredential\s+stuffing\b.*\bapi\b)'
                ],
                'keywords': ['api', 'abuse', 'rate', 'limit', 'flood', 'bulk'],
                'threshold': 1,
                'severity': 'Medium',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'Web Scraping': {
                'patterns': [
                    r'(?i)(\bscraper\b|\bcrawler\b|\bspider\b|\bbot\b)',
                    r'(?i)(\bscrape\b|\bcrawl\b|\bharvest\b)',
                    r'(?i)(\bdownload\s+all\b|\bmass\s+download\b)',
                    r'(?i)(\bpage\s*=\s*\d+.*&\bpage\s*=\s*\d+)',
                    r'(?i)(\buser-agent\b.*\bscraper|\buser-agent\b.*\bcrawler)'
                ],
                'keywords': ['scraping', 'scraper', 'crawler', 'spider', 'bot', 'harvest'],
                'threshold': 2,
                'severity': 'Low',
                'context_rules': {
                    'path_sensitive': False,
                    'param_sensitive': False,
                    'header_sensitive': True
                }
            },
            'Data Exfiltration': {
                'patterns': [
                    r'(?i)(\bdata\s+exfiltration\b|\bexfiltration\b)',
                    r'(?i)(\bdownload\s+large\b|\bexport\s+all\b)',
                    r'(?i)(\bdump\b|\bbackup\b|\barchive\b)',
                    r'(?i)(\bcompress\b|\bzip\b|\btar\b)',
                    r'(?i)(\bexfil\b|\bleak\b|\bsteal\b)'
                ],
                'keywords': ['exfiltration', 'exfil', 'leak', 'steal', 'dump', 'backup'],
                'threshold': 1,
                'severity': 'High',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            },
            'Malware Infection': {
                'patterns': [
                    r'(?i)(\bmalware\b|\bvirus\b|\btrojan\b|\bworm\b|\bspyware\b)',
                    r'(?i)(\bpayload\b|\bbackdoor\b|\brootkit\b|\bkeylogger\b)',
                    r'(?i)(\bmalicious\b.*\bfile\b|\bmalicious\b.*\bcode\b|\bmalicious\b.*\bscript\b)',
                    r'(?i)(\bexe\b|\b.msi\b|\b.bat\b|\b.sh\b|\b.php\b.*\bshell\b)',
                    r'(?i)(\bwebshell\b|\bphp\b.*\bshell\b|\basp\b.*\bshell\b|\baspx\b.*\bshell\b)',
                    r'(?i)(\bpayload\b.*\bdelivery\b|\bexploit\b.*\bkit\b|\bcommand\b.*\band\b.*\bcontrol\b)',
                    r'(?i)(\bC2\b|\bcommand\b.*\bcontrol\b|\bbotnet\b|\b僵尸网络\b)'
                ],
                'keywords': ['malware', 'virus', 'trojan', 'worm', 'backdoor', 'webshell', 'payload'],
                'threshold': 2,
                'severity': 'Critical',
                'context_rules': {
                    'path_sensitive': True,
                    'param_sensitive': True,
                    'header_sensitive': False
                }
            }
        }
        return patterns
    
    def _build_threat_intel(self) -> Dict[str, Any]:
        """构建威胁情报库"""
        return {
            'malicious_ips': set(),
            'malicious_user_agents': set(),
            'suspicious_paths': set(),
            'attack_campaigns': {}
        }
    
    def extract_multidimensional_features(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """提取多维度特征"""
        features = {}
        
        # 基本特征
        path = str(log_entry.get('path', ''))
        try:
            path = unquote(path)
        except:
            pass
        features['path'] = path
        features['method'] = str(log_entry.get('method', 'GET'))
        features['status'] = int(log_entry.get('status', 0))
        features['size'] = int(log_entry.get('size', 0))
        features['ip'] = str(log_entry.get('ip', ''))
        features['user_agent'] = str(log_entry.get('user_agent', ''))
        features['referer'] = str(log_entry.get('referer', ''))
        
        # URL特征
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/')
        features['has_query'] = '?' in path
        features['has_fragment'] = '#' in path
        features['has_special_chars'] = any(char in path for char in ['<', '>', '\'', '"', ';', '|', '&', '`'])
        features['has_sql_chars'] = any(char in path.lower() for char in ['select', 'from', 'where', 'union', 'drop', 'insert', 'update', 'delete'])
        features['has_xss_chars'] = any(char in path.lower() for char in ['script', 'javascript:', 'onerror', 'onload'])
        
        # 查询参数特征
        if '?' in path:
            query_string = path.split('?')[1]
            features['query_params_count'] = len(parse_qs(query_string))
            features['query_length'] = len(query_string)
            features['has_multiple_params'] = features['query_params_count'] > 3
        else:
            features['query_params_count'] = 0
            features['query_length'] = 0
            features['has_multiple_params'] = False
        
        # 用户代理特征
        ua = features['user_agent'].lower()
        features['ua_length'] = len(features['user_agent'])
        features['is_bot'] = any(bot in ua for bot in ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'httpie'])
        features['is_mobile'] = any(mobile in ua for mobile in ['mobile', 'android', 'iphone', 'ipad'])
        features['is_browser'] = any(browser in ua for browser in ['chrome', 'firefox', 'safari', 'edge', 'opera'])
        features['is_postman'] = 'postman' in ua
        features['is_api_client'] = any(client in ua for client in ['python-requests', 'axios', 'fetch', 'httpclient'])
        features['ua_entropy'] = self._calculate_entropy(features['user_agent'])
        
        # Referer特征
        features['has_referer'] = bool(features['referer']) and features['referer'] != '-'
        if features['has_referer']:
            try:
                referer_domain = urlparse(features['referer']).netloc
                features['referer_external'] = referer_domain not in path
                features['referer_length'] = len(features['referer'])
            except:
                features['referer_external'] = False
                features['referer_length'] = 0
        else:
            features['referer_external'] = False
            features['referer_length'] = 0
        
        # IP特征
        ip = features['ip']
        features['ip_version'] = 6 if ':' in ip else 4
        features['is_private'] = self._is_private_ip(ip)
        features['is_localhost'] = ip in ['127.0.0.1', 'localhost', '::1']
        features['ip_entropy'] = self._calculate_entropy(ip)
        
        # 状态码特征
        status = features['status']
        features['is_error'] = status >= 400
        features['is_client_error'] = 400 <= status < 500
        features['is_server_error'] = status >= 500
        features['is_404'] = status == 404
        features['is_403'] = status == 403
        features['is_401'] = status == 401
        
        # 内容特征
        features['response_size'] = features['size']
        features['large_response'] = features['size'] > 10000
        features['empty_response'] = features['size'] == 0
        features['small_response'] = 0 < features['size'] < 100
        features['medium_response'] = 100 <= features['size'] < 10000
        
        # 路径特征增强
        features['path_has_executable'] = any(ext in path.lower() for ext in ['.php', '.asp', '.aspx', '.jsp', '.exe', '.bat', '.sh', '.py'])
        features['path_has_admin'] = any(admin in path.lower() for admin in ['admin', 'login', 'auth', 'secure', 'manager', 'control'])
        features['path_has_api'] = any(api in path.lower() for api in ['api', 'rest', 'graphql', 'rpc'])
        features['path_has_upload'] = any(upload in path.lower() for upload in ['upload', 'file', 'attach'])
        features['path_has_backup'] = any(backup in path.lower() for backup in ['backup', 'dump', 'archive', 'zip', 'tar', 'backup'])
        features['path_has_config'] = any(config in path.lower() for config in ['config', 'setting', 'env', 'environment'])
        
        # 查询参数特征增强
        if '?' in path:
            query_string = path.split('?')[1]
            features['query_has_sql'] = any(sql in query_string.lower() for sql in ['select', 'from', 'where', 'union', 'drop', 'insert', 'update', 'delete'])
            features['query_has_xss'] = any(xss in query_string.lower() for xss in ['script', 'javascript:', 'onerror', 'onload'])
            features['query_has_command'] = any(cmd in query_string.lower() for cmd in ['exec', 'system', 'shell', 'command', 'eval'])
            features['query_has_path'] = any(path in query_string.lower() for path in ['../', '..\\', '..%2f', '..%5c'])
            features['query_param_count'] = len(parse_qs(query_string))
        else:
            features['query_has_sql'] = False
            features['query_has_xss'] = False
            features['query_has_command'] = False
            features['query_has_path'] = False
            features['query_param_count'] = 0
        
        raw_log = str(log_entry.get('raw_log', ''))
        post_data = str(log_entry.get('post_data', ''))
        ua = features['user_agent']
        ref = features['referer']
        content = f"{path} {ua} {ref} {raw_log} {post_data}"
        
        # HTTP头部特征
        headers = log_entry.get('headers', {})
        features['has_user_agent'] = bool(features['user_agent']) and features['user_agent'] != '-'
        features['has_referer'] = bool(features['referer']) and features['referer'] != '-'
        features['has_cookie'] = bool(headers.get('Cookie') or headers.get('cookie'))
        features['has_authorization'] = bool(headers.get('Authorization') or headers.get('authorization'))
        features['has_content_type'] = bool(headers.get('Content-Type') or headers.get('content-type'))
        
        # 安全相关特征
        features['has_security_headers'] = bool(
            headers.get('X-XSS-Protection') or 
            headers.get('X-Content-Type-Options') or 
            headers.get('Content-Security-Policy') or
            headers.get('Strict-Transport-Security')
        )
        
        # 攻击特征增强
        features['has_sql_injection'] = any(sql in content.lower() for sql in ['select', 'from', 'where', 'union', 'drop', 'insert', 'update', 'delete', '1=1', '--', '/*'])
        features['has_xss'] = any(xss in content.lower() for xss in ['<script', 'javascript:', 'onerror=', 'onload=', 'alert('])
        features['has_command_injection'] = any(cmd in content.lower() for cmd in [';', '|', '&', '`', 'exec(', 'system(', 'shell_exec('])
        features['has_path_traversal'] = any(path in content.lower() for path in ['../', '..\\', '..%2f', '..%5c', '/etc/passwd'])
        features['has_ssrf'] = any(ssrf in content.lower() for ssrf in ['localhost', '127.0.0.1', 'file://', 'gopher://', 'dict://'])
        
        # 统计特征
        features['content_length'] = len(content)
        features['content_entropy'] = self._calculate_entropy(content)
        features['path_entropy'] = self._calculate_entropy(path)
        features['ua_entropy'] = self._calculate_entropy(features['user_agent'])
        
        # 方法特征
        method = features['method'].upper()
        features['is_get'] = method == 'GET'
        features['is_post'] = method == 'POST'
        features['is_put'] = method == 'PUT'
        features['is_delete'] = method == 'DELETE'
        features['is_patch'] = method == 'PATCH'
        features['is_options'] = method == 'OPTIONS'
        features['is_head'] = method == 'HEAD'
        features['is_trace'] = method == 'TRACE'
        features['is_connect'] = method == 'CONNECT'
        
        # 行为速率（无历史或外部未注入时默认为 0）
        features['request_rate_1min'] = float(log_entry.get('request_rate_1min', 0))
        features['failure_rate'] = float(log_entry.get('failure_rate', 0))
        
        # 综合风险评分
        features['risk_score'] = 0
        if features['is_error']:
            features['risk_score'] += 1
        if features['has_sql_injection']:
            features['risk_score'] += 3
        if features['has_xss']:
            features['risk_score'] += 2
        if features['has_command_injection']:
            features['risk_score'] += 3
        if features['has_path_traversal']:
            features['risk_score'] += 2
        if features['has_ssrf']:
            features['risk_score'] += 3
        if features['path_has_executable']:
            features['risk_score'] += 2
        if features['path_has_admin']:
            features['risk_score'] += 1
        if features['request_rate_1min'] > 50:
            features['risk_score'] += 2
        if features['failure_rate'] > 0.5:
            features['risk_score'] += 2
        
        # 时间特征
        timestamp = log_entry.get('timestamp')
        if timestamp:
            features['hour'] = timestamp.hour
            features['is_business_hours'] = 9 <= timestamp.hour < 18
            features['is_weekend'] = timestamp.weekday() >= 5
            features['is_night'] = timestamp.hour < 6 or timestamp.hour >= 22
        else:
            features['hour'] = 0
            features['is_business_hours'] = False
            features['is_weekend'] = False
            features['is_night'] = False
        
        # 哈希特征
        features['path_hash'] = hashlib.md5(path.encode()).hexdigest()[:8]
        features['ua_hash'] = hashlib.md5(features['user_agent'].encode()).hexdigest()[:8]
        
        # 新增特征
        # 路径规范化特征
        features['path_normalized_length'] = len(path)
        features['path_has_encoded_chars'] = '%' in str(log_entry.get('path', ''))
        
        # 频率特征（基于历史数据）
        ip = features['ip']
        if ip in self.history:
            recent_attempts = len([entry for entry in self.history[ip] if (datetime.now() - entry['timestamp']).total_seconds() < 3600])
            features['recent_attempts'] = recent_attempts
            features['is_rapid_fire'] = recent_attempts > 10
        else:
            features['recent_attempts'] = 0
            features['is_rapid_fire'] = False
        
        # 异常检测特征
        features['is_suspicious_method'] = method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        features['is_suspicious_path'] = any(suspicious in path.lower() for suspicious in ['../', '..\\', 'admin', 'login', 'backup', 'config'])
        features['is_suspicious_user_agent'] = 'unknown' in ua or 'bot' in ua
        
        # 组合特征
        features['high_risk_combination'] = features['has_sql_injection'] and features['is_post']
        features['medium_risk_combination'] = features['has_xss'] and features['is_get']
        features['low_risk_combination'] = features['is_bot'] and features['is_404']
        
        # 新增风险评分因素
        if features['is_suspicious_method']:
            features['risk_score'] += 2
        if features['is_rapid_fire']:
            features['risk_score'] += 3
        if features['high_risk_combination']:
            features['risk_score'] += 2
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """计算字符串熵值"""
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        total_chars = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_private_ip(self, ip: str) -> bool:
        """判断是否为私有IP"""
        if ':' in ip:
            return False
        
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            if first_octet == 10:
                return True
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            if first_octet == 192 and second_octet == 168:
                return True
            if first_octet == 127:
                return True
            
            return False
        except:
            return False
    
    def extract_attack_signatures(self, log_entry: Dict[str, Any]) -> Dict[str, float]:
        """提取攻击特征签名，返回各攻击类型的得分"""
        scores = {}
        features = self.extract_multidimensional_features(log_entry)
        
        # 组合所有可能包含攻击特征的内容
        path = features['path']
        user_agent = features['user_agent']
        referer = features['referer']
        raw_log = str(log_entry.get('raw_log', ''))
        post_data = str(log_entry.get('post_data', {}))
        
        content = f"{path} {user_agent} {referer} {raw_log} {post_data}"
        
        for attack_type, config in self.attack_patterns.items():
            score = 0.0
            
            # 模式匹配得分
            pattern_matches = 0
            for pattern in config['patterns']:
                matches = re.findall(pattern, content)
                if matches:
                    pattern_matches += len(matches)
                    score += len(matches) * 2.5
            
            # 关键词匹配得分
            keyword_matches = 0
            for keyword in config['keywords']:
                if keyword.lower() in content.lower():
                    keyword_matches += 1
                    score += 1.5
            
            # 上下文敏感度加权
            context_rules = config.get('context_rules', {})
            if context_rules.get('path_sensitive') and path:
                path_score = self._calculate_context_score(path, config['patterns'])
                score += path_score * 2.0
            
            if context_rules.get('param_sensitive') and '?' in path:
                query_string = path.split('?')[1]
                param_score = self._calculate_context_score(query_string, config['patterns'])
                score += param_score * 2.5
            
            if context_rules.get('header_sensitive'):
                header_content = f"{user_agent} {referer}"
                header_score = self._calculate_context_score(header_content, config['patterns'])
                score += header_score * 2.0
            
            # 应用阈值
            threshold = config.get('threshold', 1)
            if pattern_matches + keyword_matches < threshold:
                score *= 0.3
            
            scores[attack_type] = score
        
        return scores
    
    def _calculate_context_score(self, content: str, patterns: List[str]) -> float:
        """计算上下文得分"""
        score = 0.0
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if matches:
                score += len(matches)
        return score
    
    def analyze_behavior_patterns(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """分析行为模式"""
        ip = log_entry.get('ip', '')
        features = self.extract_multidimensional_features(log_entry)
        
        # 更新历史记录
        ip_history = self.history[ip]
        ip_history.append({
            'timestamp': datetime.now(),
            'path': features['path'],
            'method': features['method'],
            'status': features['status'],
            'ua_hash': features['ua_hash'],
            'size': features['size']
        })
        
        # 限制历史记录大小
        if len(ip_history) > self.max_history_size:
            ip_history = ip_history[-self.max_history_size:]
        
        self.history[ip] = ip_history
        
        # 行为分析
        analysis = {
            'is_anomalous': False,
            'reasons': [],
            'request_count': len(ip_history),
            'behavior_score': 0.0,
            'attack_probability': 0.0,
            'predicted_attack_type': 'Normal',
            'details': {
                'request_rate': 0.0,
                'failure_rate': 0.0,
                'path_diversity': 0.0,
                'method_diversity': 0.0,
                'time_pattern': 'normal'
            }
        }
        
        if len(ip_history) < 5:
            return analysis
        
        # 计算时间窗口内的请求频率
        now = datetime.now()
        recent_1min = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 60]
        recent_5min = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 300]
        recent_1hour = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 3600]
        recent_6hours = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 21600]
        
        # 计算请求率
        request_rate_1min = len(recent_1min) / 1.0  # 每分钟请求数
        request_rate_5min = len(recent_5min) / 5.0  # 每分钟请求数
        request_rate_1hour = len(recent_1hour) / 60.0  # 每分钟请求数
        
        analysis['details']['request_rate'] = request_rate_1min
        
        # 高频请求检测
        if request_rate_1min > 100:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'高频请求 (1分钟内{len(recent_1min)}次)')
            analysis['behavior_score'] += 3.0
        elif request_rate_5min > 50:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'高频请求 (5分钟内{len(recent_5min)}次)')
            analysis['behavior_score'] += 2.5
        elif request_rate_1hour > 10:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'高频请求 (1小时内{len(recent_1hour)}次)')
            analysis['behavior_score'] += 2.0
        
        # 失败率检测
        failed_requests = [r for r in recent_1hour if r['status'] in [400, 401, 403, 404, 500]]
        if len(recent_1hour) > 10:
            failure_rate = len(failed_requests) / len(recent_1hour)
            analysis['details']['failure_rate'] = failure_rate
            
            if failure_rate > 0.8:
                analysis['is_anomalous'] = True
                analysis['reasons'].append(f'高失败率 ({failure_rate:.1%})')
                analysis['behavior_score'] += 2.5
            elif failure_rate > 0.5:
                analysis['is_anomalous'] = True
                analysis['reasons'].append(f'较高失败率 ({failure_rate:.1%})')
                analysis['behavior_score'] += 1.5
        
        # 路径多样性检测
        unique_paths = set(r['path'] for r in recent_1hour)
        path_diversity = len(unique_paths) / len(recent_1hour) if recent_1hour else 0
        analysis['details']['path_diversity'] = path_diversity
        
        if len(recent_1hour) > 20 and len(unique_paths) == 1:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'路径单一 (仅访问{len(unique_paths)}个路径)')
            analysis['behavior_score'] += 2.0
        elif len(recent_1hour) > 50 and path_diversity < 0.1:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'路径多样性低 (多样性: {path_diversity:.2f})')
            analysis['behavior_score'] += 1.5
        
        # 方法多样性检测
        unique_methods = set(r['method'] for r in recent_1hour)
        method_diversity = len(unique_methods) / len(recent_1hour) if recent_1hour else 0
        analysis['details']['method_diversity'] = method_diversity
        
        if len(recent_1hour) > 10 and len(unique_methods) == 1:
            if 'GET' in unique_methods:
                analysis['is_anomalous'] = True
                analysis['reasons'].append(f'方法单一 (仅使用GET)')
                analysis['behavior_score'] += 1.5
            elif 'POST' in unique_methods:
                analysis['is_anomalous'] = True
                analysis['reasons'].append(f'方法单一 (仅使用POST)')
                analysis['behavior_score'] += 1.8
        
        # 时间模式分析
        if features['is_night'] and request_rate_1min > 50:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'夜间高频请求')
            analysis['behavior_score'] += 1.5
            analysis['details']['time_pattern'] = 'night_activity'
        
        if features['is_weekend'] and request_rate_1min > 30:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'周末高频请求')
            analysis['behavior_score'] += 1.2
            analysis['details']['time_pattern'] = 'weekend_activity'
        
        # 用户代理变化检测
        recent_ua_hashes = [r['ua_hash'] for r in recent_1hour]
        unique_ua_count = len(set(recent_ua_hashes))
        if len(recent_1hour) > 20 and unique_ua_count > 5:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'用户代理频繁变化 ({unique_ua_count}个不同UA)')
            analysis['behavior_score'] += 1.8
        
        # 响应大小异常检测
        sizes = [r['size'] for r in recent_1hour if r['size'] > 0]
        if sizes:
            avg_size = sum(sizes) / len(sizes)
            size_std = np.std(sizes) if len(sizes) > 1 else 0
            if size_std > avg_size * 2:
                analysis['is_anomalous'] = True
                analysis['reasons'].append(f'响应大小波动异常')
                analysis['behavior_score'] += 1.5
        
        # 计算攻击概率
        if analysis['behavior_score'] > 0:
            analysis['attack_probability'] = min(1.0, analysis['behavior_score'] / 10.0)
            
            # 根据行为特征预测攻击类型
            if request_rate_1min > 50:
                analysis['predicted_attack_type'] = 'DoS/DDoS'
            elif analysis['details']['failure_rate'] > 0.8:
                analysis['predicted_attack_type'] = 'Brute Force'
            elif path_diversity < 0.05 and len(recent_1hour) > 30:
                analysis['predicted_attack_type'] = 'Web Scraping'
            elif unique_ua_count > 10 and len(recent_1hour) > 50:
                analysis['predicted_attack_type'] = 'Bot Activity'
            elif features['is_night'] and request_rate_1min > 20:
                analysis['predicted_attack_type'] = 'Suspicious Activity'
            elif features['path_has_admin'] and analysis['details']['failure_rate'] > 0.5:
                analysis['predicted_attack_type'] = 'Brute Force'
            elif features['path_has_upload'] and features['is_post']:
                analysis['predicted_attack_type'] = 'File Upload'
            elif features['path_has_executable'] and features['is_post']:
                analysis['predicted_attack_type'] = 'Malware Infection'
            elif features['has_command_injection']:
                analysis['predicted_attack_type'] = 'Command Injection'
            elif features['has_sql_injection']:
                analysis['predicted_attack_type'] = 'SQL Injection'
            elif features['has_xss']:
                analysis['predicted_attack_type'] = 'XSS'
            elif features['has_path_traversal']:
                analysis['predicted_attack_type'] = 'Path Traversal'
            elif features['has_ssrf']:
                analysis['predicted_attack_type'] = 'SSRF'
        
        # 增强的行为模式分析
        # 1. 连续失败模式
        consecutive_failures = 0
        for i in range(len(ip_history) - 1, max(-1, len(ip_history) - 10), -1):
            if ip_history[i]['status'] >= 400:
                consecutive_failures += 1
            else:
                break
        analysis['details']['consecutive_failures'] = consecutive_failures
        if consecutive_failures >= 5:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'连续失败 {consecutive_failures} 次')
            analysis['behavior_score'] += 2.0
        
        # 2. 快速路径变化模式
        recent_paths = [r['path'] for r in recent_1min]
        unique_recent_paths = set(recent_paths)
        if len(recent_paths) > 10 and len(unique_recent_paths) == len(recent_paths):
            analysis['is_anomalous'] = True
            analysis['reasons'].append('快速路径变化')
            analysis['behavior_score'] += 1.5
        
        # 3. 敏感路径访问模式
        sensitive_paths = ['/admin', '/login', '/auth', '/secure', '/config', '/settings']
        sensitive_access_count = sum(1 for r in recent_5min if any(sp in r['path'] for sp in sensitive_paths))
        if sensitive_access_count > 10:
            analysis['is_anomalous'] = True
            analysis['reasons'].append(f'频繁访问敏感路径 ({sensitive_access_count}次)')
            analysis['behavior_score'] += 2.0
        
        # 4. 异常时间模式
        if features['is_night'] and len(recent_1min) > 20:
            analysis['is_anomalous'] = True
            analysis['reasons'].append('夜间异常活动')
            analysis['behavior_score'] += 1.5
        
        # 5. 异常方法组合
        if len(unique_methods) > 3 and len(recent_1min) > 15:
            analysis['is_anomalous'] = True
            analysis['reasons'].append('异常HTTP方法组合')
            analysis['behavior_score'] += 1.2
        
        # 6. 异常响应大小模式
        if features['large_response'] and features['is_post']:
            analysis['is_anomalous'] = True
            analysis['reasons'].append('异常大响应')
            analysis['behavior_score'] += 1.5
        
        # 7. 异常内容类型
        content_type = headers.get('Content-Type') or headers.get('content-type')
        if content_type and 'application/x-www-form-urlencoded' not in content_type and 'multipart/form-data' not in content_type and features['is_post']:
            analysis['is_anomalous'] = True
            analysis['reasons'].append('异常内容类型')
            analysis['behavior_score'] += 1.0
        
        return analysis
    
    def _generate_cache_key(self, log_entry: Dict[str, Any]) -> str:
        """生成缓存键"""
        ip = log_entry.get('ip', '')
        path = log_entry.get('path', '')
        method = log_entry.get('method', '')
        user_agent = log_entry.get('user_agent', '')
        return hashlib.md5(f"{ip}:{path}:{method}:{user_agent}".encode()).hexdigest()
    
    def _update_cache(self, key: str, result: Dict[str, Any]):
        """更新缓存"""
        if len(self.cache) >= self.cache_size:
            # LRU缓存淘汰
            oldest_key = self.cache_keys.pop(0)
            del self.cache[oldest_key]
        self.cache[key] = result
        self.cache_keys.append(key)
    
    def _get_from_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """从缓存获取结果"""
        if key in self.cache:
            # 移动到缓存末尾（最近使用）
            self.cache_keys.remove(key)
            self.cache_keys.append(key)
            self.statistics['cache_hits'] += 1
            return self.cache[key]
        self.statistics['cache_misses'] += 1
        return None
    
    def classify(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """分类日志条目，返回攻击类型和详细分析"""
        start_time = datetime.now()
        
        # 生成缓存键
        cache_key = self._generate_cache_key(log_entry)
        
        # 检查缓存
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            # 计算处理时间
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.statistics['processing_times'].append(processing_time)
            if len(self.statistics['processing_times']) > 1000:
                self.statistics['processing_times'] = self.statistics['processing_times'][-1000:]
            self.statistics['average_processing_time'] = sum(self.statistics['processing_times']) / len(self.statistics['processing_times'])
            return cached_result
        
        # 提取攻击特征签名
        scores = self.extract_attack_signatures(log_entry)
        
        # 分析行为模式
        behavior_analysis = self.analyze_behavior_patterns(log_entry)
        
        # 找出得分最高的攻击类型
        if not scores:
            if behavior_analysis['is_anomalous']:
                result = {
                    'attack_type': behavior_analysis['predicted_attack_type'],
                    'confidence': round(behavior_analysis['attack_probability'], 2),
                    'severity': 'Medium',
                    'detection_methods': ['Behavior Analysis'],
                    'details': {
                        'behavior_analysis': behavior_analysis,
                        'reason': behavior_analysis['reasons'][0] if behavior_analysis['reasons'] else 'Anomalous behavior detected'
                    }
                }
            else:
                result = {
                    'attack_type': 'Normal',
                    'confidence': 0.0,
                    'severity': 'Low',
                    'detection_methods': [],
                    'details': {}
                }
        else:
            # 找出最高得分
            max_score = max(scores.values())
            max_attack_type = max(scores, key=scores.get)
            
            # 计算置信度
            total_score = sum(scores.values())
            if total_score > 0:
                confidence = min(1.0, max_score / total_score)
            else:
                confidence = 0.0
            
            # 结合行为分析调整置信度
            if behavior_analysis['is_anomalous']:
                confidence = min(1.0, confidence + behavior_analysis['attack_probability'] * 0.3)
            
            # 如果最高得分低于阈值，判定为正常
            if max_score < 2.0 and not behavior_analysis['is_anomalous']:
                result = {
                    'attack_type': 'Normal',
                    'confidence': round(confidence, 2),
                    'severity': 'Low',
                    'detection_methods': [],
                    'details': {
                        'behavior_analysis': behavior_analysis
                    }
                }
            else:
                # 获取攻击类型详细信息
                attack_config = self.attack_patterns.get(max_attack_type, {})
                severity = attack_config.get('severity', 'Low')
                
                # 构建检测方法
                detection_methods = []
                for attack_type, config in self.attack_patterns.items():
                    if scores[attack_type] > 0:
                        detection_methods.append({
                            'type': attack_type,
                            'score': round(scores[attack_type], 2),
                            'matched_patterns': len([p for p in config['patterns'] if re.search(p, str(log_entry))])
                        })
                
                # 如果有行为分析异常，添加行为分析方法
                if behavior_analysis['is_anomalous']:
                    detection_methods.append({
                        'type': 'Behavior Analysis',
                        'score': round(behavior_analysis['behavior_score'], 2),
                        'matched_patterns': len(behavior_analysis['reasons'])
                    })
                
                # 更新统计信息
                self.statistics['total_classifications'] += 1
                self.statistics['attack_counts'][max_attack_type] += 1
                
                result = {
                    'attack_type': max_attack_type,
                    'confidence': round(confidence, 2),
                    'severity': severity,
                    'detection_methods': detection_methods,
                    'details': {
                        'all_scores': {k: round(v, 2) for k, v in scores.items()},
                        'max_score': round(max_score, 2),
                        'threshold': attack_config.get('threshold', 1),
                        'behavior_analysis': behavior_analysis
                    }
                }
        
        # 更新缓存
        self._update_cache(cache_key, result)
        
        # 计算处理时间
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        self.statistics['processing_times'].append(processing_time)
        if len(self.statistics['processing_times']) > 1000:
            self.statistics['processing_times'] = self.statistics['processing_times'][-1000:]
        self.statistics['average_processing_time'] = sum(self.statistics['processing_times']) / len(self.statistics['processing_times'])
        
        return result
    
    def predict_future_attacks(self, ip: str) -> Dict[str, Any]:
        """预测未来攻击"""
        ip_history = self.history.get(ip, [])
        
        # 降低数据门槛，从10条改为5条
        if len(ip_history) < 5:
            return {
                'ip': ip,
                'prediction': 'Insufficient data',
                'confidence': 0.0,
                'risk_level': 'Low',
                'metrics': {
                    'request_rate_24h': 0,
                    'failure_rate': 0,
                    'path_diversity': 0,
                    'sample_size': len(ip_history)
                },
                'recommendations': [
                    f'该IP仅有 {len(ip_history)} 条历史记录，需要更多数据进行准确预测。',
                    '建议持续监控该IP的活动情况。',
                    '如果这是新IP，请等待更多数据积累。'
                ]
            }
        
        # 分析历史行为，使用更灵活的时间窗口
        now = datetime.now()
        
        # 检查多个时间窗口的活动
        recent_24h = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 86400]
        recent_7d = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 604800]
        recent_30d = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 2592000]
        
        # 优先使用最近24小时数据，如果没有则使用7天数据
        analysis_data = recent_24h if recent_24h else (recent_7d if recent_7d else recent_30d)
        
        if not analysis_data:
            return {
                'ip': ip,
                'prediction': 'No recent activity',
                'confidence': 0.0,
                'risk_level': 'Low',
                'metrics': {
                    'request_rate_24h': 0,
                    'failure_rate': 0,
                    'path_diversity': 0,
                    'sample_size': 0
                },
                'recommendations': [
                    '该IP最近没有活动记录。',
                    '建议检查数据源是否正常工作。',
                    '如果需要实时监控，请确保数据源持续接收日志。'
                ]
            }
        
        # 根据使用的时间窗口调整计算
        time_window_hours = 24 if recent_24h else (168 if recent_7d else 720)
        request_rate = len(analysis_data) / time_window_hours
        error_rate = len([r for r in analysis_data if r['status'] >= 400]) / len(analysis_data)
        
        # 计算路径多样性
        unique_paths = set(r['path'] for r in analysis_data)
        path_diversity = len(unique_paths) / len(analysis_data) if analysis_data else 0
        
        # 预测风险等级
        risk_level = 'Low'
        if request_rate > 100 or error_rate > 0.5:
            risk_level = 'High'
        elif request_rate > 50 or error_rate > 0.3:
            risk_level = 'Medium'
        
        # 计算置信度（基于数据量和时间新鲜度）
        time_freshness = 1.0 if recent_24h else (0.7 if recent_7d else 0.5)
        data_volume_factor = min(1.0, len(analysis_data) / 50.0)
        confidence = min(1.0, (request_rate / 200.0) * time_freshness * data_volume_factor)
        
        # 根据时间窗口添加说明
        time_window_desc = '24小时' if recent_24h else ('7天' if recent_7d else '30天')
        
        return {
            'ip': ip,
            'prediction': 'Potential attack' if risk_level != 'Low' else 'Normal behavior',
            'confidence': round(confidence, 2),
            'risk_level': risk_level,
            'metrics': {
                'request_rate_24h': round(request_rate, 2),
                'failure_rate': round(error_rate, 2),
                'path_diversity': round(path_diversity, 2),
                'sample_size': len(analysis_data),
                'time_window': time_window_desc
            },
            'recommendations': [
                f'基于最近{time_window_desc}的 {len(analysis_data)} 条记录进行分析。',
                f'请求率: {request_rate:.2f} 次/小时，错误率: {error_rate:.2%}' if error_rate > 0 else '请求率正常，未发现异常错误。',
                '建议持续监控该IP的活动情况。'
            ] if risk_level == 'Low' else [
                f'检测到异常活动！基于最近{time_window_desc}的 {len(analysis_data)} 条记录。',
                f'请求率: {request_rate:.2f} 次/小时，错误率: {error_rate:.2%}',
                '建议立即采取防护措施，如封禁该IP或增加监控频率。'
            ]
        }
    
    def analyze_behavior_patterns_detailed(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """详细的行为模式分析"""
        if not AI_AVAILABLE:
            return {
                'error': 'AI models not available'
            }
        
        ip = data.get('ip', '')
        ip_history = self.history.get(ip, [])
        
        if len(ip_history) < 10:
            return {
                'error': 'Insufficient data for analysis'
            }
        
        # 计算各种行为指标
        now = datetime.now()
        recent_1min = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 60]
        recent_5min = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 300]
        recent_1hour = [r for r in ip_history if (now - r['timestamp']).total_seconds() < 3600]
        
        # 计算请求率
        request_rate = round(len(recent_1hour) / 60.0, 2)
        
        # 计算失败率
        failed_requests = [r for r in recent_1hour if r['status'] >= 400]
        failure_rate = round(len(failed_requests) / len(recent_1hour), 2) if recent_1hour else 0.0
        
        # 计算路径多样性
        unique_paths = set(r['path'] for r in recent_1hour)
        path_diversity = round(len(unique_paths) / len(recent_1hour), 2) if recent_1hour else 0.0
        
        # 计算方法多样性
        unique_methods = set(r['method'] for r in recent_1hour)
        method_diversity = round(len(unique_methods) / len(recent_1hour), 2) if recent_1hour else 0.0
        
        return {
            'ip': ip,
            'request_rate': request_rate,
            'failure_rate': failure_rate,
            'path_diversity': path_diversity,
            'sample_size': len(recent_1hour)
        }
    
    def get_threat_intel_summary(self) -> Dict[str, Any]:
        """获取威胁情报摘要"""
        total_attacks = sum(self.statistics['attack_counts'].values())
        total_classifications = self.statistics['total_classifications']
        
        # 计算攻击类型分布
        attack_distribution = {}
        for attack_type, count in self.statistics['attack_counts'].items():
            if attack_type != 'Normal':
                attack_distribution[attack_type] = {
                    'count': count,
                    'percentage': round((count / total_attacks * 100) if total_attacks > 0 else 0, 2)
                }
        
        # 计算严重程度分布
        severity_distribution = Counter()
        for attack_type, count in self.statistics['attack_counts'].items():
            for severity, attack_types in self.severity_levels.items():
                if attack_type in attack_types:
                    severity_distribution[severity] += count
                    break
        
        return {
            'total_classifications': total_classifications,
            'total_attacks': total_attacks,
            'attack_distribution': attack_distribution,
            'severity_distribution': dict(severity_distribution),
            'top_attacks': dict(sorted(self.statistics['attack_counts'].items(), 
                                     key=lambda x: x[1], reverse=True)[:5]),
            'detection_rate': round((total_attacks / total_classifications * 100) if total_classifications > 0 else 0, 2)
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        return {
            'model_info': self.model_info,
            'statistics': {
                'total_classifications': self.statistics['total_classifications'],
                'attack_counts': dict(self.statistics['attack_counts']),
                'cache_hits': self.statistics['cache_hits'],
                'cache_misses': self.statistics['cache_misses'],
                'cache_hit_rate': round((self.statistics['cache_hits'] / (self.statistics['cache_hits'] + self.statistics['cache_misses']) * 100) if (self.statistics['cache_hits'] + self.statistics['cache_misses']) > 0 else 0, 2),
                'average_processing_time': round(self.statistics['average_processing_time'], 2)
            },
            'config': {
                'cache_size': self.cache_size,
                'max_history_size': self.max_history_size,
                'ml_params': self.ml_params
            }
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """获取性能指标"""
        return {
            'cache': {
                'hits': self.statistics['cache_hits'],
                'misses': self.statistics['cache_misses'],
                'hit_rate': round((self.statistics['cache_hits'] / (self.statistics['cache_hits'] + self.statistics['cache_misses']) * 100) if (self.statistics['cache_hits'] + self.statistics['cache_misses']) > 0 else 0, 2)
            },
            'processing': {
                'average_time_ms': round(self.statistics['average_processing_time'], 2),
                'total_classifications': self.statistics['total_classifications'],
                'attacks_detected': sum(self.statistics['attack_counts'].values())
            },
            'model': self.model_info['performance']
        }
    
    def train_model(self, training_data: List[Dict[str, Any]], labels: List[str], test_size: float = 0.2):
        """训练机器学习模型"""
        if len(training_data) < 50:
            print("警告: 训练数据太少（至少需要50个样本）")
            return False
        
        # 提取特征
        features_list = []
        for entry in training_data:
            features = self.extract_multidimensional_features(entry)
            features_list.append([
                # URL特征
                features['path_length'],
                features['path_depth'],
                features['has_query'],
                features['has_special_chars'],
                features['has_sql_chars'],
                features['has_xss_chars'],
                features['query_params_count'],
                features['query_length'],
                features['has_multiple_params'],
                
                # 用户代理特征
                features['ua_length'],
                features['is_bot'],
                features['is_mobile'],
                features['is_browser'],
                features['is_postman'],
                features['is_api_client'],
                features['ua_entropy'],
                
                # Referer特征
                features['has_referer'],
                features['referer_external'],
                features['referer_length'],
                
                # IP特征
                features['ip_version'],
                features['is_private'],
                features['is_localhost'],
                features['ip_entropy'],
                
                # 状态码特征
                features['is_error'],
                features['is_client_error'],
                features['is_server_error'],
                features['is_404'],
                features['is_403'],
                features['is_401'],
                
                # 内容特征
                features['large_response'],
                features['empty_response'],
                features['small_response'],
                
                # 方法特征
                features['is_get'],
                features['is_post'],
                features['is_delete'],
                
                # 时间特征
                features['hour'],
                features['is_business_hours'],
                features['is_weekend'],
                features['is_night']
            ])
        
        # 转换为numpy数组
        X = np.array(features_list)
        y = np.array(labels)
        
        # 划分训练集和测试集
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
        
        # 标准化特征
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # 训练模型
        self.ml_model.fit(X_train_scaled, y_train)
        self.is_trained = True
        
        # 评估模型
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        
        y_pred = self.ml_model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')
        cm = confusion_matrix(y_test, y_pred)
        
        # 更新模型信息
        self.model_info['last_trained'] = datetime.now().isoformat()
        self.model_info['performance'] = {
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'confusion_matrix': cm.tolist()
        }
        
        # 保存模型
        if self.model_path:
            self.save_model(self.model_path)
        
        print(f"攻击分类模型训练完成，使用了 {len(training_data)} 个样本")
        print(f"特征维度: {X.shape[1]}")
        print(f"模型性能:")
        print(f"  准确率: {accuracy:.4f}")
        print(f"  精确率: {precision:.4f}")
        print(f"  召回率: {recall:.4f}")
        print(f"  F1得分: {f1:.4f}")
        return True
    
    def classify_with_ml(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """使用机器学习模型分类"""
        if not self.is_trained:
            return self.classify(log_entry)
        
        # 提取特征
        features = self.extract_multidimensional_features(log_entry)
        feature_vector = np.array([[
            # URL特征
            features['path_length'],
            features['path_depth'],
            features['has_query'],
            features['has_special_chars'],
            features['has_sql_chars'],
            features['has_xss_chars'],
            features['query_params_count'],
            features['query_length'],
            features['has_multiple_params'],
            
            # 用户代理特征
            features['ua_length'],
            features['is_bot'],
            features['is_mobile'],
            features['is_browser'],
            features['is_postman'],
            features['is_api_client'],
            features['ua_entropy'],
            
            # Referer特征
            features['has_referer'],
            features['referer_external'],
            features['referer_length'],
            
            # IP特征
            features['ip_version'],
            features['is_private'],
            features['is_localhost'],
            features['ip_entropy'],
            
            # 状态码特征
            features['is_error'],
            features['is_client_error'],
            features['is_server_error'],
            features['is_404'],
            features['is_403'],
            features['is_401'],
            
            # 内容特征
            features['large_response'],
            features['empty_response'],
            features['small_response'],
            
            # 方法特征
            features['is_get'],
            features['is_post'],
            features['is_delete'],
            
            # 时间特征
            features['hour'],
            features['is_business_hours'],
            features['is_weekend'],
            features['is_night'],
            
            # 新增特征
            features['path_normalized_length'],
            features['path_has_encoded_chars'],
            features['recent_attempts'],
            features['is_rapid_fire'],
            features['is_suspicious_method'],
            features['is_suspicious_path'],
            features['is_suspicious_user_agent'],
            features['high_risk_combination'],
            features['medium_risk_combination'],
            features['low_risk_combination'],
            features['risk_score']
        ]])
        
        # 标准化特征
        feature_scaled = self.scaler.transform(feature_vector)
        
        # 预测
        prediction = self.ml_model.predict(feature_scaled)[0]
        probability = self.ml_model.predict_proba(feature_scaled)[0].max()
        
        # 获取严重程度
        severity = 'Low'
        for sev, attack_types in self.severity_levels.items():
            if prediction in attack_types:
                severity = sev
                break
        
        return {
            'attack_type': prediction,
            'confidence': round(probability, 2),
            'severity': severity,
            'detection_methods': ['Machine Learning'],
            'details': {
                'ml_prediction': True,
                'model_type': 'RandomForest',
                'feature_count': feature_vector.shape[1]
            }
        }
    
    def load_model(self, model_path: str) -> bool:
        """加载模型"""
        try:
            if os.path.exists(model_path):
                model_data = joblib.load(model_path)
                self.ml_model = model_data.get('ml_model', self.ml_model)
                self.scaler = model_data.get('scaler', self.scaler)
                self.is_trained = model_data.get('is_trained', False)
                self.ml_params = model_data.get('ml_params', self.ml_params)
                print(f"攻击分类模型已从 {model_path} 加载")
                return True
        except Exception as e:
            print(f"加载模型失败: {e}")
        return False
    
    def save_model(self, model_path: str) -> bool:
        """保存模型"""
        try:
            model_data = {
                'ml_model': self.ml_model,
                'scaler': self.scaler,
                'is_trained': self.is_trained,
                'ml_params': self.ml_params,
                'statistics': {k: dict(v) for k, v in self.statistics.items()}
            }
            joblib.dump(model_data, model_path)
            print(f"攻击分类模型已保存到 {model_path}")
            return True
        except Exception as e:
            print(f"保存模型失败: {e}")
        return False
