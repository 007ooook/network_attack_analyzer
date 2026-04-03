from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Iterator


@dataclass
class LogEntry:
    ip: str
    timestamp: Optional[datetime]
    method: str
    path: str
    status: int
    size: int
    referer: str
    user_agent: str
    received_at: datetime = field(default_factory=datetime.now)
    source: str = "unknown"
    raw_line: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    analysis: dict[str, Any] = field(default_factory=dict)
    # Payload analysis fields
    query_params: dict[str, str] = field(default_factory=dict)
    post_data: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    # Parsed components
    url_path: str = ""  # Path without query string
    query_string: str = ""  # Raw query string


TIME_FORMAT_APACHE = "%d/%b/%Y:%H:%M:%S %z"
TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y/%m/%d %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    # 增加更多时间格式支持
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S.%f",
    "%d/%b/%Y %H:%M:%S",
    "%b %d %H:%M:%S",  # Syslog格式
    "%b %d %Y %H:%M:%S",  # 扩展Syslog格式
    "%Y%m%d%H%M%S",  # 无分隔符格式
    "%Y-%m-%d",  # 仅日期
    "%H:%M:%S",  # 仅时间
    # 点分隔的日期格式
    "%d.%m.%Y %H:%M:%S",
    "%m.%d.%Y %H:%M:%S",
]


def format_timestamp(ts: Optional[datetime]) -> Optional[str]:
    """Format datetime to ISO format string for JSON serialization."""
    if ts is None:
        return None
    return ts.isoformat()


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse timestamp string to datetime object using multiple formats."""
    if not timestamp_str:
        return None
    
    # 清理时间戳字符串
    timestamp_str = timestamp_str.strip()
    
    # 首先尝试处理Unix时间戳（秒或毫秒）
    try:
        # 尝试作为秒处理
        timestamp = float(timestamp_str)
        # 检查时间戳是否在合理范围内（1970年到2100年）
        if 0 < timestamp < 4102444800:  # 4102444800 是 2100-01-01 00:00:00 的时间戳
            return datetime.fromtimestamp(timestamp)
    except (ValueError, TypeError):
        pass
    
    try:
        # 尝试作为毫秒处理
        timestamp = float(timestamp_str)
        # 检查时间戳是否在合理范围内（1970年到2100年）
        if 0 < timestamp < 4102444800000:  # 毫秒
            return datetime.fromtimestamp(timestamp / 1000)
    except (ValueError, TypeError):
        pass
    
    # 尝试标准时间格式
    for fmt in TIME_FORMATS:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            # 处理缺少年份的情况（如Syslog格式）
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    
    # 尝试ISO格式
    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except ValueError:
        pass
    
    return None


def is_valid_ip(ip: str) -> bool:
    """Validate IP address using ipaddress module."""
    if not ip or (":" not in ip and "." not in ip):
        return False
    # Quick pre-filter for obvious time strings (e.g., 11:38:08)
    # only match if it's EXACTLY 3 pairs of digits (avoid breaking IPv6)
    if re.match(r'^\d{2}:\d{2}:\d{2}$', ip):
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


class LogParser:
    def parse(self, line: str) -> Optional[LogEntry]:
        raise NotImplementedError

    def reset(self) -> None:
        pass


class NginxParser(LogParser):
    # Support both IPv4 and IPv6, more flexible request line and protocol
    LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s]*)(?:\s+(?P<proto>[^"]+))?"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )

    def parse(self, line: str) -> Optional[LogEntry]:
        match = self.LOG_PATTERN.match(line.strip())
        if not match:
            return None
        ts = None
        time_str = match.group("time")
        if time_str:
            try:
                ts = datetime.strptime(time_str, TIME_FORMAT_APACHE)
            except (ValueError, TypeError):
                ts = parse_timestamp(time_str)
        
        size_str = match.group("size")
        size = 0 if size_str == "-" else int(size_str)

        return LogEntry(
            ip=match.group("ip"),
            timestamp=ts,
            method=match.group("method"),
            path=match.group("path"),
            status=int(match.group("status")),
            size=size,
            referer=match.group("referer") or "-",
            user_agent=match.group("ua") or "-",
            source="nginx",
            raw_line=line,
        )


class JsonParser(LogParser):
    def parse(self, line: str) -> Optional[LogEntry]:
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                return None
        except json.JSONDecodeError:
            return None

        # --- Field mapping (adapt based on common formats) ---
        ip = data.get("client_ip") or data.get("ip") or data.get("source_ip")
        if not ip:
            return None

        path = data.get("uri") or data.get("path") or data.get("request_uri")
        method = data.get("method") or data.get("request_method")
        status = data.get("status") or data.get("response_code")
        size = data.get("body_bytes_sent") or data.get("size")
        ua = data.get("user_agent") or data.get("http_user_agent")
        referer = data.get("referer") or data.get("http_referer")

        ts = None
        time_field = data.get("timestamp") or data.get("time") or data.get("@timestamp")
        if isinstance(time_field, (int, float)):
            ts = datetime.fromtimestamp(time_field)
        elif isinstance(time_field, str):
            ts = parse_timestamp(time_field)

        return LogEntry(
            ip=str(ip),
            timestamp=ts,
            method=str(method or "GET"),
            path=str(path or "/"),
            status=int(status or 0),
            size=int(size or 0),
            referer=str(referer or "-"),
            user_agent=str(ua or "-"),
            source="json",
            extra=data,
            raw_line=line,
        )


class KeyValueParser(LogParser):
    def parse(self, line: str) -> Optional[LogEntry]:
        # Simple key-value parser, e.g., for firewalls
        if "=" not in line:
            return None

        data = {}
        # Improved regex to handle:
        # 1. key="value" (quoted)
        # 2. key=value (unquoted, space separated)
        # 3. key='value' (single quoted)
        # 4. key=value (at the end of line)
        pattern = re.compile(r'(\w+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s,]+))')
        matches = pattern.findall(line)
        
        if not matches:
            return None

        for match in matches:
            key = match[0]
            # Take the first non-empty value group
            value = match[1] or match[2] or match[3]
            data[key] = value

        ip = data.get("srcip") or data.get("src_ip") or data.get("src") or data.get("source") or data.get("client")
        if not ip:
            return None

        ts = None
        # Try some common firewall timestamp formats
        if "date" in data and "time" in data:
            ts_str = f"{data['date']} {data['time']}"
            ts = parse_timestamp(ts_str)
        elif "timestamp" in data:
            # 使用通用的 parse_timestamp 函数来处理时间戳
            ts = parse_timestamp(data["timestamp"])

        return LogEntry(
            ip=ip,
            timestamp=ts,
            method=data.get("method", "-"),
            path=data.get("path", data.get("dst_path", data.get("url", "/"))),
            status=int(data.get("status", 0)),
            size=int(data.get("sentbyte", data.get("size", 0))),
            referer=data.get("referer", "-"),
            user_agent=data.get("user_agent", "-"),
            source="keyvalue",
            extra=data,
            raw_line=line,
        )


class CsvParser(LogParser):
    def __init__(self):
        self.header: list[str] = []
        # Support more Chinese and security device aliases
        self.ip_field_aliases = {
            "源", "源ip", "src_ip", "source_ip", "ip", "attacker", 
            "client_ip", "remote_addr", "来源", "攻击者", "源地址", "攻击源", "ip地址"
        }
        self.ip_idx: Optional[int] = None
        self.delimiter = ","
        self.lock = threading.Lock()

    def reset(self) -> None:
        with self.lock:
            self.header = []
            self.ip_idx = None
            self.delimiter = ","

    def parse(self, line: str) -> Optional[LogEntry]:
        with self.lock:
            line = line.strip()
            if not line:
                return None

            # Determine delimiter if not set
            if not self.header:
                delimiters = [',', ';', '\t', '|']
                best_delim = ','
                max_parts = 0
                
                for d in delimiters:
                    parts = [p.strip() for p in line.split(d)]
                    if len(parts) > max_parts:
                        # Check if this split contains any IP alias
                        if any(h.lower() in self.ip_field_aliases for h in parts):
                            max_parts = len(parts)
                            best_delim = d
                
                self.delimiter = best_delim
                parts = [p.strip() for p in line.split(self.delimiter)]
                
                # Assume first line with many parts is a header if it contains any known aliases
                if any(h.lower() in self.ip_field_aliases for h in parts):
                    self.header = [h.lower() for h in parts]
                    for i, h in enumerate(self.header):
                        if h in self.ip_field_aliases:
                            self.ip_idx = i
                            break
                    return None # Skip header line
                else:
                    return None

            if self.ip_idx is None:
                return None

            try:
                reader = csv.reader(io.StringIO(line), delimiter=self.delimiter)
                row = next(reader)
                if len(row) < len(self.header):
                    # Try a fallback simple split if csv reader fails
                    row = [p.strip() for p in line.split(self.delimiter)]
                    if len(row) < len(self.header):
                        return None
            except (csv.Error, StopIteration):
                return None

            if self.ip_idx >= len(row):
                return None
                
            ip = row[self.ip_idx]
            # Basic IP validation to avoid matching header-like data
            if not is_valid_ip(ip):
                return None

            row_data = {self.header[i]: val for i, val in enumerate(row) if i < len(self.header)}

            # Try to find common fields with more aliases
            path_aliases = ["path", "uri", "请求路径", "url", "dst_path", "request", "uri_path", "路径"]
            method_aliases = ["method", "请求方法", "request_method", "action", "方法"]
            status_aliases = ["status", "状态码", "code", "response_code", "状态"]
            size_aliases = ["size", "bytes", "响应大小", "body_bytes", "字节", "大小"]
            
            path = next((row_data.get(a) for a in path_aliases if a in row_data), "-")
            method = next((row_data.get(a) for a in method_aliases if a in row_data), "GET")
            
            status_val = next((row_data.get(a) for a in status_aliases if a in row_data), 0)
            try:
                status = int(float(str(status_val))) # handle "200.0"
            except (ValueError, TypeError):
                status = 0

            size_val = next((row_data.get(a) for a in size_aliases if a in row_data), 0)
            try:
                size = int(float(str(size_val)))
            except (ValueError, TypeError):
                size = 0

            timestamp_str = row_data.get("timestamp") or row_data.get("time") or row_data.get("date")
            ts = parse_timestamp(timestamp_str) if timestamp_str else None

            return LogEntry(
                ip=ip,
                timestamp=ts,
                method=str(method),
                path=str(path),
                status=status,
                size=size,
                referer=str(row_data.get("referer", "-")),
                user_agent=str(row_data.get("user_agent", "-")),
                source="csv",
                extra=row_data,
                raw_line=line,
            )


class SyslogParser(LogParser):
    # Strip syslog prefixes like "Mar 23 17:36:38 host nginx: "
    SYSLOG_PATTERN = re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$')

    def parse(self, line: str) -> Optional[LogEntry]:
        match = self.SYSLOG_PATTERN.match(line.strip())
        if not match:
            return None
        
        # Pass the message part to other parsERS via parse_log_line recursively
        # But we need to avoid infinite recursion
        msg = match.group("msg")
        # Temporarily remove SyslogParser from active parsers to prevent recursion
        # Or just manually call other specific parsers
        for parser in _PARSER_INSTANCES:
            if isinstance(parser, SyslogParser):
                continue
            res = parser.parse(msg)
            if res:
                return res
        return None


class FallbackParser(LogParser):
    # Best-effort parser to extract IP (IPv4 or IPv6) from the line
    IP_PATTERN = re.compile(
        r'((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]+:[a-fA-F0-9:]+)'
    )
    # HTTP request pattern (more flexible)
    HTTP_REQUEST_PATTERN = re.compile(
        r'(?P<method>[A-Z]+)\s+(?P<path>\S+)'
    )
    # User-Agent pattern (more flexible)
    USER_AGENT_PATTERN = re.compile(
        r'User-Agent:\s*(?P<user_agent>.*)'
    )
    # X-Forwarded-For pattern
    X_FORWARDED_FOR_PATTERN = re.compile(
        r'X-Forwarded-For:\s*(?P<ip>\S+)'
    )

    def parse(self, line: str) -> Optional[LogEntry]:
        # Search for IP address
        ip = None
        # First try to extract from X-Forwarded-For header
        x_forwarded_for_match = self.X_FORWARDED_FOR_PATTERN.search(line)
        if x_forwarded_for_match:
            ip = x_forwarded_for_match.group('ip')
            if not is_valid_ip(ip):
                ip = None
        
        # If no IP from X-Forwarded-For, try to find IP anywhere in the line
        if not ip:
            matches = self.IP_PATTERN.findall(line)
            for candidate in matches:
                if is_valid_ip(candidate):
                    ip = candidate
                    break
        
        if not ip:
            return None
        
        # Extract HTTP method and path
        method = "-"
        path = "-"
        http_request_match = self.HTTP_REQUEST_PATTERN.search(line)
        if http_request_match:
            method = http_request_match.group('method')
            path = http_request_match.group('path')
        
        # Extract User-Agent
        user_agent = "-"
        user_agent_match = self.USER_AGENT_PATTERN.search(line)
        if user_agent_match:
            user_agent = user_agent_match.group('user_agent')
        
        # 尝试从原始日志中提取时间戳
        timestamp_str = None
        
        # 尝试匹配多种时间戳格式
        timestamp_patterns = [
            # Apache 日志格式
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*)\]',
            # ISO 格式
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)',
            # 空格分隔的日期时间
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?)',
            # Syslog 格式
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            # 斜杠分隔的日期
            r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})',
            # 点分隔的日期
            r'(\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2})',
            # 短横线分隔的日期
            r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})',
            # 无分隔符的日期时间
            r'(\d{14})',  # YYYYMMDDHHMMSS
        ]
        
        for pattern in timestamp_patterns:
            timestamp_match = re.search(pattern, line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                break
        
        extra = {"fallback": True}
        
        ts = parse_timestamp(timestamp_str) if timestamp_str else None
        
        return LogEntry(
            ip=ip,
            timestamp=ts,
            method=method,
            path=path,
            status=0,
            size=0,
            referer="-",
            user_agent=user_agent,
            source="fallback",
            raw_line=line,
            extra=extra
        )


# --- Dispatcher ---
# Order matters: more specific parsers should come first.
_PARSER_CLASSES: list[type[LogParser]] = [
    NginxParser,
    JsonParser,
    KeyValueParser,
    CsvParser,
    SyslogParser,
    FallbackParser,
]

# Global parser instances (shared across threads, each parser must be thread-safe)
_PARSER_INSTANCES: list[LogParser] = [cls() for cls in _PARSER_CLASSES]

def parse_log_line(line: str) -> Optional[LogEntry]:
    """Tries each registered parser on the line until one succeeds."""
    if not line.strip():
        return None
    for parser in _PARSER_INSTANCES:
        try:
            result = parser.parse(line)
            if result and is_valid_ip(result.ip):
                return result
        except Exception:
            continue
    return None

def reset_parsers() -> None:
    """Calls reset on all registered parser instances."""
    for p in _PARSER_INSTANCES:
        p.reset()

import concurrent.futures
import os

# 优化线程池大小：根据CPU核心数动态调整，最大支持16个线程
MAX_WORKERS = min(os.cpu_count() or 4, 16)
BATCH_SIZE = 1000  # 批处理大小，避免内存溢出

def parse_log_line_with_enhance(line: str) -> Optional[LogEntry]:
    """解析单条日志并增强"""
    item = parse_log_line(line)
    if item:
        return enhance_entry_with_payload(item)
    return None

def lines_to_entries(line_iter: Iterator[str]) -> tuple[list[LogEntry], int]:
    """解析日志行，使用多线程提高性能"""
    entries: list[LogEntry] = []
    invalid = 0
    
    # 处理多行HTTP请求数据
    http_request_lines = []
    single_lines = []
    
    for line in line_iter:
        line = line.strip()
        if not line:
            # 空行，可能是HTTP请求的结束
            if http_request_lines:
                # 合并HTTP请求行
                http_request = '\n'.join(http_request_lines)
                single_lines.append(http_request)
                # 重置HTTP请求行
                http_request_lines = []
            continue
        
        # 检查是否是HTTP请求的开始
        if line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
            # 如果已经有HTTP请求行，先处理之前的
            if http_request_lines:
                http_request = '\n'.join(http_request_lines)
                single_lines.append(http_request)
                http_request_lines = []
            # 开始新的HTTP请求
            http_request_lines.append(line)
        elif http_request_lines:
            # 继续添加HTTP请求行
            http_request_lines.append(line)
        else:
            # 单独的行，直接添加到列表
            single_lines.append(line)
    
    # 处理最后一个HTTP请求
    if http_request_lines:
        http_request = '\n'.join(http_request_lines)
        single_lines.append(http_request)
    
    # 使用线程池并行解析（分批处理，避免内存溢出）
    if single_lines:
        # 分批处理
        for i in range(0, len(single_lines), BATCH_SIZE):
            batch_lines = single_lines[i:i + BATCH_SIZE]
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # 提交当前批次的解析任务
                future_to_line = {executor.submit(parse_log_line_with_enhance, line): line for line in batch_lines}
                
                # 收集结果
                for future in concurrent.futures.as_completed(future_to_line):
                    item = future.result()
                    if item:
                        entries.append(item)
                    else:
                        invalid += 1
    
    return entries, invalid


# --- Payload Analysis Functions ---

def enhance_entry_with_payload(entry: LogEntry) -> LogEntry:
    """Enhance LogEntry with parsed payload information."""
    # Parse URL to separate path and query string
    if entry.path:
        # Handle full URLs (http://...) and relative paths
        if '://' in entry.path:
            # Full URL, parse with urllib
            parsed = urllib.parse.urlparse(entry.path)
            entry.url_path = parsed.path
            entry.query_string = parsed.query
        else:
            # Relative path, check for query string
            if '?' in entry.path:
                path_part, query_part = entry.path.split('?', 1)
                entry.url_path = path_part
                entry.query_string = query_part
            else:
                entry.url_path = entry.path
                entry.query_string = ""
        
        # Parse query parameters
        if entry.query_string:
            entry.query_params = dict(urllib.parse.parse_qsl(entry.query_string, keep_blank_values=True))
    
    # Parse referer header for additional information
    if entry.referer and entry.referer != "-":
        # Extract potential parameters from referer
        try:
            parsed_ref = urllib.parse.urlparse(entry.referer)
            if parsed_ref.query:
                ref_params = dict(urllib.parse.parse_qsl(parsed_ref.query, keep_blank_values=True))
                # Merge with existing query_params
                entry.query_params.update(ref_params)
        except Exception:
            pass
    
    # Parse user-agent for browser/device info
    if entry.user_agent and entry.user_agent != "-":
        entry.headers["User-Agent"] = entry.user_agent
    
    # Parse cookies from extra data if available
    if "cookie" in entry.extra:
        cookies_str = entry.extra.get("cookie")
        if cookies_str:
            entry.cookies = parse_cookies(cookies_str)
    
    # Try to extract POST data from extra data
    if "post_data" in entry.extra:
        post_str = entry.extra.get("post_data")
        if post_str:
            entry.post_data = parse_post_data(post_str)
    
    return entry


def parse_cookies(cookie_str: str) -> dict[str, str]:
    """Parse cookie string into dictionary."""
    cookies = {}
    try:
        for cookie in cookie_str.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    except Exception:
        pass
    return cookies


def parse_post_data(post_str: str) -> dict[str, str]:
    """Parse POST data into dictionary."""
    post_data = {}
    try:
        # Try URL-encoded form data
        post_data = dict(urllib.parse.parse_qsl(post_str, keep_blank_values=True))
    except Exception:
        try:
            # Try JSON data
            if post_str.strip().startswith('{'):
                data = json.loads(post_str)
                if isinstance(data, dict):
                    # Flatten JSON for detection
                    for key, value in data.items():
                        if isinstance(value, (str, int, float, bool)):
                            post_data[str(key)] = str(value)
                        elif value is None:
                            post_data[str(key)] = ""
        except Exception:
            pass
    return post_data


def extract_all_payload_strings(entry: LogEntry) -> list[str]:
    """Extract all potential payload strings from LogEntry for analysis."""
    payloads = []
    
    # Add URL path
    if entry.url_path:
        payloads.append(entry.url_path)
    
    # Add query parameter values
    for value in entry.query_params.values():
        if value:
            payloads.append(value)
    
    # Add POST data values
    for value in entry.post_data.values():
        if value:
            payloads.append(value)
    
    # Add header values (excluding common safe headers)
    safe_headers = {"User-Agent", "Accept", "Accept-Language", "Accept-Encoding", 
                    "Connection", "Host", "Content-Length", "Content-Type"}
    for key, value in entry.headers.items():
        if key not in safe_headers and value:
            payloads.append(value)
    
    # Add cookie values
    for value in entry.cookies.values():
        if value:
            payloads.append(value)
    
    return payloads
