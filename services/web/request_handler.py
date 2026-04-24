"""HTTP entry: static frontend + delegates /api/* to ApiHandlerMixin."""

from __future__ import annotations

import json
import traceback
from http.server import SimpleHTTPRequestHandler
from typing import ClassVar, Optional
from urllib.parse import parse_qs, urlparse

from services.error_handler import handle_error
from services.security import get_security_manager
from services.auth import auth_manager
from services.config import config
from .api_mixin import ApiHandlerMixin
from .api_routing import dispatch_api_get
from .context import ApplicationContext
from .http_utils import read_request_json_body, send_json_api_headers, send_options_preflight
from .static_assets import serve_dist_fallback_file, serve_spa_or_static


PUBLIC_ENDPOINTS = {
    '/api/login',
    '/api/health',
    '/api/system-health',
}


class AnalyzerRequestHandler(ApiHandlerMixin, SimpleHTTPRequestHandler):
    """Set class attribute `application_context` before serving (see `main.attach_application_context`)."""

    application_context: ClassVar[Optional[ApplicationContext]] = None

    def _check_security(self):
        """检查安全状态"""
        client_ip = self.client_address[0]
        
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            content_length = 0
        else:
            content_length = int(content_length)
        
        security_manager = get_security_manager()
        result = security_manager.check_security(client_ip, content_length)
        
        if not result['allowed']:
            self.send_error(result['status_code'], result['error'])
            return False
        
        return True
    
    def _check_auth(self, path: str) -> bool:
        """检查认证状态"""
        if not config.auth_enabled:
            return True
        
        if path in PUBLIC_ENDPOINTS:
            return True
        
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            self.send_response(401)
            send_json_api_headers(self)
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': '未授权访问',
                'message': '请提供有效的认证令牌'
            }).encode('utf-8'))
            return False
        
        token = auth_header.replace('Bearer ', '')
        payload = auth_manager.verify_token(token)
        
        if not payload:
            self.send_response(401)
            send_json_api_headers(self)
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': '令牌无效或已过期',
                'message': '请重新登录'
            }).encode('utf-8'))
            return False
        
        return True

    def do_GET(self):
        try:
            if not self._check_security():
                return
            
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            query_params = parse_qs(parsed_path.query)

            if serve_spa_or_static(self, path, self.ctx.project_root):
                return

            if path.startswith("/api/"):
                if not self._check_auth(path):
                    return
                if not dispatch_api_get(self, path, query_params):
                    serve_dist_fallback_file(self, path, self.ctx.project_root)
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            self._handle_error(e)

    def do_POST(self):
        try:
            if not self._check_security():
                return
            
            parsed_path = urlparse(self.path)
            path = parsed_path.path

            if path not in PUBLIC_ENDPOINTS:
                if not self._check_auth(path):
                    return

            send_json_api_headers(self)

            content_length = self.headers.get("Content-Length")
            if content_length is None:
                content_length = 0
            else:
                content_length = int(content_length)

            post_data = self.rfile.read(content_length) if content_length > 0 else b""

            data = read_request_json_body(self, post_data, path)

            if path == "/api/login":
                self.handle_login(data)
            elif path == "/api/logout":
                self.handle_logout(data)
            elif path == "/api/change-password":
                self.handle_change_password(data)
            elif path == "/api/parse":
                self.handle_parse_logs(data)
            elif path == "/api/config":
                self.handle_update_config(data)
            elif path == "/api/config/single":
                self.handle_update_single_config(data)
            elif path == "/api/config/reset":
                self.handle_reset_config(data)
            elif path == "/api/threats":
                self.handle_add_threat(data)
            elif path == "/api/predict":
                self.handle_generate_prediction(data)
            elif path == "/api/export-logs":
                self.handle_export_logs(data)
            elif path == "/api/behavior-analysis":
                self.handle_analyze_behavior(data)
            elif path == "/api/data-sources":
                self.handle_create_data_source(data)
            elif path.startswith("/api/data-sources/"):
                parts = path.split("/")
                if len(parts) >= 4:
                    source_id = parts[3]
                    action = parts[4] if len(parts) > 4 else None
                    if action == "start":
                        self.handle_start_data_source(source_id)
                    elif action == "stop":
                        self.handle_stop_data_source(source_id)
                    elif action == "test":
                        self.handle_test_data_source(source_id, data)
                    else:
                        self.handle_update_data_source(source_id, data)
                else:
                    self.send_error(404, "Not Found")
            elif path == "/api/webhook-logs":
                self.handle_webhook_logs(data)
            elif path == "/api/alert-rules":
                self.handle_create_alert_rule(data)
            elif path == "/api/alert-policies":
                self.handle_create_alert_policy(data)
            elif path == "/api/fetch-threats":
                self.handle_fetch_threats(data)
            elif path == "/api/test-threat-intel":
                self.handle_test_threat_intel(data)
            elif path.startswith("/api/rules/"):
                parts = path.split("/")
                if len(parts) == 4:
                    rule_id = parts[3]
                    self.handle_update_alert_rule(rule_id, data)
                else:
                    self.send_error(404, "Not Found")
            elif path == "/api/rules":
                self.handle_create_alert_rule(data)
            elif path == "/api/security-config":
                self.handle_update_security_config(data)
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            self._handle_error(e)

    def do_DELETE(self):
        try:
            if not self._check_security():
                return
            
            path = urlparse(self.path).path
            
            if not self._check_auth(path):
                return

            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length)
            
            send_json_api_headers(self, methods="GET, POST, DELETE, OPTIONS")

            if path.startswith("/api/data-sources/"):
                parts = path.split("/")
                if len(parts) == 4:
                    source_id = parts[3]
                    self.handle_delete_data_source(source_id)
                else:
                    self.send_error(404, "Not Found")
            elif path.startswith("/api/rules/"):
                parts = path.split("/")
                if len(parts) == 4:
                    rule_id = parts[3]
                    if not self.ctx.policy_manager:
                        response = {'error': 'Policy manager not available'}
                        self.write_json(response)
                        return
                    success = self.ctx.policy_manager.rule_engine.remove_rule(rule_id)
                    response = {'success': success, 'message': f'Rule {rule_id} deleted' if success else 'Rule not found'}
                    self.write_json(response)
                else:
                    self.send_error(404, "Not Found")
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            self._handle_error(e)

    def _handle_error(self, error: Exception):
        """处理错误并返回标准化的错误响应"""
        error_response = handle_error(error)
        
        # 发送错误响应
        self.send_response(error_response['error']['code'])
        send_json_api_headers(self)
        self.end_headers()
        
        # 写入错误响应体
        self.wfile.write(json.dumps(error_response).encode('utf-8'))

    def do_OPTIONS(self):
        send_options_preflight(self)
