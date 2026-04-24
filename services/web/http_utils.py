"""Shared HTTP helpers (CORS, JSON response headers, write JSON body)."""

import json
from typing import Any, Union
from services.security import get_security_manager

# 紧凑 JSON：更小 body、略快的序列化/传输
_JSON_KWARGS = {"ensure_ascii": False, "separators": (",", ":")}


def get_cors_origin(handler) -> str:
    """获取允许的CORS来源"""
    origin = handler.headers.get('Origin', '')
    security_manager = get_security_manager()
    
    if origin and security_manager.is_origin_allowed(origin):
        return origin
    
    return ''


def _send_cors_headers(handler, methods: str) -> None:
    allowed_origin = get_cors_origin(handler)
    if allowed_origin:
        handler.send_header("Access-Control-Allow-Origin", allowed_origin)
    handler.send_header("Access-Control-Allow-Methods", methods)
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.send_header("Access-Control-Allow-Credentials", "true")
    handler.end_headers()


def send_json_api_headers(handler, methods: str = "GET, POST, OPTIONS") -> None:
    handler.send_response(200)
    handler.send_header("Content-type", "application/json")
    _send_cors_headers(handler, methods)


def send_options_preflight(handler, methods: str = "GET, POST, DELETE, OPTIONS") -> None:
    handler.send_response(200)
    _send_cors_headers(handler, methods)


def write_json_body(wfile, obj: Any) -> None:
    wfile.write(json.dumps(obj, **_JSON_KWARGS).encode("utf-8"))


def read_request_json_body(handler, raw: bytes, path: str) -> Union[dict, str, Any]:
    """解析 POST body：/api/parse 与 /api/webhook-logs 支持 text/plain，其余默认 JSON。"""
    if path in ("/api/parse", "/api/webhook-logs"):
        content_type = handler.headers.get("Content-Type", "")
        if "text/plain" in content_type:
            return raw.decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def content_type_for_path(file_path: str) -> str:
    if file_path.endswith(".js"):
        return "application/javascript"
    if file_path.endswith(".css"):
        return "text/css"
    if file_path.endswith(".json"):
        return "application/json"
    if file_path.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"
