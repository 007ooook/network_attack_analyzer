"""API GET 路由表：字典查找替代长 if/elif，略减分支开销、结构更清晰。"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

from .http_utils import send_json_api_headers

# (path, handler_method_name) — handler 为 AnalyzerRequestHandler 实例
_GetExact = Dict[str, Callable[[Any, dict], None]]
_GetPrefix = List[Tuple[str, Callable[[Any, str, dict], None]]]


def _exact_routes() -> _GetExact:
    return {
        "/api/logs": lambda h, q: h.handle_get_logs(q),
        "/api/statistics": lambda h, q: h.handle_get_statistics(),
        "/api/config": lambda h, q: h.handle_get_config(),
        "/api/query-threat-intel": lambda h, q: h.handle_query_threat_intel(q),
        "/api/threat-intel-summary": lambda h, q: h.handle_get_threat_intel_summary(),
        "/api/health": lambda h, q: h.handle_get_system_health(),
        "/api/system-health": lambda h, q: h.handle_get_system_health(),
        "/api/threats": lambda h, q: h.handle_get_threats(q),
        "/api/predictions": lambda h, q: h.handle_get_predictions(q),
        "/api/attack-trends": lambda h, q: h.handle_get_attack_trends(q),
        "/api/data-sources": lambda h, q: h.handle_get_data_sources(),
        "/api/data-source-logs": lambda h, q: h.handle_get_data_source_logs(q),
        "/api/alerts": lambda h, q: h.handle_get_alerts(q),
        "/api/alerts/statistics": lambda h, q: h.handle_get_alert_statistics(),
        "/api/alert-rules": lambda h, q: h.handle_get_alert_rules(),
        "/api/alert-policies": lambda h, q: h.handle_get_alert_policies(),
        "/api/notification-history": lambda h, q: h.handle_get_notification_history(q),
        "/api/metrics": lambda h, q: h.handle_get_metrics(q),
        "/api/rules": lambda h, q: h.handle_get_alert_rules(),
        "/api/me": lambda h, q: h.handle_get_current_user(),
        "/api/security-config": lambda h, q: h.handle_get_security_config(),
    }


def _prefix_routes() -> _GetPrefix:
    return [
        ("/api/predict-attack/", lambda h, path, q: h.handle_predict_attack(path)),
        ("/api/ip-analysis/", lambda h, path, q: h.handle_analyze_ip(path)),
        ("/api/data-sources/", lambda h, path, q: h.handle_get_data_source_detail(path)),
        ("/api/alert-rules/", lambda h, path, q: h.handle_alert_rule_operations(path)),
        ("/api/alert-policies/", lambda h, path, q: h.handle_alert_policy_operations(path)),
    ]


_GET_EXACT = _exact_routes()
_GET_PREFIX = _prefix_routes()


def dispatch_api_get(handler, path: str, query_params: dict) -> bool:
    """
    若 path 命中已注册 API，则发送 JSON 头并调用 handler，返回 True。
    未命中返回 False（由调用方处理静态回退等）。
    """
    fn = _GET_EXACT.get(path)
    if fn is not None:
        send_json_api_headers(handler)
        fn(handler, query_params)
        return True
    for prefix, pfn in _GET_PREFIX:
        if path.startswith(prefix):
            send_json_api_headers(handler)
            pfn(handler, path, query_params)
            return True
    return False
