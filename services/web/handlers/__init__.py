"""Domain-specific HTTP API handler mixins."""

from services.web.json_response import JsonResponseMixin

from .alert_handlers import AlertHandlersMixin
from .analytics_handlers import AnalyticsHandlersMixin
from .context_access import ContextAccessMixin
from .data_source_handlers import DataSourceHandlersMixin
from .logs_handlers import LogsHandlersMixin
from .threat_intel_handlers import ThreatIntelHandlersMixin
from .auth_handlers import AuthHandlersMixin

__all__ = [
    "AlertHandlersMixin",
    "AnalyticsHandlersMixin",
    "AuthHandlersMixin",
    "ContextAccessMixin",
    "DataSourceHandlersMixin",
    "JsonResponseMixin",
    "LogsHandlersMixin",
    "ThreatIntelHandlersMixin",
]

class ApiHandlerMixin(
    ContextAccessMixin,
    JsonResponseMixin,
    LogsHandlersMixin,
    ThreatIntelHandlersMixin,
    AnalyticsHandlersMixin,
    DataSourceHandlersMixin,
    AlertHandlersMixin,
    AuthHandlersMixin,
):
    """Composed API handlers for AnalyzerRequestHandler."""

    pass
