"""Application bootstrap: wires services into a single ApplicationContext (no globals in handlers)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional


def _ensure_project_root_on_path(project_root: str) -> None:
    if project_root not in sys.path:
        sys.path.append(project_root)
    sys.path.insert(0, project_root)


def _noop_cached(ttl=None):
    def decorator(func):
        return func

    return decorator


@dataclass
class ApplicationContext:
    project_root: str
    cache_available: bool
    cached: Callable
    cache_manager: Any
    service_manager_available: bool
    service_manager: Any
    data_source_available: bool
    get_data_source_manager: Callable[[], Any]
    lines_to_entries: Optional[Callable]
    ai_available: bool
    anomaly_detector: Any
    attack_classifier: Any
    alert_manager: Any
    policy_manager: Any
    notification_manager: Any
    get_db_connection: Optional[Callable[[], Any]]

    @property
    def database_path(self) -> str:
        return os.path.join(self.project_root, "data", "network_attack_analyzer.db")


def bootstrap_application(services_dir: Optional[str] = None) -> ApplicationContext:
    """
    Initialize caches, DB, AI, data sources, and listeners.
    `services_dir` should be the path to the `services` package directory.
    """
    if services_dir is None:
        services_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_root = os.path.dirname(services_dir)
    _ensure_project_root_on_path(project_root)

    get_db_connection_fn: Optional[Callable[[], Any]] = None
    try:
        from config.database import init_database, get_db_connection

        init_database()
        get_db_connection_fn = get_db_connection
    except ImportError as e:
        print(f"Error: Cannot import database: {e}")

    try:
        from services.cache import cached as real_cached, cache_manager as real_cache_manager

        cache_available = True
        cached = real_cached
        cache_manager = real_cache_manager
    except ImportError as e:
        print(f"Warning: Cache module not available: {e}")
        cache_available = False
        cached = _noop_cached

        class _EmptyCache:
            def get(self, key):
                return None

            def set(self, key, value, ttl=None):
                pass

            def delete(self, key):
                pass

            def clear(self):
                pass

            def get_stats(self):
                return {}

        cache_manager = _EmptyCache()

    try:
        from services.service_manager import service_manager as sm

        service_manager_available = True
        service_manager = sm
    except ImportError as e:
        print(f"Warning: Service manager not available: {e}")
        service_manager_available = False
        service_manager = None

    try:
        from services.data_source_manager import get_data_source_manager as gdsm

        data_source_available = True
        get_data_source_manager = gdsm
    except ImportError as e:
        print(f"Warning: Data source manager not available: {e}")
        data_source_available = False

        def get_data_source_manager():
            raise RuntimeError("Data source manager not available")

    lines_to_entries = None
    try:
        from utils.log_parsers import lines_to_entries as lte

        lines_to_entries = lte
    except ImportError as e:
        print(f"Warning: Log parsers not available: {e}")

    ai_available = False
    anomaly_detector = None
    attack_classifier = None
    alert_manager = None
    policy_manager = None
    notification_manager = None

    # 首先尝试初始化告警管理器（不依赖numpy）
    try:
        from ai.models.alert_deduplication import AlertManager
        from ai.models.alert_rules import AlertPolicyManager
        from ai.models.alert_notification import AlertNotificationManager, LogDetailedAction

        alert_manager = AlertManager()
        policy_manager = AlertPolicyManager()
        notification_manager = AlertNotificationManager()

        policy_manager.rule_engine.create_default_rules()
        policy_manager.create_default_policies()

        log_detailed_action = LogDetailedAction(
            log_file=os.path.join(project_root, "data", "detailed_alerts.log"),
            enabled=True,
        )
        notification_manager.add_response_action(log_detailed_action)
        notification_manager.start_background_worker()
        
        print("Info: Alert managers loaded successfully")
    except Exception as e:
        print(f"Warning: Alert managers initialization failed: {e}")

    # 然后尝试初始化AI模型（依赖numpy等）
    try:
        from ai.models.anomaly_detection import AnomalyDetector
        from ai.models.attack_classifier import EnhancedAttackClassifier

        model_dir = os.path.join(project_root, "ai", "models")
        anomaly_model_path = os.path.join(model_dir, "anomaly_detector.joblib")
        classifier_model_path = os.path.join(model_dir, "attack_classifier.joblib")

        anomaly_detector = AnomalyDetector(anomaly_model_path)
        attack_classifier = EnhancedAttackClassifier(classifier_model_path)
        
        if attack_classifier:
            attack_classifier.load_history_from_database()

        if data_source_available and attack_classifier:
            get_data_source_manager(attack_classifier)

        ai_available = True
        print("Info: AI models loaded successfully")
    except Exception as e:
        print(f"Warning: AI models not available: {e}")

    # 无论AI模型是否可用，都启动服务管理器
    if service_manager_available and service_manager is not None:
        try:
            service_manager.start_all_services()
            print("Info: Service manager started successfully")
        except Exception as e:
            print(f"Warning: Service manager failed to start: {e}")

    return ApplicationContext(
        project_root=project_root,
        cache_available=cache_available,
        cached=cached,
        cache_manager=cache_manager,
        service_manager_available=service_manager_available,
        service_manager=service_manager,
        data_source_available=data_source_available,
        get_data_source_manager=get_data_source_manager,
        lines_to_entries=lines_to_entries,
        ai_available=ai_available,
        anomaly_detector=anomaly_detector,
        attack_classifier=attack_classifier,
        alert_manager=alert_manager,
        policy_manager=policy_manager,
        notification_manager=notification_manager,
        get_db_connection=get_db_connection_fn,
    )
