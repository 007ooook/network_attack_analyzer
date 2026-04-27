"""
HTTP 服务入口：组装 ApplicationContext，挂载 AnalyzerRequestHandler。

业务 API 实现在 services/web/api_mixin.py；静态资源见 services/web/static_assets.py。

作者: yeJ
"""

from __future__ import annotations

import os
import socketserver
import sys
import logging
import time

_services_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_services_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from services.error_handler import handle_error, log_error
from services.web.context import ApplicationContext, bootstrap_application
from services.web.request_handler import AnalyzerRequestHandler

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/server.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('server')


def attach_application_context(ctx: ApplicationContext) -> None:
    AnalyzerRequestHandler.application_context = ctx


def start_server(port: int = 65534) -> None:
    try:
        # 确保日志目录存在
        os.makedirs('logs', exist_ok=True)
        
        # 初始化监控
        from services.monitoring import collect_and_save_metrics
        
        # 启动指标收集线程
        import threading
        def metrics_collector():
            while True:
                collect_and_save_metrics()
                time.sleep(60)  # 每分钟收集一次指标
        
        metrics_thread = threading.Thread(target=metrics_collector, daemon=True)
        metrics_thread.start()
        logger.info("指标收集线程已启动")
        
        ctx = bootstrap_application(_services_dir)
        attach_application_context(ctx)
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", port), AnalyzerRequestHandler) as httpd:
            logger.info(f"Server running at http://localhost:{port}")
            httpd.serve_forever()
    except Exception as e:
        log_error(e, "Server startup")
        print(f"Server failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    start_server()
