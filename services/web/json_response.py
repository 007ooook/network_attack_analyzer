"""统一 JSON 响应体写入：委托到 http_utils.write_json_body。"""

from __future__ import annotations

from typing import Any
from services.web.http_utils import write_json_body


class JsonResponseMixin:
    """供 API Mixin 使用：在已发送 JSON 头后写入 body。"""

    def write_json(self, obj: Any) -> None:
        write_json_body(self.wfile, obj)
