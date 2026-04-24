"""威胁情报相关纯函数（无 handler 状态，便于测试与复用）。"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return False


def filter_public_ips(ips: Iterable[str]) -> List[str]:
    return [ip for ip in ips if is_public_ip(ip)]
