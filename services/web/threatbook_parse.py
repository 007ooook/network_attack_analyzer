"""微步 ThreatBook v3 scene/ip_reputation 响应解析（供拉取与测试共用）。"""

from __future__ import annotations

from typing import Any, Dict


def threatbook_v3_error_message(response_code: Any, verbose_msg: str) -> str:
    if response_code == -1:
        return f"API 密钥无效或没有访问权限: {verbose_msg}"
    if response_code == -2:
        return f"API 调用方法无效: {verbose_msg}"
    if response_code == -3:
        return f"请求频率超限: {verbose_msg}"
    if response_code == -4:
        return f"超出访问限制: {verbose_msg}"
    if response_code == 1001:
        return f"IP 资源格式错误: {verbose_msg}"
    return f"API 查询失败 (响应码: {response_code}): {verbose_msg}"


def parse_threatbook_ip_reputation(result_data: Dict[str, Any], ip: str) -> Dict[str, Any]:
    """
    解析 v3 响应。成功返回 success=True 及 threat_type, severity, description；
    失败返回 success=False 及 error。
    """
    if not result_data:
        return {"success": False, "error": "无返回数据"}

    if result_data.get("response_code") != 0:
        code = result_data.get("response_code")
        vm = result_data.get("verbose_msg", "未知错误")
        return {"success": False, "error": threatbook_v3_error_message(code, str(vm))}

    ip_data = result_data.get("data", {}).get(ip, {})

    basic = ip_data.get("basic", {})
    location_info = basic.get("location", {})
    location = f"{location_info.get('country', '')} {location_info.get('province', '')} {location_info.get('city', '')}".strip()
    isp = basic.get("carrier", "")
    asn = ip_data.get("asn", {})
    asn_info = f"{asn.get('number', '')} {asn.get('info', '')}".strip()

    verdict = "malicious" if ip_data.get("is_malicious", False) else "benign"
    judgments = ip_data.get("judgments", [])
    tag_str = ", ".join(judgments) if isinstance(judgments, list) else ""

    severity_raw = ip_data.get("severity", "info")
    severity_map = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Low",
    }
    severity = severity_map.get(str(severity_raw).lower(), "Low")

    description_parts = []
    if location:
        description_parts.append(f"地理位置: {location}")
    if isp:
        description_parts.append(f"运营商: {isp}")
    description_parts.append(f"情报判定: {verdict}")
    if tag_str:
        description_parts.append(f"标签: {tag_str}")
    if asn_info:
        description_parts.append(f"ASN: {asn_info}")

    description = "\n".join(description_parts) if description_parts else "无详细情报信息"
    threat_type = "Malicious IP" if verdict == "malicious" else "Benign IP"

    return {
        "success": True,
        "threat_type": threat_type,
        "severity": severity,
        "description": description,
        "verdict": verdict,
    }
