#!/usr/bin/env python3
import time
import json
import urllib.request

def test_config_save():
    # 准备测试数据
    config_data = {
        "api_url": "http://localhost:8003",
        "enable_cors": True,
        "allowed_origins": "*",
        "log_retention_days": 30,
        "max_log_size": 100,
        "enable_email_alert": False,
        "email_recipients": "admin@example.com",
        "alert_threshold": 0.8,
        "enable_rate_limiting": True,
        "rate_limit": 1000,
        "enable_ip_blocking": False,
        "block_duration": 3600,
        "enable_ssl": False,
        "ssl_cert_path": "",
        "ssl_key_path": "",
        "model_version": "2.0.0"
    }
    
    # 转换为JSON
    data = json.dumps(config_data).encode('utf-8')
    
    # 设置请求头
    headers = {
        'Content-Type': 'application/json',
    }
    
    # 创建请求
    req = urllib.request.Request('http://localhost:8003/api/config', data=data, headers=headers)
    
    # 测试保存速度
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            print(f"配置保存响应时间: {response_time:.2f} 毫秒")
            print(f"响应状态码: {response.getcode()}")
            print(f"响应内容: {response.read().decode('utf-8')}")
    except Exception as e:
        end_time = time.time()
        response_time = (end_time - start_time) * 1000  # 转换为毫秒
        print(f"测试失败，响应时间: {response_time:.2f} 毫秒")
        print(f"错误: {str(e)}")

if __name__ == "__main__":
    print("测试配置保存速度...")
    test_config_save()
    print("测试完成")