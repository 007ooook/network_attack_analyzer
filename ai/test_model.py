#!/usr/bin/env python3
"""
测试优化后的AI攻击分类器性能
"""

import os
import sys
import time
import json
from datetime import datetime

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.models.attack_classifier import EnhancedAttackClassifier

# 示例日志数据
sample_logs = [
    # 正常请求
    {
        'ip': '192.168.1.100',
        'path': '/index.html',
        'method': 'GET',
        'status': 200,
        'size': 1024,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'referer': 'https://example.com',
        'timestamp': datetime.now()
    },
    # SQL注入攻击
    {
        'ip': '10.0.0.1',
        'path': '/login.php?username=admin\' OR 1=1--&password=test',
        'method': 'GET',
        'status': 401,
        'size': 512,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'referer': '-',
        'timestamp': datetime.now()
    },
    # XSS攻击
    {
        'ip': '10.0.0.2',
        'path': '/search.php?q=<script>alert("XSS")</script>',
        'method': 'GET',
        'status': 200,
        'size': 2048,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'referer': 'https://example.com',
        'timestamp': datetime.now()
    },
    # 暴力破解攻击
    {
        'ip': '10.0.0.3',
        'path': '/login.php?username=admin&password=123456',
        'method': 'POST',
        'status': 401,
        'size': 256,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'referer': 'https://example.com/login',
        'timestamp': datetime.now()
    },
    # 路径遍历攻击
    {
        'ip': '10.0.0.4',
        'path': '/download.php?file=../../../etc/passwd',
        'method': 'GET',
        'status': 403,
        'size': 128,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'referer': '-',
        'timestamp': datetime.now()
    }
]

def test_feature_extraction(classifier):
    """测试特征提取性能"""
    print("\n=== 测试特征提取性能 ===")
    start_time = time.time()
    for i, log in enumerate(sample_logs):
        features = classifier.extract_multidimensional_features(log)
        print(f"样本 {i+1} 特征提取完成，特征数: {len(features)}")
    end_time = time.time()
    avg_time = (end_time - start_time) * 1000 / len(sample_logs)
    print(f"平均特征提取时间: {avg_time:.2f} ms")
    return avg_time

def test_classification(classifier):
    """测试分类性能"""
    print("\n=== 测试分类性能 ===")
    start_time = time.time()
    results = []
    for i, log in enumerate(sample_logs):
        result = classifier.classify(log)
        results.append(result)
        print(f"样本 {i+1} 分类结果: {result['attack_type']} (置信度: {result['confidence']:.2f}, 严重程度: {result['severity']})")
    end_time = time.time()
    avg_time = (end_time - start_time) * 1000 / len(sample_logs)
    print(f"平均分类时间: {avg_time:.2f} ms")
    return avg_time, results

def test_cache_performance(classifier):
    """测试缓存性能"""
    print("\n=== 测试缓存性能 ===")
    # 第一次分类（缓存未命中）
    start_time = time.time()
    for log in sample_logs:
        classifier.classify(log)
    end_time = time.time()
    first_time = (end_time - start_time) * 1000 / len(sample_logs)
    print(f"第一次分类平均时间: {first_time:.2f} ms")
    
    # 第二次分类（缓存命中）
    start_time = time.time()
    for log in sample_logs:
        classifier.classify(log)
    end_time = time.time()
    second_time = (end_time - start_time) * 1000 / len(sample_logs)
    print(f"第二次分类平均时间: {second_time:.2f} ms")
    
    # 计算缓存命中率
    stats = classifier.get_model_info()['statistics']
    cache_hits = stats['cache_hits']
    cache_misses = stats['cache_misses']
    hit_rate = stats['cache_hit_rate']
    print(f"缓存命中: {cache_hits}, 缓存未命中: {cache_misses}, 命中率: {hit_rate:.2f}%")
    
    return first_time, second_time, hit_rate

def test_behavior_analysis(classifier):
    """测试行为分析性能"""
    print("\n=== 测试行为分析性能 ===")
    # 模拟同一个IP的多次请求
    ip = '192.168.1.101'
    
    # 生成多个请求
    for i in range(20):
        log = {
            'ip': ip,
            'path': f'/page{i}.html',
            'method': 'GET',
            'status': 200 if i < 15 else 404,
            'size': 1024,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'referer': 'https://example.com',
            'timestamp': datetime.now()
        }
        classifier.classify(log)
    
    # 分析行为
    start_time = time.time()
    analysis = classifier.analyze_behavior_patterns(sample_logs[0])
    end_time = time.time()
    analysis_time = (end_time - start_time) * 1000
    
    print(f"行为分析时间: {analysis_time:.2f} ms")
    print(f"行为分析结果: 异常={analysis['is_anomalous']}, 攻击概率={analysis['attack_probability']:.2f}")
    if analysis['reasons']:
        print(f"异常原因: {', '.join(analysis['reasons'])}")
    
    return analysis_time

def test_model_info(classifier):
    """测试模型信息"""
    print("\n=== 测试模型信息 ===")
    model_info = classifier.get_model_info()
    print(json.dumps(model_info, indent=2, ensure_ascii=False))
    
    performance = classifier.get_performance_metrics()
    print("\n性能指标:")
    print(json.dumps(performance, indent=2, ensure_ascii=False))

def main():
    """主测试函数"""
    print("开始测试优化后的AI攻击分类器...")
    
    # 初始化分类器
    classifier = EnhancedAttackClassifier()
    
    # 测试特征提取
    test_feature_extraction(classifier)
    
    # 测试分类
    test_classification(classifier)
    
    # 测试缓存性能
    test_cache_performance(classifier)
    
    # 测试行为分析
    test_behavior_analysis(classifier)
    
    # 测试模型信息
    test_model_info(classifier)
    
    print("\n测试完成！")

if __name__ == "__main__":
    main()
