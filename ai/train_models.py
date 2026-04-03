import os
import sys
import json
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any
import sqlite3
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ai.models.anomaly_detection import AnomalyDetector
from ai.models.attack_classifier import EnhancedAttackClassifier

class ModelTrainer:
    def __init__(self, db_path: str = None):
        """初始化模型训练器"""
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'network_attack_analyzer.db')
        
        self.db_path = db_path
        self.model_dir = os.path.join(os.path.dirname(__file__), '..', 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.anomaly_model_path = os.path.join(self.model_dir, 'anomaly_detector.joblib')
        self.classifier_model_path = os.path.join(self.model_dir, 'attack_classifier.joblib')
        
        self.anomaly_detector = AnomalyDetector(self.anomaly_model_path)
        self.attack_classifier = EnhancedAttackClassifier(self.classifier_model_path)
    
    def get_db_connection(self):
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def load_training_data(self, days: int = 30, limit: int = 10000) -> List[Dict[str, Any]]:
        """从数据库加载训练数据"""
        conn = self.get_db_connection()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ip, timestamp, method, path, status, size, 
                       referer, user_agent, query_params, post_data, 
                       headers, cookies, url_path, query_string
                FROM access_logs
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (cutoff_date.isoformat(), limit))
            
            rows = cursor.fetchall()
            
            training_data = []
            for row in rows:
                entry = {
                    'ip': row['ip'],
                    'timestamp': datetime.fromisoformat(row['timestamp']) if row['timestamp'] else None,
                    'method': row['method'],
                    'path': row['path'],
                    'status': row['status'],
                    'size': row['size'],
                    'referer': row['referer'],
                    'user_agent': row['user_agent'],
                    'query_params': json.loads(row['query_params']) if row['query_params'] else {},
                    'post_data': json.loads(row['post_data']) if row['post_data'] else {},
                    'headers': json.loads(row['headers']) if row['headers'] else {},
                    'cookies': json.loads(row['cookies']) if row['cookies'] else {},
                    'url_path': row['url_path'],
                    'query_string': row['query_string']
                }
                training_data.append(entry)
            
            print(f"从数据库加载了 {len(training_data)} 条训练数据")
            return training_data
            
        finally:
            conn.close()
    
    def generate_training_labels(self, training_data: List[Dict[str, Any]]) -> List[str]:
        """生成训练标签"""
        labels = []
        
        for entry in training_data:
            # 使用攻击分类器进行初步分类
            result = self.attack_classifier.classify(entry)
            
            # 根据分类结果生成标签
            if result['attack_type'] == 'Normal':
                labels.append('Normal')
            else:
                labels.append(result['attack_type'])
        
        return labels
    
    def train_anomaly_detector(self, training_data: List[Dict[str, Any]]) -> bool:
        """训练异常检测模型"""
        print("\n开始训练异常检测模型...")
        
        try:
            self.anomaly_detector.train(training_data)
            
            if self.anomaly_detector.is_trained:
                print("异常检测模型训练成功！")
                return True
            else:
                print("异常检测模型训练失败！")
                return False
                
        except Exception as e:
            print(f"训练异常检测模型时出错: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def train_attack_classifier(self, training_data: List[Dict[str, Any]]) -> bool:
        """训练攻击分类模型"""
        print("\n开始训练攻击分类模型...")
        
        try:
            labels = self.generate_training_labels(training_data)
            
            success = self.attack_classifier.train_model(training_data, labels)
            
            if success:
                print("攻击分类模型训练成功！")
                return True
            else:
                print("攻击分类模型训练失败！")
                return False
                
        except Exception as e:
            print(f"训练攻击分类模型时出错: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def train_all_models(self, days: int = 30, limit: int = 10000) -> bool:
        """训练所有模型"""
        print(f"开始训练所有模型（使用最近 {days} 天的数据，最多 {limit} 条）...")
        
        # 加载训练数据
        training_data = self.load_training_data(days=days, limit=limit)
        
        if len(training_data) < 50:
            print("训练数据不足，无法训练模型！")
            return False
        
        # 训练异常检测模型
        anomaly_success = self.train_anomaly_detector(training_data)
        
        # 训练攻击分类模型
        classifier_success = self.train_attack_classifier(training_data)
        
        # 评估模型性能
        if anomaly_success and classifier_success:
            print("\n所有模型训练完成！")
            self.evaluate_models(training_data)
            return True
        else:
            print("\n部分模型训练失败！")
            return False
    
    def evaluate_models(self, test_data: List[Dict[str, Any]]):
        """评估模型性能"""
        print("\n开始评估模型性能...")
        
        anomaly_count = 0
        attack_count = 0
        
        for entry in test_data[:100]:  # 只评估前100条
            # 测试异常检测
            anomaly_result = self.anomaly_detector.detect(entry)
            if anomaly_result['is_anomaly']:
                anomaly_count += 1
            
            # 测试攻击分类
            classification_result = self.attack_classifier.classify(entry)
            if classification_result['attack_type'] != 'Normal':
                attack_count += 1
        
        print(f"异常检测: 在100条测试数据中检测到 {anomaly_count} 个异常")
        print(f"攻击分类: 在100条测试数据中检测到 {attack_count} 个攻击")
        
        # 获取威胁情报摘要
        threat_summary = self.attack_classifier.get_threat_intel_summary()
        print(f"\n威胁情报摘要:")
        print(f"总分类次数: {threat_summary['total_classifications']}")
        print(f"总攻击次数: {threat_summary['total_attacks']}")
        print(f"检测率: {threat_summary['detection_rate']}%")
    
    def auto_train(self, interval_hours: int = 24, min_data_size: int = 100):
        """自动训练模型"""
        print(f"自动训练模式启动，每 {interval_hours} 小时检查一次...")
        
        while True:
            try:
                print(f"\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - 检查是否需要训练...")
                
                # 检查是否有足够的新数据
                training_data = self.load_training_data(days=1, limit=min_data_size)
                
                if len(training_data) >= min_data_size:
                    print(f"发现 {len(training_data)} 条新数据，开始训练...")
                    self.train_all_models(days=7, limit=5000)
                else:
                    print(f"新数据不足（需要至少 {min_data_size} 条），跳过训练...")
                
                # 等待下一次检查
                import time
                time.sleep(interval_hours * 3600)
                
            except KeyboardInterrupt:
                print("\n自动训练已停止")
                break
            except Exception as e:
                print(f"自动训练时出错: {e}")
                import time
                time.sleep(3600)  # 出错后等待1小时再重试

def main():
    parser = argparse.ArgumentParser(description='训练AI模型')
    parser.add_argument('--days', type=int, default=30, help='使用最近多少天的数据')
    parser.add_argument('--limit', type=int, default=10000, help='最多使用多少条数据')
    parser.add_argument('--auto', action='store_true', help='启用自动训练模式')
    parser.add_argument('--interval', type=int, default=24, help='自动训练间隔（小时）')
    parser.add_argument('--db', type=str, help='数据库路径')
    
    args = parser.parse_args()
    
    trainer = ModelTrainer(db_path=args.db)
    
    if args.auto:
        trainer.auto_train(interval_hours=args.interval)
    else:
        success = trainer.train_all_models(days=args.days, limit=args.limit)
        sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
