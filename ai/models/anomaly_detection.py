import os
import json
import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class AnomalyDetector:
    def __init__(self, model_path: Optional[str] = None):
        """初始化异常检测器"""
        self.model_path = model_path
        self.is_trained = False
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        self.feature_names = []
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def extract_features(self, log_entry: Dict[str, Any]) -> List[float]:
        """从日志条目中提取特征"""
        features = []
        
        # 基本长度特征
        features.append(len(log_entry.get('path', '')))
        features.append(len(log_entry.get('user_agent', '')))
        features.append(len(log_entry.get('referer', '')))
        features.append(log_entry.get('status', 0))
        features.append(log_entry.get('size', 0))
        
        # 查询参数特征
        query_params = log_entry.get('query_params', {})
        features.append(len(query_params))
        
        # POST数据特征
        post_data = log_entry.get('post_data', {})
        features.append(len(str(post_data)))
        
        # 请求方法特征
        method = log_entry.get('method', 'GET')
        method_features = [0] * 4
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'PATCH': 3}
        if method in method_map:
            method_features[method_map[method]] = 1
        features.extend(method_features)
        
        # IP特征
        ip = log_entry.get('ip', '')
        features.append(len(ip))
        features.append(1 if '.' in ip else 0)
        features.append(1 if ':' in ip else 0)
        
        # 路径特征
        path = log_entry.get('path', '')
        features.append(path.count('/'))
        features.append(path.count('.'))
        features.append(1 if path.lower().endswith('.php') else 0)
        features.append(1 if path.lower().endswith('.asp') else 0)
        features.append(1 if path.lower().endswith('.jsp') else 0)
        
        # 用户代理特征
        user_agent = log_entry.get('user_agent', '')
        features.append(1 if 'bot' in user_agent.lower() else 0)
        features.append(1 if 'curl' in user_agent.lower() else 0)
        features.append(1 if 'wget' in user_agent.lower() else 0)
        features.append(1 if 'python' in user_agent.lower() else 0)
        
        # 时间特征（如果timestamp存在）
        timestamp = log_entry.get('timestamp')
        if timestamp:
            features.append(timestamp.hour)
            features.append(timestamp.weekday())
        else:
            features.append(0)
            features.append(0)
        
        return features
    
    def train(self, training_data: List[Dict[str, Any]]):
        """训练异常检测模型"""
        if len(training_data) < 10:
            print("警告: 训练数据太少（至少需要10个样本）")
            return
        
        features_list = []
        for entry in training_data:
            features = self.extract_features(entry)
            features_list.append(features)
        
        # 转换为numpy数组
        X = np.array(features_list)
        
        # 标准化特征
        X_scaled = self.scaler.fit_transform(X)
        
        # 训练IsolationForest模型
        self.model.fit(X_scaled)
        self.is_trained = True
        
        # 保存模型
        if self.model_path:
            self.save_model(self.model_path)
        
        print(f"异常检测模型训练完成，使用了 {len(training_data)} 个样本")
        print(f"模型参数: n_estimators={self.model.n_estimators}, contamination={self.model.contamination}")
    
    def detect(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """检测异常"""
        if not self.is_trained:
            return self.heuristic_detect(log_entry)
        
        features = self.extract_features(log_entry)
        X = np.array([features])
        
        # 标准化特征
        X_scaled = self.scaler.transform(X)
        
        # 预测异常分数
        anomaly_score = self.model.decision_function(X_scaled)[0]
        is_anomaly = self.model.predict(X_scaled)[0] == -1
        
        # 计算置信度（基于异常分数）
        confidence = min(1.0, max(0.0, (0.5 - anomaly_score) / 0.5))
        
        return {
            'anomaly_score': float(abs(anomaly_score)),
            'is_anomaly': bool(is_anomaly),
            'confidence': float(confidence)
        }
    
    def heuristic_detect(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """使用启发式规则检测异常（当模型未训练时使用）"""
        score = 0.0
        
        # 检查状态码
        status = log_entry.get('status', 0)
        if status >= 400:
            score += 1.0
        if status >= 500:
            score += 1.0
        
        # 检查请求方法
        method = log_entry.get('method', 'GET')
        if method in ['PUT', 'DELETE', 'PATCH']:
            score += 0.5
        
        # 检查路径长度
        path = log_entry.get('path', '')
        if len(path) > 100:
            score += 1.0
        
        # 检查查询参数数量
        query_params = log_entry.get('query_params', {})
        if len(query_params) > 10:
            score += 1.0
        
        # 检查POST数据大小
        post_data = log_entry.get('post_data', {})
        if len(str(post_data)) > 1000:
            score += 1.0
        
        # 检查用户代理
        user_agent = log_entry.get('user_agent', '')
        if 'bot' in user_agent.lower():
            score += 0.5
        if not user_agent:
            score += 0.5
        
        # 检查路径中的可疑模式
        suspicious_patterns = ['..', '%2e', 'etc/passwd', 'union', 'select', 'script']
        for pattern in suspicious_patterns:
            if pattern.lower() in path.lower():
                score += 1.0
                break
        
        is_anomaly = score > 2.0
        confidence = min(1.0, score / 5.0)
        
        return {
            'anomaly_score': float(score),
            'is_anomaly': bool(is_anomaly),
            'confidence': float(confidence)
        }
    
    def save_model(self, path: str):
        """保存模型"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names
        }
        joblib.dump(model_data, path)
        print(f"异常检测模型已保存到 {path}")
    
    def load_model(self, path: str):
        """加载模型"""
        if os.path.exists(path):
            model_data = joblib.load(path)
            self.model = model_data.get('model', self.model)
            self.scaler = model_data.get('scaler', self.scaler)
            self.is_trained = model_data.get('is_trained', False)
            self.feature_names = model_data.get('feature_names', [])
            print(f"异常检测模型已从 {path} 加载")
        else:
            print(f"模型文件不存在: {path}")
