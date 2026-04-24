import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'network_attack_analyzer.db')

def init_database():
    """初始化数据库，创建必要的表结构"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 创建日志表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        ip TEXT,
        method TEXT,
        path TEXT,
        status INTEGER,
        size INTEGER,
        referer TEXT,
        user_agent TEXT,
        raw_log TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(ip, timestamp, method, path) ON CONFLICT IGNORE
    )
    ''')
    
    # 创建分析结果表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id INTEGER,
        anomaly_score REAL,
        attack_type TEXT,
        confidence REAL,
        threat_level TEXT,
        ai_model TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (log_id) REFERENCES logs (id)
    )
    ''')
    
    # 创建威胁情报表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS threat_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT,
        indicator_type TEXT,
        threat_type TEXT,
        severity TEXT,
        description TEXT,
        source TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 创建预测分析表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prediction_time TEXT,
        attack_type TEXT,
        probability REAL,
        prediction_date TEXT,
        model_version TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 创建告警表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT,
        source_ip TEXT,
        target_ip TEXT,
        attack_type TEXT,
        severity TEXT,
        confidence REAL,
        description TEXT,
        signature TEXT,
        is_duplicate BOOLEAN DEFAULT 0,
        is_aggregated BOOLEAN DEFAULT 0,
        count INTEGER DEFAULT 1,
        priority_score REAL DEFAULT 0,
        first_seen TEXT,
        last_seen TEXT,
        unique_source_ips TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 创建告警规则表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alert_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        enabled BOOLEAN DEFAULT 1,
        conditions TEXT,
        actions TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 创建告警策略表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alert_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        policy_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        enabled BOOLEAN DEFAULT 1,
        config TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 创建索引
    # logs 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs (ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_source ON logs (source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_method ON logs (method)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_path ON logs (path)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_status ON logs (status)')
    
    # analysis_results 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_results_log_id ON analysis_results (log_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_results_threat_level ON analysis_results (threat_level)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_results_attack_type ON analysis_results (attack_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_results_confidence ON analysis_results (confidence)')
    
    # threat_intel 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel (indicator)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_intel_threat_type ON threat_intel (threat_type)')
    
    # predictions 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_prediction_date ON predictions (prediction_date)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_attack_type ON predictions (attack_type)')
    
    # alerts 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts (attack_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_priority_score ON alerts (priority_score)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at)')
    
    # alert_rules 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_rules_rule_id ON alert_rules (rule_id)')
    
    # alert_policies 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_policies_policy_id ON alert_policies (policy_id)')
    
    # data_sources 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_sources_name ON data_sources (name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_sources_type ON data_sources (source_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_sources_status ON data_sources (status)')
    
    # data_source_logs 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_source_logs_source_id ON data_source_logs (source_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_source_logs_received_at ON data_source_logs (received_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_source_logs_processed ON data_source_logs (processed)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_source_logs_source_ip ON data_source_logs (source_ip)')
    
    # system_config 表索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_config_key ON system_config (key)')
    
    conn.commit()
    conn.close()
    
    print(f"数据库初始化完成，文件路径: {DB_PATH}")

def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

if __name__ == '__main__':
    init_database()
