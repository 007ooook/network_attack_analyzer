"""数据源与 Webhook。"""

import json
import sqlite3
from datetime import datetime

from services.data_source_manager import DataSourceConfig
from services.web.database import DatabaseConnection


class DataSourceHandlersMixin:
    def handle_get_data_sources(self):
        """获取所有数据源列表"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            manager = self.ctx.get_data_source_manager()
        
            # 获取所有数据源
            sources = manager.get_all_data_sources()
        
            # 构建响应
            response = {
                'sources': [{ 
                    'id': s.id,
                    'name': s.name,
                    'source_type': s.source_type,
                    'enabled': s.enabled,
                    'status': s.status,
                    'created_at': s.created_at,
                    'updated_at': s.updated_at,
                    'last_error': s.last_error,
                    'last_connected_at': s.last_connected_at,
                    'last_log_received': s.last_log_received,
                    'last_source_ip': s.last_source_ip,
                    'total_logs_received': s.total_logs_received,
                    'total_logs_processed': s.total_logs_processed,
                    'recent_logs_5m': self._get_recent_logs_count(s.id, 5)  # 最近5分钟的日志数
                } for s in sources]
            }
            self.write_json(response)
        except Exception as e:
            print(f"Error getting data sources: {str(e)}")
            import traceback
            traceback.print_exc()
            response = {'error': f"Error getting data sources: {str(e)}"}
            self.write_json(response)
    
    def _get_recent_logs_count(self, source_id: int, minutes: int) -> int:
        """获取最近指定分钟内的日志数量"""
        try:
            with DatabaseConnection(self.ctx) as conn:
                cursor = conn.cursor()
                # 计算时间范围 - 使用 UTC 时间
                import datetime
                import time
            
                # 获取当前时间（UTC）- 使用 timezone-aware 对象
                end_time = datetime.datetime.now(datetime.timezone.utc)
                start_time = end_time - datetime.timedelta(minutes=minutes)
            
                # 转换为数据库使用的时间格式
                start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            
                # 查询最近指定分钟内的日志数量
                cursor.execute('''
                    SELECT COUNT(*) FROM data_source_logs 
                    WHERE source_id = ? AND received_at >= ?
                ''', (source_id, start_time_str))
            
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            print(f"Error getting recent logs count: {str(e)}")
            return 0

    def handle_get_data_source_detail(self, path):
        """获取单个数据源详情"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            parts = path.split('/')
            if len(parts) < 4:
                self.send_error(404, "Not Found")
                return
        
            source_id = int(parts[3])
            manager = self.ctx.get_data_source_manager()
            source = manager.get_data_source(source_id)
        
            if not source:
                response = {'error': 'Data source not found'}
                self.write_json(response)
                return
        
            response = {
                'source': {
                    'id': source.id,
                    'name': source.name,
                    'source_type': source.source_type,
                    'enabled': source.enabled,
                    'status': source.status,
                    # Syslog配置
                    'syslog_host': source.syslog_host,
                    'syslog_port': source.syslog_port,
                    'syslog_protocol': source.syslog_protocol,
                    # 文件配置
                    'file_path': source.file_path,
                    'file_format': source.file_format,
                    'file_encoding': source.file_encoding,
                    'file_poll_interval': source.file_poll_interval,
                    # API配置
                    'api_url': source.api_url,
                    'api_method': source.api_method,
                    'api_headers': source.api_headers,
                    'api_auth_type': source.api_auth_type,
                    'api_poll_interval': source.api_poll_interval,
                    # Webhook配置
                    'webhook_secret': source.webhook_secret,
                    'webhook_verify_signature': source.webhook_verify_signature,
                    # 通用配置
                    'log_format': source.log_format,
                    'log_pattern': source.log_pattern,
                    'field_mapping': source.field_mapping,
                    'filters': source.filters,
                    'created_at': source.created_at,
                    'updated_at': source.updated_at,
                    'last_error': source.last_error,
                    'last_connected_at': source.last_connected_at,
                    'total_logs_received': source.total_logs_received,
                    'total_logs_processed': source.total_logs_processed
                }
            }
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting data source: {str(e)}"}
            self.write_json(response)

    def handle_create_data_source(self, data):
        """创建数据源"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            config = DataSourceConfig(
                name=data.get('name', ''),
                source_type=data.get('source_type', ''),
                enabled=data.get('enabled', True),
                # Syslog配置
                syslog_host=data.get('syslog_host', '1.1.1.155'),
                syslog_port=data.get('syslog_port', 1514),
                syslog_protocol=data.get('syslog_protocol', 'udp'),
                # 文件配置
                file_path=data.get('file_path', ''),
                file_format=data.get('file_format', 'auto'),
                file_encoding=data.get('file_encoding', 'utf-8'),
                file_poll_interval=data.get('file_poll_interval', 5),
                # API配置
                api_url=data.get('api_url', ''),
                api_method=data.get('api_method', 'GET'),
                api_headers=json.dumps(data.get('api_headers', {})),
                api_auth_type=data.get('api_auth_type', 'none'),
                api_auth_config=json.dumps(data.get('api_auth_config', {})),
                api_poll_interval=data.get('api_poll_interval', 60),
                # Webhook配置
                webhook_secret=data.get('webhook_secret', ''),
                webhook_verify_signature=data.get('webhook_verify_signature', False),
                # 通用配置
                log_format=data.get('log_format', 'auto'),
                log_pattern=data.get('log_pattern', ''),
                field_mapping=json.dumps(data.get('field_mapping', {})),
                filters=json.dumps(data.get('filters', {}))
            )
        
            manager = self.ctx.get_data_source_manager()
            source_id = manager.create_data_source(config)
        
            response = {'success': True, 'id': source_id, 'message': 'Data source created successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error creating data source: {str(e)}"}
            self.write_json(response)

    def handle_update_data_source(self, source_id, data):
        """更新数据源"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            source_id = int(source_id)
            manager = self.ctx.get_data_source_manager()
        
            existing = manager.get_data_source(source_id)
            if not existing:
                response = {'error': 'Data source not found'}
                self.write_json(response)
                return
        
            config = DataSourceConfig(
                id=source_id,
                name=data.get('name', existing.name),
                source_type=data.get('source_type', existing.source_type),
                enabled=data.get('enabled', existing.enabled),
                status=existing.status,
                # Syslog配置
                syslog_host=data.get('syslog_host', existing.syslog_host),
                syslog_port=data.get('syslog_port', existing.syslog_port),
                syslog_protocol=data.get('syslog_protocol', existing.syslog_protocol),
                # 文件配置
                file_path=data.get('file_path', existing.file_path),
                file_format=data.get('file_format', existing.file_format),
                file_encoding=data.get('file_encoding', existing.file_encoding),
                file_poll_interval=data.get('file_poll_interval', existing.file_poll_interval),
                # API配置
                api_url=data.get('api_url', existing.api_url),
                api_method=data.get('api_method', existing.api_method),
                api_headers=json.dumps(data.get('api_headers', {})) if 'api_headers' in data else existing.api_headers,
                api_auth_type=data.get('api_auth_type', existing.api_auth_type),
                api_auth_config=json.dumps(data.get('api_auth_config', {})) if 'api_auth_config' in data else existing.api_auth_config,
                api_poll_interval=data.get('api_poll_interval', existing.api_poll_interval),
                # Webhook配置
                webhook_secret=data.get('webhook_secret', existing.webhook_secret),
                webhook_verify_signature=data.get('webhook_verify_signature', existing.webhook_verify_signature),
                # 通用配置
                log_format=data.get('log_format', existing.log_format),
                log_pattern=data.get('log_pattern', existing.log_pattern),
                field_mapping=json.dumps(data.get('field_mapping', {})) if 'field_mapping' in data else existing.field_mapping,
                filters=json.dumps(data.get('filters', {})) if 'filters' in data else existing.filters
            )
        
            success = manager.update_data_source(source_id, config)
        
            response = {'success': success, 'message': 'Data source updated successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error updating data source: {str(e)}"}
            self.write_json(response)

    def handle_start_data_source(self, source_id):
        """启动数据源"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            source_id = int(source_id)
            manager = self.ctx.get_data_source_manager()
            success = manager.start_data_source(source_id)
        
            if success:
                response = {'success': True, 'message': 'Data source started successfully'}
            else:
                # 获取数据源状态，查看具体错误信息
                source = manager.get_data_source(source_id)
                error_message = source.last_error if source and source.last_error else 'Failed to start data source'
                response = {'success': False, 'error': error_message}
        
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error starting data source: {str(e)}"}
            self.write_json(response)

    def handle_stop_data_source(self, source_id):
        """停止数据源"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            source_id = int(source_id)
            manager = self.ctx.get_data_source_manager()
            success = manager.stop_data_source(source_id)
        
            response = {'success': success, 'message': 'Data source stopped successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error stopping data source: {str(e)}"}
            self.write_json(response)

    def handle_test_data_source(self, source_id, data):
        """测试数据源连接"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            source_id = int(source_id)
            manager = self.ctx.get_data_source_manager()
            config = manager.get_data_source(source_id)
        
            if not config:
                response = {'error': 'Data source not found'}
                self.write_json(response)
                return
        
            # 使用重构后的测试方法
            test_result = manager.test_data_source_connection(config)
        
            response = test_result
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error testing data source: {str(e)}"}
            self.write_json(response)

    def handle_get_data_source_logs(self, query_params):
        """获取数据源接收的日志"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            source_id = query_params.get('source_id', [None])[0]
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
        
            # 获取筛选参数
            start_time = query_params.get('start_time', [None])[0]
            end_time = query_params.get('end_time', [None])[0]
            processed = query_params.get('processed', [None])[0]
            has_error = query_params.get('has_error', [None])[0]
            keyword = query_params.get('keyword', [None])[0]
            ip = query_params.get('ip', [None])[0]
        
            try:
                # 使用 DatabaseConnection 上下文管理器获取数据库连接
                with DatabaseConnection(self.ctx) as conn:
                    cursor = conn.cursor()
                
                    # 构建查询条件
                    where_conditions = []
                    sql_params = []
                
                    if source_id:
                        where_conditions.append('source_id = ?')
                        sql_params.append(source_id)
                
                    if start_time:
                        where_conditions.append('received_at >= ?')
                        sql_params.append(start_time)
                
                    if end_time:
                        where_conditions.append('received_at <= ?')
                        sql_params.append(end_time)
                
                    if processed is not None:
                        processed_bool = processed.lower() == 'true'
                        where_conditions.append('processed = ?')
                        sql_params.append(processed_bool)
                
                    if has_error is not None:
                        has_error_bool = has_error.lower() == 'true'
                        if has_error_bool:
                            where_conditions.append('(error_message IS NOT NULL AND error_message != "")')
                        else:
                            where_conditions.append('(error_message IS NULL OR error_message = "")')
                
                    if keyword:
                        where_conditions.append('raw_log LIKE ?')
                        sql_params.append(f'%{keyword}%')
                
                    if ip:
                        where_conditions.append('(raw_log LIKE ? OR source_ip LIKE ?)')
                        sql_params.append(f'%{ip}%')
                        sql_params.append(f'%{ip}%')
                
                    # 构建 WHERE 子句
                    where_clause = 'WHERE ' + ' AND '.join(where_conditions) if where_conditions else ''
                
                    # 获取总日志数
                    count_query = f'SELECT COUNT(*) FROM data_source_logs {where_clause}'
                    cursor.execute(count_query, sql_params)
                    total_logs = cursor.fetchone()[0]
                
                    # 获取日志数据
                    data_query = f'SELECT * FROM data_source_logs {where_clause} ORDER BY received_at DESC LIMIT ? OFFSET ?'
                    cursor.execute(data_query, sql_params + [limit, offset])
                
                    logs = []
                    for row in cursor.fetchall():
                        logs.append({
                            'id': row['id'],
                            'source_id': row['source_id'],
                            'raw_log': row['raw_log'],
                            'parsed_log': json.loads(row['parsed_log']) if row['parsed_log'] else {},
                            'received_at': row['received_at'],
                            'processed': bool(row['processed']),
                            'error_message': row['error_message'],
                            'source_ip': row['source_ip'] if 'source_ip' in row.keys() else ''
                        })
                
                    response = {'logs': logs, 'limit': limit, 'offset': offset, 'total': total_logs}
                    self.write_json(response)
            except Exception as e:
                response = {'error': f"Error getting data source logs: {str(e)}"}
                self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting data source logs: {str(e)}"}
            self.write_json(response)

    def handle_delete_data_source(self, source_id):
        """删除数据源"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            try:
                conn = self.ctx.get_db_connection()
            except NameError:
                response = {'error': 'Database connection not available'}
                self.write_json(response)
                return
        
            cursor = conn.cursor()
        
            # 开始事务
            conn.execute('BEGIN TRANSACTION')
        
            try:
                # 删除相关的日志记录
                cursor.execute('DELETE FROM data_source_logs WHERE source_id = ?', (source_id,))
            
                # 删除数据源记录
                cursor.execute('DELETE FROM data_sources WHERE id = ?', (source_id,))
            
                # 提交事务
                conn.execute('COMMIT')
            
                response = {'success': True, 'message': 'Data source deleted successfully'}
                self.write_json(response)
            except Exception as e:
                # 回滚事务
                conn.execute('ROLLBACK')
                response = {'error': f"Error deleting data source: {str(e)}"}
                self.write_json(response)
            finally:
                conn.close()
        except Exception as e:
            response = {'error': f"Error deleting data source: {str(e)}"}
            self.write_json(response)

    def handle_webhook_logs(self, data):
        """接收Webhook日志"""
        try:
            if not self.ctx.data_source_available:
                response = {'error': 'Data source manager not available'}
                self.write_json(response)
                return
        
            # 从请求头中获取数据源标识
            source_name = self.headers.get('X-Data-Source', 'webhook')
        
            # 查找或创建Webhook数据源
            manager = self.ctx.get_data_source_manager()
            sources = manager.get_all_data_sources()
        
            webhook_source = None
            for s in sources:
                if s.source_type == 'webhook' and s.name == source_name:
                    webhook_source = s
                    break
        
            if not webhook_source:
                # 自动创建Webhook数据源
                config = DataSourceConfig(
                    name=source_name,
                    source_type='webhook',
                    enabled=True
                )
                source_id = manager.create_data_source(config)
            else:
                source_id = webhook_source.id
        
            # 处理接收到的日志
            if isinstance(data, str):
                # 如果 data 是字符串，直接使用它作为原始日志
                log_data = {
                    'raw': data,
                    'source': 'webhook',
                    'received_at': datetime.now().isoformat()
                }
            else:
                # 如果 data 是字典，将其转换为 JSON 字符串
                log_data = {
                    'raw': json.dumps(data),
                    'parsed': data,
                    'source': 'webhook',
                    'received_at': datetime.now().isoformat()
                }
        
            manager._on_log_received(source_id, log_data)
        
            response = {'success': True, 'message': 'Log received'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error processing webhook: {str(e)}"}
            self.write_json(response)
