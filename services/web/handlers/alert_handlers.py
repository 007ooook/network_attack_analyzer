"""告警、规则、策略与通知历史。"""

import json

from services.web.database import DatabaseConnection


class AlertHandlersMixin:
    def handle_get_alerts(self, query_params):
        """获取告警列表"""
        try:
            if not self.ctx.alert_manager:
                response = {'error': 'Alert manager not available'}
                self.write_json(response)
                return
        
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
            severity = query_params.get('severity', [None])[0]
            start_date = query_params.get('start_date', [None])[0]
            end_date = query_params.get('end_date', [None])[0]
        
            alerts = self.ctx.alert_manager.get_alerts(
                limit=limit,
                offset=offset,
                severity=severity,
                start_date=start_date,
                end_date=end_date
            )
        
            # 转换数字为布尔值
            for alert in alerts:
                alert['is_duplicate'] = bool(alert.get('is_duplicate', 0))
                alert['is_aggregated'] = bool(alert.get('is_aggregated', 0))
        
            response = {'alerts': alerts, 'limit': limit, 'offset': offset}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting alerts: {str(e)}"}
            self.write_json(response)
    
    def handle_get_alert_statistics(self):
        """获取告警统计信息"""
        try:
            if not self.ctx.alert_manager:
                response = {'error': 'Alert manager not available'}
                self.write_json(response)
                return
        
            statistics = self.ctx.alert_manager.get_alert_statistics()
            response = {'statistics': statistics}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting alert statistics: {str(e)}"}
            self.write_json(response)
    
    def handle_get_alert_rules(self):
        """获取所有告警规则"""
        try:
            if not self.ctx.policy_manager:
                response = {'error': 'Policy manager not available'}
                self.write_json(response)
                return
        
            rules = self.ctx.policy_manager.rule_engine.get_all_rules()
            rules_data = [{
                'rule_id': rule.rule_id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'conditions': rule.conditions,
                'actions': rule.actions
            } for rule in rules]
        
            response = {'rules': rules_data}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting alert rules: {str(e)}"}
            self.write_json(response)
    
    def handle_alert_rule_operations(self, path):
        """处理告警规则操作"""
        try:
            if not self.ctx.policy_manager:
                response = {'error': 'Policy manager not available'}
                self.write_json(response)
                return
        
            parts = path.split('/')
            if len(parts) < 4:
                self.send_error(400, "Bad Request")
                return
        
            rule_id = parts[3]
            action = parts[4] if len(parts) > 4 else None
        
            if action == 'enable':
                success = self.ctx.policy_manager.rule_engine.enable_rule(rule_id)
                response = {'success': success, 'message': f'Rule {rule_id} enabled' if success else 'Rule not found'}
            elif action == 'disable':
                success = self.ctx.policy_manager.rule_engine.disable_rule(rule_id)
                response = {'success': success, 'message': f'Rule {rule_id} disabled' if success else 'Rule not found'}
            elif action == 'delete':
                success = self.ctx.policy_manager.rule_engine.remove_rule(rule_id)
                response = {'success': success, 'message': f'Rule {rule_id} deleted' if success else 'Rule not found'}
            else:
                response = {'error': 'Invalid action'}
        
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error handling alert rule operation: {str(e)}"}
            self.write_json(response)
    
    def handle_get_alert_policies(self):
        """获取所有告警策略"""
        try:
            if not self.ctx.policy_manager:
                response = {'error': 'Policy manager not available'}
                self.write_json(response)
                return
        
            policies = self.ctx.policy_manager.get_all_policies()
            response = {'policies': policies}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting alert policies: {str(e)}"}
            self.write_json(response)
    
    def handle_alert_policy_operations(self, path):
        """处理告警策略操作"""
        try:
            if not self.ctx.policy_manager:
                response = {'error': 'Policy manager not available'}
                self.write_json(response)
                return
        
            parts = path.split('/')
            if len(parts) < 4:
                self.send_error(400, "Bad Request")
                return
        
            policy_id = parts[3]
            action = parts[4] if len(parts) > 4 else None
        
            if action == 'delete':
                success = self.ctx.policy_manager.delete_policy(policy_id)
                response = {'success': success, 'message': f'Policy {policy_id} deleted' if success else 'Policy not found'}
            else:
                response = {'error': 'Invalid action'}
        
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error handling alert policy operation: {str(e)}"}
            self.write_json(response)
    
    def handle_create_alert_rule(self, data):
        """创建告警规则"""
        try:
            if not self.ctx.policy_manager:
                response = {'error': 'Policy manager not available'}
                self.write_json(response)
                return
        
            name = data.get('name')
            description = data.get('description', '')
            severity = data.get('severity', 'Medium')
            enabled = data.get('enabled', True)
            conditions = data.get('conditions', {})
            actions = data.get('actions', [])
        
            if not name:
                response = {'error': 'Rule name is required'}
                self.write_json(response)
                return
        
            rule_id = data.get('rule_id') or self.ctx.policy_manager.rule_engine._generate_rule_id(name)
        
            from ai.models.alert_rules import AlertRule
            rule = AlertRule(
                rule_id=rule_id,
                name=name,
                description=description,
                severity=severity,
                enabled=enabled,
                conditions=conditions,
                actions=actions
            )
        
            self.ctx.policy_manager.rule_engine.add_rule(rule)
            response = {'success': True, 'rule_id': rule_id, 'message': 'Rule created successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error creating alert rule: {str(e)}"}
            self.write_json(response)
    
    def handle_update_alert_rule(self, rule_id, data):
        """更新告警规则"""
        try:
            if not self.ctx.policy_manager:
                response = {'error': 'Policy manager not available'}
                self.write_json(response)
                return
        
            name = data.get('name')
            description = data.get('description')
            severity = data.get('severity')
            enabled = data.get('enabled')
            conditions = data.get('conditions')
            actions = data.get('actions')
        
            rule = self.ctx.policy_manager.rule_engine.get_rule(rule_id)
            if not rule:
                response = {'error': 'Rule not found'}
                self.write_json(response)
                return
        
            if name:
                rule.name = name
            if description is not None:
                rule.description = description
            if severity:
                rule.severity = severity
            if enabled is not None:
                rule.enabled = enabled
            if conditions is not None:
                rule.conditions = conditions
            if actions is not None:
                rule.actions = actions
        
            self.ctx.policy_manager.rule_engine.update_rule_in_database(rule)
            response = {'success': True, 'message': 'Rule updated successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error updating alert rule: {str(e)}"}
            self.write_json(response)
    
    def handle_create_alert_policy(self, data):
        """创建告警策略"""
        try:
            if not self.ctx.policy_manager:
                response = {'error': 'Policy manager not available'}
                self.write_json(response)
                return
        
            policy_id = data.get('policy_id', f'policy_{datetime.now().timestamp()}')
            name = data.get('name')
            description = data.get('description', '')
            enabled = data.get('enabled', True)
            alert_threshold = data.get('alert_threshold', 0.5)
            dedup_window_minutes = data.get('dedup_window_minutes', 30)
            aggregation_window_minutes = data.get('aggregation_window_minutes', 5)
        
            if not name:
                response = {'error': 'Policy name is required'}
                self.write_json(response)
                return
        
            policy_config = {
                'name': name,
                'description': description,
                'enabled': enabled,
                'alert_threshold': alert_threshold,
                'dedup_window_minutes': dedup_window_minutes,
                'aggregation_window_minutes': aggregation_window_minutes
            }
        
            self.ctx.policy_manager.add_policy(policy_id, policy_config)
            response = {'success': True, 'policy_id': policy_id, 'message': 'Policy created successfully'}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error creating alert policy: {str(e)}"}
            self.write_json(response)
    
    def handle_get_notification_history(self, query_params):
        """获取通知历史"""
        try:
            if not self.ctx.notification_manager:
                response = {'error': 'Notification manager not available'}
                self.write_json(response)
                return
        
            limit = int(query_params.get('limit', [100])[0])
            offset = int(query_params.get('offset', [0])[0])
        
            history = self.ctx.notification_manager.get_notification_history(limit=limit, offset=offset)
            response = {'history': history, 'limit': limit, 'offset': offset}
            self.write_json(response)
        except Exception as e:
            response = {'error': f"Error getting notification history: {str(e)}"}
            self.write_json(response)
