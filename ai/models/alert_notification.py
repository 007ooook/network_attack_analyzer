import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import json
import os
import requests
import threading
import time

class AlertNotificationChannel:
    """告警通知渠道基类"""
    
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
    
    def send(self, alert: Dict[str, Any]) -> bool:
        """发送告警通知"""
        raise NotImplementedError
    
    def is_enabled(self) -> bool:
        """检查通知渠道是否启用"""
        return self.enabled


class EmailNotificationChannel(AlertNotificationChannel):
    """邮件通知渠道"""
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        from_email: str,
        to_emails: List[str],
        enabled: bool = True
    ):
        super().__init__('Email', enabled)
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.to_emails = to_emails
    
    def send(self, alert: Dict[str, Any]) -> bool:
        """发送邮件通知"""
        if not self.is_enabled():
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"[安全告警] {alert.get('severity', 'Medium')} - {alert.get('attack_type', 'Unknown')}"
            
            body = f"""
            告警详情：
            
            告警类型：{alert.get('alert_type', 'Security Alert')}
            攻击类型：{alert.get('attack_type', 'Unknown')}
            严重程度：{alert.get('severity', 'Medium')}
            源IP：{alert.get('source_ip', 'Unknown')}
            置信度：{alert.get('confidence', 0):.2%}
            描述：{alert.get('description', '')}
            
            时间：{alert.get('created_at', datetime.now().isoformat())}
            
            请及时处理此告警。
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
                server.quit()
            
            print(f"邮件通知发送成功: {alert.get('attack_type')}")
            return True
        except Exception as e:
            print(f"邮件通知发送失败: {e}")
            return False


class WebhookNotificationChannel(AlertNotificationChannel):
    """Webhook通知渠道"""
    
    def __init__(
        self,
        webhook_url: str,
        headers: Optional[Dict[str, str]] = None,
        enabled: bool = True
    ):
        super().__init__('Webhook', enabled)
        self.webhook_url = webhook_url
        self.headers = headers or {'Content-Type': 'application/json'}
    
    def send(self, alert: Dict[str, Any]) -> bool:
        """发送Webhook通知"""
        if not self.is_enabled():
            return False
        
        try:
            payload = {
                'alert_id': alert.get('id'),
                'alert_type': alert.get('alert_type'),
                'attack_type': alert.get('attack_type'),
                'severity': alert.get('severity'),
                'source_ip': alert.get('source_ip'),
                'confidence': alert.get('confidence'),
                'description': alert.get('description'),
                'timestamp': alert.get('created_at')
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"Webhook通知发送成功: {alert.get('attack_type')}")
                return True
            else:
                print(f"Webhook通知发送失败: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"Webhook通知发送失败: {e}")
            return False


class SlackNotificationChannel(AlertNotificationChannel):
    """Slack通知渠道"""
    
    def __init__(
        self,
        webhook_url: str,
        channel: str = '#alerts',
        username: str = 'Security Bot',
        enabled: bool = True
    ):
        super().__init__('Slack', enabled)
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
    
    def send(self, alert: Dict[str, Any]) -> bool:
        """发送Slack通知"""
        if not self.is_enabled():
            return False
        
        try:
            color_map = {
                'Critical': 'danger',
                'High': 'warning',
                'Medium': 'warning',
                'Low': 'good',
                'Info': '#36a64f'
            }
            
            color = color_map.get(alert.get('severity', 'Medium'), 'warning')
            
            payload = {
                'channel': self.channel,
                'username': self.username,
                'attachments': [{
                    'color': color,
                    'title': f"安全告警: {alert.get('attack_type', 'Unknown')}",
                    'fields': [
                        {
                            'title': '严重程度',
                            'value': alert.get('severity', 'Medium'),
                            'short': True
                        },
                        {
                            'title': '源IP',
                            'value': alert.get('source_ip', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': '置信度',
                            'value': f"{alert.get('confidence', 0):.2%}",
                            'short': True
                        },
                        {
                            'title': '描述',
                            'value': alert.get('description', ''),
                            'short': False
                        }
                    ],
                    'footer': f"时间: {alert.get('created_at', datetime.now().isoformat())}",
                    'ts': int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                print(f"Slack通知发送成功: {alert.get('attack_type')}")
                return True
            else:
                print(f"Slack通知发送失败: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"Slack通知发送失败: {e}")
            return False


class AlertResponseAction:
    """告警响应动作基类"""
    
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
    
    def execute(self, alert: Dict[str, Any]) -> bool:
        """执行响应动作"""
        raise NotImplementedError
    
    def is_enabled(self) -> bool:
        """检查响应动作是否启用"""
        return self.enabled


class IPBlockAction(AlertResponseAction):
    """IP封禁响应动作"""
    
    def __init__(self, enabled: bool = True, block_duration_hours: int = 24):
        super().__init__('IP Block', enabled)
        self.block_duration_hours = block_duration_hours
        self.blocked_ips = set()
    
    def execute(self, alert: Dict[str, Any]) -> bool:
        """执行IP封禁动作"""
        if not self.is_enabled():
            return False
        
        source_ip = alert.get('source_ip')
        if not source_ip:
            return False
        
        try:
            # 这里可以集成防火墙API或系统命令来实际封禁IP
            # 示例：调用系统命令
            # os.system(f"iptables -A INPUT -s {source_ip} -j DROP")
            
            self.blocked_ips.add(source_ip)
            print(f"已封禁IP: {source_ip}，持续{self.block_duration_hours}小时")
            return True
        except Exception as e:
            print(f"IP封禁失败: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """解封IP"""
        if ip in self.blocked_ips:
            try:
                # 这里可以集成防火墙API或系统命令来解封IP
                # os.system(f"iptables -D INPUT -s {ip} -j DROP")
                
                self.blocked_ips.remove(ip)
                print(f"已解封IP: {ip}")
                return True
            except Exception as e:
                print(f"IP解封失败: {e}")
                return False
        return False


class LogDetailedAction(AlertResponseAction):
    """详细日志记录响应动作"""
    
    def __init__(self, log_file: str, enabled: bool = True):
        super().__init__('Log Detailed', enabled)
        self.log_file = log_file
    
    def execute(self, alert: Dict[str, Any]) -> bool:
        """执行详细日志记录动作"""
        if not self.is_enabled():
            return False
        
        try:
            log_entry = f"""
            [{datetime.now().isoformat()}] 详细告警日志:
            告警ID: {alert.get('id')}
            告警类型: {alert.get('alert_type')}
            攻击类型: {alert.get('attack_type')}
            严重程度: {alert.get('severity')}
            源IP: {alert.get('source_ip')}
            置信度: {alert.get('confidence')}
            描述: {alert.get('description')}
            匹配规则: {alert.get('matched_rules', [])}
            """
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            
            print(f"详细日志记录成功: {alert.get('attack_type')}")
            return True
        except Exception as e:
            print(f"详细日志记录失败: {e}")
            return False


class AlertNotificationManager:
    """告警通知管理器"""
    
    def __init__(self):
        self.notification_channels: List[AlertNotificationChannel] = []
        self.response_actions: List[AlertResponseAction] = []
        self.notification_history: List[Dict[str, Any]] = []
        self.notification_queue = []
        self.worker_thread = None
        self.running = False
    
    def add_notification_channel(self, channel: AlertNotificationChannel) -> None:
        """添加通知渠道"""
        self.notification_channels.append(channel)
        print(f"添加通知渠道: {channel.name}")
    
    def add_response_action(self, action: AlertResponseAction) -> None:
        """添加响应动作"""
        self.response_actions.append(action)
        print(f"添加响应动作: {action.name}")
    
    def remove_notification_channel(self, channel_name: str) -> bool:
        """移除通知渠道"""
        for i, channel in enumerate(self.notification_channels):
            if channel.name == channel_name:
                del self.notification_channels[i]
                print(f"移除通知渠道: {channel_name}")
                return True
        return False
    
    def remove_response_action(self, action_name: str) -> bool:
        """移除响应动作"""
        for i, action in enumerate(self.response_actions):
            if action.name == action_name:
                del self.response_actions[i]
                print(f"移除响应动作: {action_name}")
                return True
        return False
    
    def send_notification(self, alert: Dict[str, Any]) -> Dict[str, bool]:
        """发送告警通知"""
        results = {}
        
        for channel in self.notification_channels:
            if channel.is_enabled():
                success = channel.send(alert)
                results[channel.name] = success
        
        # 记录通知历史
        self.notification_history.append({
            'alert_id': alert.get('id'),
            'timestamp': datetime.now().isoformat(),
            'channels': results,
            'alert': alert
        })
        
        return results
    
    def execute_response_actions(self, alert: Dict[str, Any]) -> Dict[str, bool]:
        """执行响应动作"""
        results = {}
        
        for action in self.response_actions:
            if action.is_enabled():
                success = action.execute(alert)
                results[action.name] = success
        
        return results
    
    def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """处理告警，包括通知和响应动作"""
        notification_results = self.send_notification(alert)
        response_results = self.execute_response_actions(alert)
        
        return {
            'notification_results': notification_results,
            'response_results': response_results,
            'alert': alert
        }
    
    def start_background_worker(self) -> None:
        """启动后台工作线程"""
        if self.worker_thread is None or not self.worker_thread.is_alive():
            self.running = True
            self.worker_thread = threading.Thread(target=self._background_worker, daemon=True)
            self.worker_thread.start()
            print("告警通知后台工作线程已启动")
    
    def stop_background_worker(self) -> None:
        """停止后台工作线程"""
        self.running = False
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)
            print("告警通知后台工作线程已停止")
    
    def _background_worker(self) -> None:
        """后台工作线程"""
        while self.running:
            if self.notification_queue:
                alert = self.notification_queue.pop(0)
                try:
                    self.process_alert(alert)
                except Exception as e:
                    print(f"处理告警时出错: {e}")
            
            time.sleep(1)
    
    def queue_alert(self, alert: Dict[str, Any]) -> None:
        """将告警加入处理队列"""
        self.notification_queue.append(alert)
        
        if not self.worker_thread or not self.worker_thread.is_alive():
            self.start_background_worker()
    
    def get_notification_history(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """获取通知历史"""
        return self.notification_history[offset:offset + limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取通知统计信息"""
        total_notifications = len(self.notification_history)
        channel_stats = {}
        
        for history in self.notification_history:
            for channel, success in history['channels'].items():
                if channel not in channel_stats:
                    channel_stats[channel] = {'total': 0, 'success': 0, 'failed': 0}
                
                channel_stats[channel]['total'] += 1
                if success:
                    channel_stats[channel]['success'] += 1
                else:
                    channel_stats[channel]['failed'] += 1
        
        return {
            'total_notifications': total_notifications,
            'channel_statistics': channel_stats,
            'active_channels': len([c for c in self.notification_channels if c.is_enabled()]),
            'active_actions': len([a for a in self.response_actions if a.is_enabled()])
        }