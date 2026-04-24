"""认证相关API处理器"""

import json
from services.auth import auth_manager


class AuthHandlersMixin:
    """认证处理器混入类"""
    
    def handle_login(self, data):
        """处理登录请求"""
        try:
            username = data.get('username', '')
            password = data.get('password', '')
            
            if not username or not password:
                self.write_json({'error': '用户名和密码不能为空'})
                return
            
            lock_info = auth_manager.get_account_lock_info(username)
            if lock_info.get('locked'):
                remaining = lock_info.get('remaining_seconds', 0)
                self.write_json({
                    'error': f'账户已被锁定，请在{remaining // 60}分钟后重试',
                    'locked': True,
                    'remaining_seconds': remaining
                })
                return
            
            token = auth_manager.authenticate(username, password)
            if token:
                self.write_json({
                    'success': True,
                    'token': token,
                    'message': '登录成功'
                })
            else:
                attempts = auth_manager.login_attempts.get(username, 0)
                remaining = auth_manager.config.max_login_attempts - attempts
                self.write_json({
                    'error': f'用户名或密码错误',
                    'remaining_attempts': max(0, remaining)
                })
        except Exception as e:
            self.write_json({'error': f'登录失败: {str(e)}'})
    
    def handle_logout(self, data):
        """处理登出请求"""
        try:
            token = data.get('token', '')
            auth_manager.logout(token)
            self.write_json({'success': True, 'message': '登出成功'})
        except Exception as e:
            self.write_json({'error': f'登出失败: {str(e)}'})
    
    def handle_change_password(self, data):
        """处理修改密码请求"""
        try:
            username = data.get('username', '')
            old_password = data.get('old_password', '')
            new_password = data.get('new_password', '')
            
            if not all([username, old_password, new_password]):
                self.write_json({'error': '所有字段都不能为空'})
                return
            
            result = auth_manager.change_password(username, old_password, new_password)
            if result['success']:
                self.write_json({'success': True, 'message': '密码修改成功'})
            else:
                self.write_json({'error': result.get('error', '修改密码失败'), 'details': result.get('details', [])})
        except Exception as e:
            self.write_json({'error': f'修改密码失败: {str(e)}'})
    
    def handle_get_current_user(self):
        """获取当前用户信息"""
        try:
            token = self.headers.get('Authorization', '').replace('Bearer ', '')
            payload = auth_manager.verify_token(token)
            
            if payload:
                self.write_json({
                    'success': True,
                    'user': {
                        'username': payload['sub'],
                        'role': payload['role']
                    }
                })
            else:
                self.write_json({'error': '未授权'}, status_code=401)
        except Exception as e:
            self.write_json({'error': f'获取用户信息失败: {str(e)}'})
    
    def handle_get_security_config(self):
        """获取账号安全配置"""
        try:
            config_data = auth_manager.get_security_config()
            self.write_json({'success': True, 'config': config_data})
        except Exception as e:
            self.write_json({'error': f'获取配置失败: {str(e)}'})
    
    def handle_update_security_config(self, data):
        """更新账号安全配置"""
        try:
            auth_manager.update_security_config(data)
            self.write_json({'success': True, 'message': '配置已更新'})
        except Exception as e:
            self.write_json({'error': f'更新配置失败: {str(e)}'})
