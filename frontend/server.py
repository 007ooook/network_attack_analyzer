#!/usr/bin/env python3
import http.server
import socketserver
import os

PORT = 8080

class FrontendHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # 检查请求的路径是否存在
        path = self.translate_path(self.path)
        
        # 如果路径不存在，返回index.html
        if not os.path.exists(path) or os.path.isdir(path):
            self.path = '/index.html'
        
        # 调用父类的do_GET方法处理请求
        super().do_GET()

if __name__ == '__main__':
    # 切换到dist目录
    os.chdir('dist')
    
    # 创建服务器
    with socketserver.TCPServer(('', PORT), FrontendHandler) as httpd:
        print(f'Frontend server running at http://localhost:{PORT}')
        httpd.serve_forever()
