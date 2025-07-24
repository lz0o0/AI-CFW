"""
透明代理 - 负责透明拦截和处理网络流量
"""

import socket
import threading
import logging
import time
import select
from typing import Dict, Any, Optional, Tuple, List
import struct


class TransparentProxy:
    """透明代理主类"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化透明代理
        
        Args:
            config: 配置字典
        """
        self.config = config
        self.logger = logging.getLogger('TransparentProxy')
        
        # 代理配置
        self.firewall_config = config.get('firewall', {})
        self.proxy_port = self.firewall_config.get('port', 8080)
        self.ssl_port = self.firewall_config.get('ssl_port', 8443)
        self.interface = self.firewall_config.get('interface', 'any')
        
        # 运行状态
        self.is_running = False
        self.proxy_socket = None
        self.ssl_socket = None
        
        # 连接管理
        self.active_connections = {}
        self.connection_count = 0
        self.max_connections = 1000
        
        # 统计信息
        self.stats = {
            'connections_total': 0,
            'connections_active': 0,
            'bytes_transferred': 0,
            'errors': 0,
            'start_time': None
        }
        
        # 处理线程
        self.worker_threads = []
        self.stop_event = threading.Event()
        
        self.logger.info("透明代理初始化完成")
    
    def start(self) -> bool:
        """
        启动透明代理
        
        Returns:
            bool: 启动是否成功
        """
        if self.is_running:
            self.logger.warning("透明代理已在运行")
            return False
        
        try:
            self.logger.info(f"启动透明代理，端口: {self.proxy_port}, SSL端口: {self.ssl_port}")
            
            # 重置停止事件
            self.stop_event.clear()
            
            # 启动HTTP代理
            if not self._start_http_proxy():
                self.logger.error("HTTP代理启动失败")
                return False
            
            # 启动HTTPS代理
            if not self._start_https_proxy():
                self.logger.error("HTTPS代理启动失败")
                self.stop()
                return False
            
            self.is_running = True
            self.stats['start_time'] = time.time()
            
            self.logger.info("透明代理启动成功")
            return True
            
        except Exception as e:
            self.logger.error(f"透明代理启动失败: {e}")
            return False
    
    def stop(self) -> bool:
        """
        停止透明代理
        
        Returns:
            bool: 停止是否成功
        """
        if not self.is_running:
            self.logger.warning("透明代理未在运行")
            return False
        
        try:
            self.logger.info("停止透明代理")
            
            # 设置停止事件
            self.stop_event.set()
            
            # 关闭监听socket
            if self.proxy_socket:
                self.proxy_socket.close()
                self.proxy_socket = None
            
            if self.ssl_socket:
                self.ssl_socket.close()
                self.ssl_socket = None
            
            # 关闭所有活动连接
            for conn_id, conn_info in list(self.active_connections.items()):
                try:
                    if 'client_socket' in conn_info:
                        conn_info['client_socket'].close()
                    if 'server_socket' in conn_info:
                        conn_info['server_socket'].close()
                except Exception:
                    pass
            
            self.active_connections.clear()
            
            # 等待工作线程结束
            for thread in self.worker_threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            
            self.worker_threads.clear()
            self.is_running = False
            
            self.logger.info("透明代理已停止")
            return True
            
        except Exception as e:
            self.logger.error(f"透明代理停止失败: {e}")
            return False
    
    def _start_http_proxy(self) -> bool:
        """启动HTTP代理服务器"""
        try:
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # 绑定到指定端口
            bind_address = '0.0.0.0' if self.interface == 'any' else self.interface
            self.proxy_socket.bind((bind_address, self.proxy_port))
            self.proxy_socket.listen(100)
            
            # 启动HTTP处理线程
            http_thread = threading.Thread(
                target=self._http_proxy_loop,
                name="HTTPProxyServer"
            )
            http_thread.daemon = True
            http_thread.start()
            self.worker_threads.append(http_thread)
            
            self.logger.info(f"HTTP代理服务器启动成功，监听 {bind_address}:{self.proxy_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"HTTP代理服务器启动失败: {e}")
            return False
    
    def _start_https_proxy(self) -> bool:
        """启动HTTPS代理服务器"""
        try:
            self.ssl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssl_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # 绑定到指定端口
            bind_address = '0.0.0.0' if self.interface == 'any' else self.interface
            self.ssl_socket.bind((bind_address, self.ssl_port))
            self.ssl_socket.listen(100)
            
            # 启动HTTPS处理线程
            https_thread = threading.Thread(
                target=self._https_proxy_loop,
                name="HTTPSProxyServer"
            )
            https_thread.daemon = True
            https_thread.start()
            self.worker_threads.append(https_thread)
            
            self.logger.info(f"HTTPS代理服务器启动成功，监听 {bind_address}:{self.ssl_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"HTTPS代理服务器启动失败: {e}")
            return False
    
    def _http_proxy_loop(self):
        """HTTP代理主循环"""
        self.logger.info("HTTP代理循环开始")
        
        while not self.stop_event.is_set():
            try:
                # 设置超时以便能响应停止事件
                self.proxy_socket.settimeout(1.0)
                
                try:
                    client_socket, client_address = self.proxy_socket.accept()
                    self.logger.debug(f"接收到HTTP连接: {client_address}")
                    
                    # 检查连接数限制
                    if len(self.active_connections) >= self.max_connections:
                        self.logger.warning("达到最大连接数限制")
                        client_socket.close()
                        continue
                    
                    # 处理连接
                    self._handle_http_connection(client_socket, client_address)
                    
                except socket.timeout:
                    continue  # 超时，继续循环检查停止事件
                except socket.error as e:
                    if not self.stop_event.is_set():
                        self.logger.error(f"HTTP代理socket错误: {e}")
                    break
                
            except Exception as e:
                self.logger.error(f"HTTP代理循环错误: {e}")
                self.stats['errors'] += 1
                time.sleep(0.1)
        
        self.logger.info("HTTP代理循环结束")
    
    def _https_proxy_loop(self):
        """HTTPS代理主循环"""
        self.logger.info("HTTPS代理循环开始")
        
        while not self.stop_event.is_set():
            try:
                # 设置超时以便能响应停止事件
                self.ssl_socket.settimeout(1.0)
                
                try:
                    client_socket, client_address = self.ssl_socket.accept()
                    self.logger.debug(f"接收到HTTPS连接: {client_address}")
                    
                    # 检查连接数限制
                    if len(self.active_connections) >= self.max_connections:
                        self.logger.warning("达到最大连接数限制")
                        client_socket.close()
                        continue
                    
                    # 处理连接
                    self._handle_https_connection(client_socket, client_address)
                    
                except socket.timeout:
                    continue  # 超时，继续循环检查停止事件
                except socket.error as e:
                    if not self.stop_event.is_set():
                        self.logger.error(f"HTTPS代理socket错误: {e}")
                    break
                
            except Exception as e:
                self.logger.error(f"HTTPS代理循环错误: {e}")
                self.stats['errors'] += 1
                time.sleep(0.1)
        
        self.logger.info("HTTPS代理循环结束")
    
    def _handle_http_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """处理HTTP连接"""
        conn_id = self._generate_connection_id()
        
        try:
            # 记录连接
            self.active_connections[conn_id] = {
                'client_socket': client_socket,
                'client_address': client_address,
                'protocol': 'HTTP',
                'start_time': time.time()
            }
            
            self.stats['connections_total'] += 1
            self.stats['connections_active'] = len(self.active_connections)
            
            # 启动连接处理线程
            thread = threading.Thread(
                target=self._process_http_connection,
                args=(conn_id, client_socket, client_address),
                name=f"HTTPConn-{conn_id}"
            )
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)
            
        except Exception as e:
            self.logger.error(f"处理HTTP连接失败: {e}")
            self._cleanup_connection(conn_id)
    
    def _handle_https_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """处理HTTPS连接"""
        conn_id = self._generate_connection_id()
        
        try:
            # 记录连接
            self.active_connections[conn_id] = {
                'client_socket': client_socket,
                'client_address': client_address,
                'protocol': 'HTTPS',
                'start_time': time.time()
            }
            
            self.stats['connections_total'] += 1
            self.stats['connections_active'] = len(self.active_connections)
            
            # 启动连接处理线程
            thread = threading.Thread(
                target=self._process_https_connection,
                args=(conn_id, client_socket, client_address),
                name=f"HTTPSConn-{conn_id}"
            )
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)
            
        except Exception as e:
            self.logger.error(f"处理HTTPS连接失败: {e}")
            self._cleanup_connection(conn_id)
    
    def _process_http_connection(self, conn_id: str, client_socket: socket.socket, client_address: Tuple[str, int]):
        """处理HTTP连接数据"""
        try:
            # 设置socket超时
            client_socket.settimeout(30.0)
            
            while not self.stop_event.is_set():
                # 接收客户端数据
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    self.stats['bytes_transferred'] += len(data)
                    
                    # 解析HTTP请求
                    request_info = self._parse_http_request(data)
                    if not request_info:
                        break
                    
                    # 建立到目标服务器的连接
                    server_socket = self._connect_to_server(
                        request_info['host'], 
                        request_info.get('port', 80)
                    )
                    
                    if not server_socket:
                        break
                    
                    # 更新连接信息
                    self.active_connections[conn_id]['server_socket'] = server_socket
                    self.active_connections[conn_id]['target_host'] = request_info['host']
                    
                    # 转发数据
                    server_socket.send(data)
                    
                    # 开始双向数据转发
                    self._relay_data(client_socket, server_socket, conn_id)
                    break
                    
                except socket.timeout:
                    continue
                except socket.error:
                    break
            
        except Exception as e:
            self.logger.error(f"HTTP连接处理错误: {e}")
            self.stats['errors'] += 1
        finally:
            self._cleanup_connection(conn_id)
    
    def _process_https_connection(self, conn_id: str, client_socket: socket.socket, client_address: Tuple[str, int]):
        """处理HTTPS连接数据"""
        try:
            # 设置socket超时
            client_socket.settimeout(30.0)
            
            # 接收CONNECT请求
            data = client_socket.recv(4096)
            if not data:
                return
            
            # 解析CONNECT请求
            connect_info = self._parse_connect_request(data)
            if not connect_info:
                # 发送错误响应
                response = b"HTTP/1.1 400 Bad Request\r\n\r\n"
                client_socket.send(response)
                return
            
            # 建立到目标服务器的连接
            server_socket = self._connect_to_server(
                connect_info['host'], 
                connect_info.get('port', 443)
            )
            
            if not server_socket:
                # 发送连接失败响应
                response = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                client_socket.send(response)
                return
            
            # 发送连接成功响应
            response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            client_socket.send(response)
            
            # 更新连接信息
            self.active_connections[conn_id]['server_socket'] = server_socket
            self.active_connections[conn_id]['target_host'] = connect_info['host']
            
            # 开始SSL数据转发
            self._relay_ssl_data(client_socket, server_socket, conn_id)
            
        except Exception as e:
            self.logger.error(f"HTTPS连接处理错误: {e}")
            self.stats['errors'] += 1
        finally:
            self._cleanup_connection(conn_id)
    
    def _parse_http_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """解析HTTP请求"""
        try:
            request_lines = data.decode('utf-8', errors='ignore').split('\r\n')
            if not request_lines:
                return None
            
            # 解析请求行
            request_line = request_lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
            
            method, url, version = parts[0], parts[1], parts[2]
            
            # 解析Host头
            host = None
            port = 80
            
            for line in request_lines[1:]:
                if line.lower().startswith('host:'):
                    host_value = line[5:].strip()
                    if ':' in host_value:
                        host, port_str = host_value.split(':', 1)
                        port = int(port_str)
                    else:
                        host = host_value
                    break
            
            if not host:
                return None
            
            return {
                'method': method,
                'url': url,
                'version': version,
                'host': host,
                'port': port
            }
            
        except Exception as e:
            self.logger.error(f"解析HTTP请求失败: {e}")
            return None
    
    def _parse_connect_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """解析CONNECT请求"""
        try:
            request_line = data.decode('utf-8', errors='ignore').split('\r\n')[0]
            parts = request_line.split(' ')
            
            if len(parts) < 2 or parts[0].upper() != 'CONNECT':
                return None
            
            host_port = parts[1]
            if ':' in host_port:
                host, port_str = host_port.split(':', 1)
                port = int(port_str)
            else:
                host = host_port
                port = 443
            
            return {
                'host': host,
                'port': port
            }
            
        except Exception as e:
            self.logger.error(f"解析CONNECT请求失败: {e}")
            return None
    
    def _connect_to_server(self, host: str, port: int) -> Optional[socket.socket]:
        """连接到目标服务器"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10.0)
            server_socket.connect((host, port))
            
            self.logger.debug(f"成功连接到服务器: {host}:{port}")
            return server_socket
            
        except Exception as e:
            self.logger.error(f"连接服务器失败 {host}:{port}: {e}")
            return None
    
    def _relay_data(self, client_socket: socket.socket, server_socket: socket.socket, conn_id: str):
        """转发HTTP数据"""
        try:
            while not self.stop_event.is_set():
                # 使用select检查哪个socket有数据
                ready_sockets, _, error_sockets = select.select(
                    [client_socket, server_socket], [], [client_socket, server_socket], 1.0
                )
                
                if error_sockets:
                    break
                
                for sock in ready_sockets:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            return
                        
                        self.stats['bytes_transferred'] += len(data)
                        
                        # 转发数据
                        if sock is client_socket:
                            server_socket.send(data)
                        else:
                            client_socket.send(data)
                            
                    except socket.error:
                        return
            
        except Exception as e:
            self.logger.error(f"数据转发错误: {e}")
    
    def _relay_ssl_data(self, client_socket: socket.socket, server_socket: socket.socket, conn_id: str):
        """转发SSL数据"""
        # SSL数据转发逻辑与HTTP类似，但需要处理加密数据
        self._relay_data(client_socket, server_socket, conn_id)
    
    def _generate_connection_id(self) -> str:
        """生成连接ID"""
        self.connection_count += 1
        return f"conn_{self.connection_count}_{int(time.time())}"
    
    def _cleanup_connection(self, conn_id: str):
        """清理连接"""
        if conn_id in self.active_connections:
            conn_info = self.active_connections[conn_id]
            
            # 关闭socket
            for socket_key in ['client_socket', 'server_socket']:
                if socket_key in conn_info:
                    try:
                        conn_info[socket_key].close()
                    except Exception:
                        pass
            
            # 删除连接记录
            del self.active_connections[conn_id]
            self.stats['connections_active'] = len(self.active_connections)
            
            self.logger.debug(f"清理连接: {conn_id}")
    
    def get_status(self) -> Dict[str, Any]:
        """
        获取透明代理状态
        
        Returns:
            Dict: 状态信息
        """
        return {
            'running': self.is_running,
            'proxy_port': self.proxy_port,
            'ssl_port': self.ssl_port,
            'interface': self.interface,
            'active_connections': len(self.active_connections),
            'max_connections': self.max_connections,
            'worker_threads': len([t for t in self.worker_threads if t.is_alive()])
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取统计信息
        
        Returns:
            Dict: 统计信息
        """
        stats = self.stats.copy()
        
        # 计算运行时间
        if stats['start_time']:
            stats['uptime'] = time.time() - stats['start_time']
        else:
            stats['uptime'] = 0
        
        return stats
    
    def reload_config(self, config: Dict[str, Any]) -> bool:
        """
        重新加载配置
        
        Args:
            config: 新配置
            
        Returns:
            bool: 重载是否成功
        """
        try:
            old_running = self.is_running
            
            # 如果正在运行，先停止
            if old_running:
                self.stop()
            
            # 更新配置
            self.config = config
            self.firewall_config = config.get('firewall', {})
            self.proxy_port = self.firewall_config.get('port', 8080)
            self.ssl_port = self.firewall_config.get('ssl_port', 8443)
            self.interface = self.firewall_config.get('interface', 'any')
            
            # 如果之前在运行，重新启动
            if old_running:
                self.start()
            
            self.logger.info("透明代理配置重载成功")
            return True
            
        except Exception as e:
            self.logger.error(f"透明代理配置重载失败: {e}")
            return False


def main():
    """主函数，用于直接运行测试"""
    config = {
        "firewall": {
            "port": 8080,
            "ssl_port": 8443,
            "interface": "any"
        }
    }
    
    proxy = TransparentProxy(config)
    
    print("=== 透明代理测试 ===")
    print(f"初始状态: {proxy.get_status()}")
    
    print("\n启动透明代理...")
    if proxy.start():
        print("启动成功")
        print("代理服务器正在运行...")
        print(f"HTTP代理: http://localhost:{proxy.proxy_port}")
        print(f"HTTPS代理: https://localhost:{proxy.ssl_port}")
        
        try:
            # 运行一段时间进行测试
            time.sleep(5)
            print(f"\n统计信息: {proxy.get_statistics()}")
        except KeyboardInterrupt:
            print("\n接收到中断信号")
        
        print("\n停止透明代理...")
        if proxy.stop():
            print("停止成功")
    else:
        print("启动失败")


if __name__ == "__main__":
    main()
