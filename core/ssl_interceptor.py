"""
SSL拦截器 - 负责SSL/TLS流量拦截和证书管理
"""

import os
import logging
import threading
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import json

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class SSLInterceptor:
    """SSL拦截器主类"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化SSL拦截器
        
        Args:
            config: 配置字典
        """
        self.config = config
        self.logger = logging.getLogger('SSLInterceptor')
        
        # SSL配置
        self.ssl_config = config.get('ssl', {})
        self.ca_cert_path = self.ssl_config.get('ca_cert_path', './ssl_certs/ca.crt')
        self.ca_key_path = self.ssl_config.get('ca_key_path', './ssl_certs/ca.key')
        self.cert_duration_days = self.ssl_config.get('cert_duration_days', 365)
        
        # 运行状态
        self.is_running = False
        self.is_enabled = False
        self.intercepted_connections = {}
        
        # 统计信息
        self.stats = {
            'connections_intercepted': 0,
            'certificates_generated': 0,
            'ssl_handshakes': 0,
            'decryption_attempts': 0,
            'decryption_successes': 0,
            'errors': 0
        }
        
        # 证书缓存
        self.certificate_cache = {}
        self.cache_lock = threading.Lock()
        
        # 检查依赖
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.warning("cryptography库未安装，SSL功能将受限")
        
        self.logger.info("SSL拦截器初始化完成")
    
    def start(self) -> bool:
        """
        启动SSL拦截器
        
        Returns:
            bool: 启动是否成功
        """
        if self.is_running:
            self.logger.warning("SSL拦截器已在运行")
            return False
        
        try:
            self.logger.info("启动SSL拦截器")
            
            # 检查和创建证书目录
            cert_dir = os.path.dirname(self.ca_cert_path)
            if not os.path.exists(cert_dir):
                os.makedirs(cert_dir, exist_ok=True)
                self.logger.info(f"创建证书目录: {cert_dir}")
            
            # 检查CA证书
            if not self._check_ca_certificate():
                self.logger.info("生成新的CA证书")
                if not self._generate_ca_certificate():
                    self.logger.error("CA证书生成失败")
                    return False
            
            self.is_running = True
            self.logger.info("SSL拦截器启动成功")
            return True
            
        except Exception as e:
            self.logger.error(f"SSL拦截器启动失败: {e}")
            return False
    
    def stop(self) -> bool:
        """
        停止SSL拦截器
        
        Returns:
            bool: 停止是否成功
        """
        if not self.is_running:
            self.logger.warning("SSL拦截器未在运行")
            return False
        
        try:
            self.logger.info("停止SSL拦截器")
            
            # 清理拦截的连接
            self.intercepted_connections.clear()
            
            # 清理证书缓存
            with self.cache_lock:
                self.certificate_cache.clear()
            
            self.is_running = False
            self.logger.info("SSL拦截器已停止")
            return True
            
        except Exception as e:
            self.logger.error(f"SSL拦截器停止失败: {e}")
            return False
    
    def enable(self) -> bool:
        """
        启用SSL拦截
        
        Returns:
            bool: 启用是否成功
        """
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                self.logger.error("SSL拦截需要cryptography库")
                return False
            
            self.is_enabled = True
            self.logger.info("SSL拦截已启用")
            return True
            
        except Exception as e:
            self.logger.error(f"启用SSL拦截失败: {e}")
            return False
    
    def disable(self) -> bool:
        """
        禁用SSL拦截
        
        Returns:
            bool: 禁用是否成功
        """
        try:
            self.is_enabled = False
            self.logger.info("SSL拦截已禁用")
            return True
            
        except Exception as e:
            self.logger.error(f"禁用SSL拦截失败: {e}")
            return False
    
    def _check_ca_certificate(self) -> bool:
        """检查CA证书是否存在且有效"""
        try:
            if not os.path.exists(self.ca_cert_path) or not os.path.exists(self.ca_key_path):
                return False
            
            if CRYPTOGRAPHY_AVAILABLE:
                # 验证证书有效性
                with open(self.ca_cert_path, 'rb') as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data)
                    
                    # 检查证书是否过期
                    if cert.not_valid_after < datetime.utcnow():
                        self.logger.warning("CA证书已过期")
                        return False
            
            self.logger.info("CA证书检查通过")
            return True
            
        except Exception as e:
            self.logger.error(f"CA证书检查失败: {e}")
            return False
    
    def _generate_ca_certificate(self) -> bool:
        """生成CA证书"""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("无法生成CA证书：cryptography库未安装")
            return False
        
        try:
            # 生成私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # 创建证书
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Firewall CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Firewall Root CA"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=self.cert_duration_days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).sign(private_key, hashes.SHA256())
            
            # 保存私钥
            with open(self.ca_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # 保存证书
            with open(self.ca_cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            self.logger.info("CA证书生成成功")
            self.stats['certificates_generated'] += 1
            return True
            
        except Exception as e:
            self.logger.error(f"CA证书生成失败: {e}")
            return False
    
    def generate_server_certificate(self, hostname: str) -> Tuple[str, str]:
        """
        为指定主机名生成服务器证书
        
        Args:
            hostname: 主机名
            
        Returns:
            Tuple[str, str]: (证书路径, 私钥路径)
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("无法生成服务器证书：cryptography库未安装")
            return None, None
        
        try:
            # 检查缓存
            with self.cache_lock:
                if hostname in self.certificate_cache:
                    return self.certificate_cache[hostname]
            
            # 加载CA证书和私钥
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            
            with open(self.ca_key_path, 'rb') as f:
                ca_private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            
            # 生成服务器私钥
            server_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # 创建服务器证书
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Firewall Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            server_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                server_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=90)  # 服务器证书短期有效
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName(f"*.{hostname}"),
                ]),
                critical=False,
            ).sign(ca_private_key, hashes.SHA256())
            
            # 保存证书文件
            cert_dir = os.path.dirname(self.ca_cert_path)
            server_cert_path = os.path.join(cert_dir, f"{hostname}.crt")
            server_key_path = os.path.join(cert_dir, f"{hostname}.key")
            
            with open(server_cert_path, 'wb') as f:
                f.write(server_cert.public_bytes(serialization.Encoding.PEM))
            
            with open(server_key_path, 'wb') as f:
                f.write(server_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # 添加到缓存
            with self.cache_lock:
                self.certificate_cache[hostname] = (server_cert_path, server_key_path)
            
            self.logger.info(f"为 {hostname} 生成服务器证书成功")
            self.stats['certificates_generated'] += 1
            return server_cert_path, server_key_path
            
        except Exception as e:
            self.logger.error(f"生成服务器证书失败: {e}")
            return None, None
    
    def deploy_ca_certificate(self) -> bool:
        """
        部署CA证书到系统信任存储
        
        Returns:
            bool: 部署是否成功
        """
        try:
            self.logger.info("部署CA证书到系统信任存储")
            
            if not os.path.exists(self.ca_cert_path):
                self.logger.error("CA证书文件不存在")
                return False
            
            # 这里应该实现将CA证书添加到系统信任存储的逻辑
            # 具体实现取决于操作系统
            
            # 为演示目的，这里只是复制证书到一个公共位置
            import shutil
            deploy_path = "./deployed_ca.crt"
            shutil.copy2(self.ca_cert_path, deploy_path)
            
            self.logger.info(f"CA证书已部署到: {deploy_path}")
            self.logger.warning("请手动将CA证书添加到客户端的信任存储中")
            
            return True
            
        except Exception as e:
            self.logger.error(f"部署CA证书失败: {e}")
            return False
    
    def intercept_ssl_connection(self, client_socket, target_host: str, target_port: int) -> bool:
        """
        拦截SSL连接
        
        Args:
            client_socket: 客户端socket
            target_host: 目标主机
            target_port: 目标端口
            
        Returns:
            bool: 拦截是否成功
        """
        if not self.is_enabled:
            return False
        
        try:
            self.logger.info(f"拦截SSL连接: {target_host}:{target_port}")
            
            # 生成服务器证书
            cert_path, key_path = self.generate_server_certificate(target_host)
            if not cert_path or not key_path:
                return False
            
            # 这里应该实现SSL拦截逻辑
            # 包括建立与客户端和服务器的SSL连接
            
            self.stats['connections_intercepted'] += 1
            self.stats['ssl_handshakes'] += 1
            
            return True
            
        except Exception as e:
            self.logger.error(f"SSL连接拦截失败: {e}")
            self.stats['errors'] += 1
            return False
    
    def decrypt_traffic(self, encrypted_data: bytes) -> Optional[bytes]:
        """
        解密流量数据
        
        Args:
            encrypted_data: 加密的数据
            
        Returns:
            Optional[bytes]: 解密后的数据，失败返回None
        """
        if not self.is_enabled:
            return None
        
        try:
            self.stats['decryption_attempts'] += 1
            
            # 这里应该实现实际的解密逻辑
            # 现在只是返回模拟数据
            decrypted_data = b"Decrypted: " + encrypted_data[:100]
            
            self.stats['decryption_successes'] += 1
            self.logger.debug(f"解密数据成功，大小: {len(decrypted_data)} 字节")
            
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"解密流量失败: {e}")
            self.stats['errors'] += 1
            return None
    
    def get_status(self) -> Dict[str, Any]:
        """
        获取SSL拦截器状态
        
        Returns:
            Dict: 状态信息
        """
        return {
            'running': self.is_running,
            'enabled': self.is_enabled,
            'cryptography_available': CRYPTOGRAPHY_AVAILABLE,
            'ca_cert_exists': os.path.exists(self.ca_cert_path),
            'cached_certificates': len(self.certificate_cache),
            'active_connections': len(self.intercepted_connections)
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取统计信息
        
        Returns:
            Dict: 统计信息
        """
        stats = self.stats.copy()
        
        # 计算成功率
        if stats['decryption_attempts'] > 0:
            stats['decryption_success_rate'] = (
                stats['decryption_successes'] / stats['decryption_attempts'] * 100
            )
        else:
            stats['decryption_success_rate'] = 0
        
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
            self.config = config
            self.ssl_config = config.get('ssl', {})
            self.ca_cert_path = self.ssl_config.get('ca_cert_path', './ssl_certs/ca.crt')
            self.ca_key_path = self.ssl_config.get('ca_key_path', './ssl_certs/ca.key')
            self.cert_duration_days = self.ssl_config.get('cert_duration_days', 365)
            
            self.logger.info("SSL拦截器配置重载成功")
            return True
        except Exception as e:
            self.logger.error(f"SSL拦截器配置重载失败: {e}")
            return False


class CertificateDeployer:
    """证书部署器 - 用于自动部署证书到客户端"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化证书部署器
        
        Args:
            config: 配置字典
        """
        self.config = config
        self.logger = logging.getLogger('CertificateDeployer')
        
        self.logger.info("证书部署器初始化完成")
    
    def deploy_to_client(self, client_info: Dict[str, Any]) -> bool:
        """
        部署证书到客户端
        
        Args:
            client_info: 客户端信息
            
        Returns:
            bool: 部署是否成功
        """
        try:
            self.logger.info(f"部署证书到客户端: {client_info}")
            
            # 这里应该实现具体的证书部署逻辑
            # 例如通过网络推送、邮件发送、文件共享等方式
            
            return True
            
        except Exception as e:
            self.logger.error(f"证书部署失败: {e}")
            return False


def main():
    """主函数，用于直接运行测试"""
    config = {
        "ssl": {
            "ca_cert_path": "./test_ssl_certs/ca.crt",
            "ca_key_path": "./test_ssl_certs/ca.key",
            "cert_duration_days": 365
        }
    }
    
    interceptor = SSLInterceptor(config)
    
    print("=== SSL拦截器测试 ===")
    print(f"初始状态: {interceptor.get_status()}")
    
    print("\n启动SSL拦截器...")
    if interceptor.start():
        print("启动成功")
        
        print("\n启用SSL拦截...")
        if interceptor.enable():
            print("启用成功")
            
            print("\n部署CA证书...")
            if interceptor.deploy_ca_certificate():
                print("部署成功")
            
            print(f"\n统计信息: {interceptor.get_statistics()}")
        
        print("\n停止SSL拦截器...")
        if interceptor.stop():
            print("停止成功")
    else:
        print("启动失败")


if __name__ == "__main__":
    main()
