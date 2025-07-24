#!/usr/bin/env python3
"""
防火墙管理脚本
支持在防火墙设备上部署和运行
支持流量拦截、SSL解密、深度包检测
作者: Leep
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# 导入新的高级模块
try:
    from .traffic_processor import TrafficProcessor, TrafficMirror
    from .ssl_interceptor import SSLInterceptor, CertificateDeployer
    from .dpi_engine import DPIEngine
    from .transparent_proxy import TransparentProxy
    ADVANCED_FEATURES = True
except ImportError:
    try:
        from traffic_processor import TrafficProcessor, TrafficMirror
        from ssl_interceptor import SSLInterceptor, CertificateDeployer
        from dpi_engine import DPIEngine
        from transparent_proxy import TransparentProxy
        ADVANCED_FEATURES = True
    except ImportError:
        ADVANCED_FEATURES = False
        print("警告: 高级功能模块未找到，将以基础模式运行")


class FirewallManager:
    """防火墙管理器类"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        初始化防火墙管理器
        
        Args:
            config_file: 配置文件路径
        """
        self.config_file = config_file or "firewall_config.json"
        self.config = self._load_config()
        self._setup_logging()
        
        # 高级功能组件
        self.traffic_processor = None
        self.traffic_mirror = None
        self.ssl_interceptor = None
        self.certificate_deployer = None
        self.dpi_engine = None
        
        # 初始化高级功能
        if ADVANCED_FEATURES:
            self._init_advanced_features()
        
    def _load_config(self) -> Dict:
        """加载配置文件"""
        default_config = {
            "log_level": "INFO",
            "log_file": "firewall.log",
            "interface": "eth0",
            "rules": [],
            "whitelist": [],
            "blacklist": [],
            # 新增高级功能配置
            "traffic_mode": "direct",  # direct, mirror, hybrid
            "ssl_interception": {
                "enabled": False,
                "ca_cert_path": "firewall_ca.crt",
                "ca_key_path": "firewall_ca.key",
                "intercept_domains": []
            },
            "dpi": {
                "enabled": False,
                "content_filter": {
                    "blocked_keywords": [],
                    "blocked_patterns": [],
                    "blocked_domains": [],
                    "blocked_urls": [],
                    "blocked_file_types": ["exe", "bat", "scr"],
                    "malware_signatures": []
                },
                "threat_detection": {
                    "max_connections_per_ip": 100,
                    "max_requests_per_minute": 1000,
                    "ddos_threshold": 10000,
                    "port_scan_threshold": 20
                }
            },
            "advanced_logging": {
                "log_ssl_connections": False,
                "log_http_content": False,
                "log_threats": True
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                # 合并默认配置
                default_config.update(config)
                return default_config
            except Exception as e:
                print(f"加载配置文件失败: {e}")
                return default_config
        else:
            # 创建默认配置文件
            self._save_config(default_config)
            return default_config
    
    def _save_config(self, config: Dict) -> None:
        """保存配置文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"保存配置文件失败: {e}")
    
    def _setup_logging(self) -> None:
        """设置日志记录"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        log_file = self.config.get('log_file', 'firewall.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        logging.info("防火墙管理器初始化完成")
    
    def _init_advanced_features(self):
        """初始化高级功能组件"""
        try:
            # 初始化流量处理器
            if self.config.get('traffic_mode') in ['direct', 'hybrid']:
                self.traffic_processor = TrafficProcessor(self.config)
                logging.info("流量处理器初始化成功")
            
            # 初始化流量镜像
            if self.config.get('traffic_mode') in ['mirror', 'hybrid']:
                self.traffic_mirror = TrafficMirror(self.config)
                logging.info("流量镜像初始化成功")
            
            # 初始化SSL拦截器
            if self.config.get('ssl_interception', {}).get('enabled', False):
                self.ssl_interceptor = SSLInterceptor(self.config['ssl_interception'])
                self.certificate_deployer = CertificateDeployer(self.ssl_interceptor)
                logging.info("SSL拦截器初始化成功")
            
            # 初始化DPI引擎
            if self.config.get('dpi', {}).get('enabled', False):
                self.dpi_engine = DPIEngine(self.config['dpi'])
                logging.info("DPI引擎初始化成功")
                
        except Exception as e:
            logging.error(f"高级功能初始化失败: {e}")
            logging.warning("将以基础模式运行")
    
    def install(self) -> bool:
        """
        安装防火墙脚本到系统
        
        Returns:
            bool: 安装是否成功
        """
        try:
            logging.info("开始安装防火墙脚本...")
            
            # TODO: 实现防火墙脚本的安装逻辑
            # 1. 检查系统环境
            # 2. 安装必要的依赖
            # 3. 设置开机自启动
            # 4. 配置防火墙规则
            
            logging.info("防火墙脚本安装完成")
            return True
            
        except Exception as e:
            logging.error(f"安装失败: {e}")
            return False
    
    def uninstall(self) -> bool:
        """
        卸载防火墙脚本
        
        Returns:
            bool: 卸载是否成功
        """
        try:
            logging.info("开始卸载防火墙脚本...")
            
            # TODO: 实现防火墙脚本的卸载逻辑
            # 1. 停止服务
            # 2. 移除自启动配置
            # 3. 清理防火墙规则
            # 4. 删除相关文件
            
            logging.info("防火墙脚本卸载完成")
            return True
            
        except Exception as e:
            logging.error(f"卸载失败: {e}")
            return False
    
    def start(self) -> bool:
        """
        启动防火墙服务
        
        Returns:
            bool: 启动是否成功
        """
        try:
            logging.info("启动防火墙服务...")
            
            # TODO: 实现基础防火墙服务启动逻辑
            # 1. 检查系统状态
            # 2. 加载防火墙规则
            # 3. 启动监控服务
            
            # 启动高级功能
            if ADVANCED_FEATURES:
                if self.traffic_processor:
                    self.traffic_processor.start()
                    logging.info("流量处理器已启动")
                
                if self.traffic_mirror:
                    interface = self.config.get('interface', 'eth0')
                    self.traffic_mirror.start_capture(interface)
                    logging.info(f"流量镜像已启动，监听接口: {interface}")
            
            logging.info("防火墙服务启动成功")
            return True
            
        except Exception as e:
            logging.error(f"启动失败: {e}")
            return False
    
    def stop(self) -> bool:
        """
        停止防火墙服务
        
        Returns:
            bool: 停止是否成功
        """
        try:
            logging.info("停止防火墙服务...")
            
            # 停止高级功能
            if ADVANCED_FEATURES:
                if self.traffic_processor:
                    self.traffic_processor.stop()
                    logging.info("流量处理器已停止")
                
                if self.traffic_mirror:
                    self.traffic_mirror.stop_capture()
                    logging.info("流量镜像已停止")
            
            # TODO: 实现基础防火墙服务停止逻辑
            # 1. 保存当前状态
            # 2. 清理临时规则
            # 3. 停止监控服务
            
            logging.info("防火墙服务停止成功")
            return True
            
        except Exception as e:
            logging.error(f"停止失败: {e}")
            return False
    
    def status(self) -> Dict:
        """
        获取防火墙状态
        
        Returns:
            Dict: 防火墙状态信息
        """
        try:
            # TODO: 实现防火墙状态检查逻辑
            status_info = {
                "running": False,
                "rules_count": len(self.config.get('rules', [])),
                "last_update": datetime.now().isoformat(),
                "memory_usage": "0MB",
                "cpu_usage": "0%",
                "advanced_features": {
                    "available": ADVANCED_FEATURES,
                    "traffic_mode": self.config.get('traffic_mode', 'direct'),
                    "ssl_interception": self.config.get('ssl_interception', {}).get('enabled', False),
                    "dpi_enabled": self.config.get('dpi', {}).get('enabled', False)
                }
            }
            
            # 添加高级功能统计
            if ADVANCED_FEATURES:
                advanced_stats = self.get_advanced_stats()
                if advanced_stats:
                    status_info["advanced_stats"] = advanced_stats
            
            logging.info("获取防火墙状态成功")
            return status_info
            
        except Exception as e:
            logging.error(f"获取状态失败: {e}")
            return {"error": str(e)}
    
    def add_rule(self, rule: Dict) -> bool:
        """
        添加防火墙规则
        
        Args:
            rule: 防火墙规则配置
            
        Returns:
            bool: 添加是否成功
        """
        try:
            logging.info(f"添加防火墙规则: {rule}")
            
            # TODO: 实现防火墙规则添加逻辑
            # 1. 验证规则格式
            # 2. 检查规则冲突
            # 3. 应用规则
            # 4. 保存到配置
            
            self.config['rules'].append(rule)
            self._save_config(self.config)
            
            logging.info("防火墙规则添加成功")
            return True
            
        except Exception as e:
            logging.error(f"添加规则失败: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        删除防火墙规则
        
        Args:
            rule_id: 规则ID
            
        Returns:
            bool: 删除是否成功
        """
        try:
            logging.info(f"删除防火墙规则: {rule_id}")
            
            # TODO: 实现防火墙规则删除逻辑
            # 1. 查找规则
            # 2. 移除规则
            # 3. 更新配置
            
            logging.info("防火墙规则删除成功")
            return True
            
        except Exception as e:
            logging.error(f"删除规则失败: {e}")
            return False
    
    def list_rules(self) -> List[Dict]:
        """
        列出所有防火墙规则
        
        Returns:
            List[Dict]: 防火墙规则列表
        """
        try:
            rules = self.config.get('rules', [])
            logging.info(f"获取到 {len(rules)} 条防火墙规则")
            return rules
            
        except Exception as e:
            logging.error(f"获取规则列表失败: {e}")
            return []
    
    def reload_config(self) -> bool:
        """
        重新加载配置文件
        
        Returns:
            bool: 重载是否成功
        """
        try:
            logging.info("重新加载配置文件...")
            self.config = self._load_config()
            logging.info("配置文件重载成功")
            return True
            
        except Exception as e:
            logging.error(f"重载配置失败: {e}")
            return False
    
    def backup_config(self, backup_path: Optional[str] = None) -> bool:
        """
        备份配置文件
        
        Args:
            backup_path: 备份文件路径
            
        Returns:
            bool: 备份是否成功
        """
        try:
            if not backup_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"firewall_config_backup_{timestamp}.json"
            
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            
            logging.info(f"配置文件备份成功: {backup_path}")
            return True
            
        except Exception as e:
            logging.error(f"备份配置失败: {e}")
            return False
    
    def enable_ssl_interception(self) -> bool:
        """
        启用SSL拦截功能
        
        Returns:
            bool: 启用是否成功
        """
        try:
            if not ADVANCED_FEATURES:
                logging.error("SSL拦截功能不可用")
                return False
            
            if not self.ssl_interceptor:
                self.ssl_interceptor = SSLInterceptor(self.config.get('ssl_interception', {}))
                self.certificate_deployer = CertificateDeployer(self.ssl_interceptor)
            
            # 更新配置
            self.config.setdefault('ssl_interception', {})['enabled'] = True
            self._save_config(self.config)
            
            logging.info("SSL拦截功能已启用")
            return True
            
        except Exception as e:
            logging.error(f"启用SSL拦截失败: {e}")
            return False
    
    def disable_ssl_interception(self) -> bool:
        """
        禁用SSL拦截功能
        
        Returns:
            bool: 禁用是否成功
        """
        try:
            # 更新配置
            self.config.setdefault('ssl_interception', {})['enabled'] = False
            self._save_config(self.config)
            
            logging.info("SSL拦截功能已禁用")
            return True
            
        except Exception as e:
            logging.error(f"禁用SSL拦截失败: {e}")
            return False
    
    def deploy_ca_certificate(self, target_platform: str = "windows") -> str:
        """
        生成CA证书部署包
        
        Args:
            target_platform: 目标平台
            
        Returns:
            部署包路径
        """
        try:
            if not self.certificate_deployer:
                logging.error("证书部署器未初始化")
                return ""
            
            deployment_path = self.certificate_deployer.create_auto_deployment_package()
            logging.info(f"CA证书部署包已创建: {deployment_path}")
            return deployment_path
            
        except Exception as e:
            logging.error(f"创建证书部署包失败: {e}")
            return ""
    
    def enable_traffic_interception(self, mode: str = "direct") -> bool:
        """
        启用流量拦截
        
        Args:
            mode: 拦截模式 (direct/mirror/hybrid)
            
        Returns:
            bool: 启用是否成功
        """
        try:
            if not ADVANCED_FEATURES:
                logging.error("流量拦截功能不可用")
                return False
            
            if mode not in ['direct', 'mirror', 'hybrid']:
                logging.error(f"不支持的拦截模式: {mode}")
                return False
            
            # 更新配置
            self.config['traffic_mode'] = mode
            self._save_config(self.config)
            
            # 重新初始化流量处理器
            if mode in ['direct', 'hybrid']:
                self.traffic_processor = TrafficProcessor(self.config)
            
            if mode in ['mirror', 'hybrid']:
                self.traffic_mirror = TrafficMirror(self.config)
            
            logging.info(f"流量拦截已启用，模式: {mode}")
            return True
            
        except Exception as e:
            logging.error(f"启用流量拦截失败: {e}")
            return False
    
    def enable_dpi(self) -> bool:
        """
        启用深度包检测
        
        Returns:
            bool: 启用是否成功
        """
        try:
            if not ADVANCED_FEATURES:
                logging.error("DPI功能不可用")
                return False
            
            # 更新配置
            self.config.setdefault('dpi', {})['enabled'] = True
            self._save_config(self.config)
            
            # 初始化DPI引擎
            if not self.dpi_engine:
                self.dpi_engine = DPIEngine(self.config['dpi'])
            
            logging.info("深度包检测已启用")
            return True
            
        except Exception as e:
            logging.error(f"启用DPI失败: {e}")
            return False
    
    def get_advanced_stats(self) -> Dict:
        """
        获取高级功能统计信息
        
        Returns:
            Dict: 统计信息
        """
        stats = {}
        
        try:
            if self.traffic_processor:
                # 检查方法是否存在
                if hasattr(self.traffic_processor, 'get_stats'):
                    stats['traffic_processor'] = self.traffic_processor.get_stats()
                else:
                    # 提供基础统计信息
                    stats['traffic_processor'] = {
                        'status': 'initialized',
                        'class': 'TrafficProcessor'
                    }
            
            if self.traffic_mirror:
                if hasattr(self.traffic_mirror, 'get_analysis_results'):
                    stats['traffic_mirror'] = self.traffic_mirror.get_analysis_results()
                else:
                    stats['traffic_mirror'] = {
                        'status': 'initialized',
                        'class': 'TrafficMirror'
                    }
            
            if self.ssl_interceptor:
                if hasattr(self.ssl_interceptor, 'get_stats'):
                    stats['ssl_interceptor'] = self.ssl_interceptor.get_stats()
                else:
                    stats['ssl_interceptor'] = {
                        'status': 'initialized',
                        'class': 'SSLInterceptor'
                    }
            
            if self.dpi_engine:
                if hasattr(self.dpi_engine, 'get_stats'):
                    stats['dpi_engine'] = self.dpi_engine.get_stats()
                else:
                    stats['dpi_engine'] = {
                        'status': 'initialized',
                        'class': 'DPIEngine'
                    }
                
        except Exception as e:
            logging.error(f"获取高级统计失败: {e}")
            stats['error'] = str(e)
        
        return stats


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="防火墙管理脚本 - 支持SSL拦截和深度包检测")
    parser.add_argument('--config', '-c', help='配置文件路径')
    parser.add_argument('--action', '-a', required=True,
                       choices=['install', 'uninstall', 'start', 'stop', 'status', 'reload',
                               'enable-ssl', 'disable-ssl', 'deploy-cert', 'enable-traffic',
                               'enable-dpi'],
                       help='执行的操作')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    parser.add_argument('--traffic-mode', choices=['direct', 'mirror', 'hybrid'],
                       default='direct', help='流量处理模式')
    parser.add_argument('--platform', choices=['windows', 'linux', 'macos'],
                       default='windows', help='证书部署目标平台')
    
    args = parser.parse_args()
    
    # 创建防火墙管理器实例
    fw_manager = FirewallManager(args.config)
    
    # 执行相应的操作
    try:
        if args.action == 'install':
            success = fw_manager.install()
        elif args.action == 'uninstall':
            success = fw_manager.uninstall()
        elif args.action == 'start':
            success = fw_manager.start()
        elif args.action == 'stop':
            success = fw_manager.stop()
        elif args.action == 'status':
            status = fw_manager.status()
            print(json.dumps(status, indent=2, ensure_ascii=False))
            success = 'error' not in status
        elif args.action == 'reload':
            success = fw_manager.reload_config()
        elif args.action == 'enable-ssl':
            success = fw_manager.enable_ssl_interception()
            if success:
                print("SSL拦截已启用")
                print("请使用 'deploy-cert' 命令生成客户端证书安装包")
        elif args.action == 'disable-ssl':
            success = fw_manager.disable_ssl_interception()
            if success:
                print("SSL拦截已禁用")
        elif args.action == 'deploy-cert':
            cert_path = fw_manager.deploy_ca_certificate(args.platform)
            if cert_path:
                print(f"证书部署包已创建: {cert_path}")
                print("请将此部署包分发给客户端进行安装")
                success = True
            else:
                success = False
        elif args.action == 'enable-traffic':
            success = fw_manager.enable_traffic_interception(args.traffic_mode)
            if success:
                print(f"流量拦截已启用，模式: {args.traffic_mode}")
        elif args.action == 'enable-dpi':
            success = fw_manager.enable_dpi()
            if success:
                print("深度包检测已启用")
        else:
            print(f"不支持的操作: {args.action}")
            success = False
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n操作被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"执行操作时发生错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
