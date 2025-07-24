#!/usr/bin/env python3
"""
CFW高级防火墙系统 - 主入口文件

功能特性：
1. 流量拦截和处理 - 能够接管处理流经防火墙的流量
2. 双模式处理 - 支持直接处理和镜像处理两种模式
3. SSL/TLS解析 - 加密流量解析处理，包含证书部署
4. 深度包检测 - 基于LLM的智能流量分析
5. 透明代理 - 无感知的流量拦截和处理

作者: Leep
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from core.firewall_manager import FirewallManager
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"警告: 无法导入核心模块: {e}")
    CORE_AVAILABLE = False

try:
    from utils.install_dependencies import main as install_dependencies
    INSTALL_AVAILABLE = True
except ImportError:
    def install_dependencies():
        print("依赖安装功能不可用")
    INSTALL_AVAILABLE = False


def setup_logging(log_level="INFO"):
    """设置日志系统"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('firewall.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def check_dependencies():
    """检查并安装依赖"""
    try:
        import scapy
        import cryptography
        print("✓ 依赖检查通过")
        return True
    except ImportError as e:
        print(f"✗ 缺少依赖: {e}")
        print("正在安装依赖...")
        install_dependencies()
        return True


def main():
    """主入口函数"""
    parser = argparse.ArgumentParser(
        description="CFW高级防火墙系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s start                    # 启动防火墙
  %(prog)s start --mode direct      # 启动直接处理模式
  %(prog)s start --mode mirror      # 启动镜像处理模式
  %(prog)s ssl-setup               # 设置SSL拦截
  %(prog)s ssl-deploy              # 部署SSL证书
  %(prog)s status                  # 查看状态
  %(prog)s stop                    # 停止防火墙
  
高级功能:
  %(prog)s transparent-proxy       # 启动透明代理模式
  %(prog)s dpi-analyze            # 开启深度包检测分析
  %(prog)s llm-detection          # 启用LLM流量检测
        """
    )
    
    parser.add_argument(
        'command',
        choices=['start', 'stop', 'status', 'ssl-setup', 'ssl-deploy', 
                'transparent-proxy', 'dpi-analyze', 'llm-detection', 'install-deps'],
        help='执行的命令'
    )
    
    parser.add_argument(
        '--mode',
        choices=['direct', 'mirror'],
        default='direct',
        help='处理模式：direct(直接处理) 或 mirror(镜像处理)'
    )
    
    parser.add_argument(
        '--config',
        default='firewall_config.json',
        help='配置文件路径'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='日志级别'
    )
    
    args = parser.parse_args()
    
    # 设置日志
    setup_logging(args.log_level)
    
    # 检查核心模块可用性
    if not CORE_AVAILABLE and args.command != 'install-deps':
        print("错误: 核心模块不可用，请先运行 'python main.py install-deps'")
        return 1
    
    # 处理安装依赖命令
    if args.command == 'install-deps':
        print("开始安装依赖...")
        install_dependencies()
        return 0
    
    # 检查配置文件
    if not os.path.exists(args.config):
        print(f"警告: 配置文件不存在: {args.config}")
        print("使用默认配置")
    
    try:
        # 创建防火墙管理器
        firewall = FirewallManager(args.config)
        
        # 处理命令
        if args.command == 'start':
            print(f"启动防火墙，模式: {args.mode}")
            # 设置流量处理模式
            if args.mode == 'mirror':
                firewall.enable_traffic_interception('mirror')
            else:
                firewall.enable_traffic_interception('direct')
            
            if firewall.start():
                print("✓ 防火墙启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止防火墙...")
                    firewall.stop()
                    print("✓ 防火墙已停止")
            else:
                print("✗ 防火墙启动失败")
                return 1
        
        elif args.command == 'stop':
            print("停止防火墙...")
            if firewall.stop():
                print("✓ 防火墙已停止")
            else:
                print("✗ 防火墙停止失败")
                return 1
        
        elif args.command == 'status':
            status = firewall.status()
            print("=== 防火墙状态 ===")
            print(f"运行状态: {'运行中' if status.get('running', False) else '已停止'}")
            
            # 显示高级功能状态
            advanced_features = status.get('advanced_features', {})
            print(f"高级功能可用: {'是' if advanced_features.get('available', False) else '否'}")
            print(f"流量处理模式: {advanced_features.get('traffic_mode', '未知')}")
            print(f"SSL拦截: {'启用' if advanced_features.get('ssl_interception', False) else '禁用'}")
            print(f"DPI引擎: {'启用' if advanced_features.get('dpi_enabled', False) else '禁用'}")
            
            # 显示高级统计信息
            advanced_stats = status.get('advanced_stats', {})
            if advanced_stats:
                print("\n=== 组件状态 ===")
                for component, info in advanced_stats.items():
                    print(f"{component}: {info.get('status', '未知')}")
        
        elif args.command == 'ssl-setup':
            print("设置SSL拦截...")
            if firewall.enable_ssl_interception():
                print("✓ SSL拦截设置成功")
            else:
                print("✗ SSL拦截设置失败")
                return 1
        
        elif args.command == 'ssl-deploy':
            print("部署CA证书...")
            if firewall.deploy_ca_certificate():
                print("✓ CA证书部署成功")
            else:
                print("✗ CA证书部署失败")
                return 1
        
        elif args.command == 'transparent-proxy':
            print("启动透明代理模式...")
            # 设置配置为透明代理模式
            if hasattr(firewall, 'config'):
                firewall.config.setdefault('firewall', {})['mode'] = 'transparent_proxy'
            
            if firewall.start():
                print("✓ 透明代理启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止透明代理...")
                    firewall.stop()
                    print("✓ 透明代理已停止")
            else:
                print("✗ 透明代理启动失败")
                return 1
        
        elif args.command == 'dpi-analyze':
            print("开启深度包检测分析...")
            # 启用DPI功能
            firewall.enable_dpi()
            
            if firewall.start():
                print("✓ DPI分析启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止DPI分析...")
                    firewall.stop()
                    print("✓ DPI分析已停止")
            else:
                print("✗ DPI分析启动失败")
                return 1
        
        elif args.command == 'llm-detection':
            print("启用LLM流量检测...")
            # 启用DPI引擎（包含LLM检测）
            firewall.enable_dpi()
            
            if firewall.start():
                print("✓ LLM检测启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止LLM检测...")
                    firewall.stop()
                    print("✓ LLM检测已停止")
            else:
                print("✗ LLM检测启动失败")
                return 1
    
    except Exception as e:
        print(f"错误: {e}")
        logging.exception("程序执行异常")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
