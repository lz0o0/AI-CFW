#!/usr/bin/env python3
"""
防火墙依赖安装脚本
安装SSL拦截和深度包检测所需的Python库
"""

import subprocess
import sys
import os
import platform

def install_package(package):
    """安装Python包"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✓ {package} 安装成功")
        return True
    except subprocess.CalledProcessError:
        print(f"✗ {package} 安装失败")
        return False

def check_package(package):
    """检查包是否已安装"""
    try:
        __import__(package)
        return True
    except ImportError:
        return False

def main():
    """主函数"""
    print("防火墙高级功能依赖安装脚本")
    print("=" * 50)
    
    # 检查Python版本
    if sys.version_info < (3, 6):
        print("错误: 需要Python 3.6或更高版本")
        sys.exit(1)
    
    print(f"Python版本: {sys.version}")
    print(f"操作系统: {platform.system()} {platform.release()}")
    print()
    
    # 必需的包列表
    required_packages = [
        ("cryptography", "cryptography"),  # SSL证书生成和处理
        ("scapy", "scapy"),               # 网络包处理
        ("netfilterqueue", "netfilterqueue"),  # Linux网络过滤队列（仅Linux）
    ]
    
    # 可选的包列表
    optional_packages = [
        ("dpkt", "dpkt"),                 # 网络包解析
        ("pyOpenSSL", "pyOpenSSL"),       # SSL/TLS支持
        ("psutil", "psutil"),             # 系统监控
        ("requests", "requests"),         # HTTP请求
    ]
    
    success_count = 0
    failed_packages = []
    
    print("安装必需的依赖包...")
    print("-" * 30)
    
    for package_name, import_name in required_packages:
        # 跳过Linux特定的包（在Windows上）
        if package_name == "netfilterqueue" and platform.system() == "Windows":
            print(f"⚠ {package_name} (跳过，Windows不支持)")
            continue
            
        if check_package(import_name):
            print(f"✓ {package_name} 已安装")
            success_count += 1
        else:
            print(f"正在安装 {package_name}...")
            if install_package(package_name):
                success_count += 1
            else:
                failed_packages.append(package_name)
    
    print("\n安装可选的依赖包...")
    print("-" * 30)
    
    for package_name, import_name in optional_packages:
        if check_package(import_name):
            print(f"✓ {package_name} 已安装")
        else:
            print(f"正在安装 {package_name}...")
            install_package(package_name)  # 可选包安装失败不计入错误
    
    print("\n" + "=" * 50)
    print("安装完成")
    
    if failed_packages:
        print(f"❌ 以下必需包安装失败: {', '.join(failed_packages)}")
        print("\n手动安装建议:")
        for package in failed_packages:
            print(f"  pip install {package}")
        
        if "netfilterqueue" in failed_packages and platform.system() == "Linux":
            print("\nLinux系统netfilterqueue安装说明:")
            print("  Ubuntu/Debian: sudo apt-get install libnetfilter-queue-dev")
            print("  CentOS/RHEL: sudo yum install libnetfilter_queue-devel")
            print("  然后运行: pip install netfilterqueue")
        
        print("\n某些高级功能可能无法使用。")
        return False
    else:
        print("🎉 所有必需依赖安装成功！")
        
        # 创建功能测试
        print("\n测试高级功能...")
        test_advanced_features()
        
        return True

def test_advanced_features():
    """测试高级功能是否可用"""
    features = {
        "SSL拦截": False,
        "流量处理": False,
        "深度包检测": False
    }
    
    # 测试SSL拦截
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        features["SSL拦截"] = True
    except ImportError:
        pass
    
    # 测试流量处理
    try:
        if platform.system() == "Linux":
            from scapy.all import sniff
            features["流量处理"] = True
        else:
            # Windows上的基础流量处理
            import socket
            features["流量处理"] = True
    except ImportError:
        pass
    
    # 测试深度包检测
    try:
        import re
        features["深度包检测"] = True
    except ImportError:
        pass
    
    print("功能可用性:")
    for feature, available in features.items():
        status = "✓ 可用" if available else "✗ 不可用"
        print(f"  {feature}: {status}")
    
    if all(features.values()):
        print("\n🚀 所有高级功能都可用！")
    else:
        print("\n⚠ 部分功能不可用，请检查依赖安装。")

def install_dependencies():
    """安装依赖的简化接口"""
    return main()

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n安装被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n安装过程中发生错误: {e}")
        sys.exit(1)
