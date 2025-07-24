#!/usr/bin/env python3
"""
CFW防火墙项目维护脚本
用于清理临时文件、缓存和其他不需要的文件
"""

import os
import shutil
import glob
from pathlib import Path

def clean_python_cache():
    """清理Python缓存文件"""
    print("清理Python缓存文件...")
    
    # 查找并删除__pycache__目录
    for cache_dir in glob.glob("**/__pycache__", recursive=True):
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
            print(f"  删除: {cache_dir}")
    
    # 删除.pyc文件
    for pyc_file in glob.glob("**/*.pyc", recursive=True):
        if os.path.exists(pyc_file):
            os.remove(pyc_file)
            print(f"  删除: {pyc_file}")

def clean_log_files():
    """清理日志文件"""
    print("清理日志文件...")
    
    log_patterns = ["*.log", "*.log.*"]
    for pattern in log_patterns:
        for log_file in glob.glob(pattern):
            if os.path.exists(log_file):
                os.remove(log_file)
                print(f"  删除: {log_file}")

def clean_temp_files():
    """清理临时文件"""
    print("清理临时文件...")
    
    temp_patterns = [
        "*.tmp", "*.temp", "*.swp", "*.swo", "*~",
        "*.bak", "*.backup"
    ]
    
    for pattern in temp_patterns:
        for temp_file in glob.glob(pattern):
            if os.path.exists(temp_file):
                os.remove(temp_file)
                print(f"  删除: {temp_file}")

def clean_build_artifacts():
    """清理构建产物"""
    print("清理构建产物...")
    
    build_dirs = ["build", "dist", "*.egg-info"]
    for pattern in build_dirs:
        for item in glob.glob(pattern):
            if os.path.isdir(item):
                shutil.rmtree(item)
                print(f"  删除目录: {item}")
            elif os.path.isfile(item):
                os.remove(item)
                print(f"  删除文件: {item}")

def clean_certificate_files():
    """清理证书文件（保留cert_deployment目录中的）"""
    print("清理根目录下的证书文件...")
    
    cert_patterns = ["*.crt", "*.key", "*.pem", "*.p12", "*.pfx"]
    for pattern in cert_patterns:
        for cert_file in glob.glob(pattern):
            # 不删除cert_deployment目录中的证书文件
            if not cert_file.startswith("cert_deployment/"):
                if os.path.exists(cert_file):
                    os.remove(cert_file)
                    print(f"  删除: {cert_file}")

def clean_test_artifacts():
    """清理测试产物"""
    print("清理测试产物...")
    
    test_patterns = [
        "test_*.json", "test_*.log", "test_backup.*",
        ".pytest_cache", ".coverage", "htmlcov"
    ]
    
    for pattern in test_patterns:
        for item in glob.glob(pattern):
            if os.path.isdir(item):
                shutil.rmtree(item)
                print(f"  删除目录: {item}")
            elif os.path.isfile(item):
                os.remove(item)
                print(f"  删除文件: {item}")

def clean_system_files():
    """清理系统文件"""
    print("清理系统文件...")
    
    system_files = [
        ".DS_Store", "Thumbs.db", "desktop.ini",
        "ehthumbs.db", "Desktop.ini"
    ]
    
    for file_name in system_files:
        for sys_file in glob.glob(f"**/{file_name}", recursive=True):
            if os.path.exists(sys_file):
                os.remove(sys_file)
                print(f"  删除: {sys_file}")

def main():
    """主函数"""
    print("CFW防火墙项目清理工具")
    print("=" * 40)
    
    # 确保在项目根目录
    if not os.path.exists("main.py"):
        print("错误: 请在项目根目录运行此脚本")
        return
    
    try:
        clean_python_cache()
        clean_log_files()
        clean_temp_files()
        clean_build_artifacts()
        clean_certificate_files()
        clean_test_artifacts()
        clean_system_files()
        
        print("\n" + "=" * 40)
        print("🎉 项目清理完成！")
        
    except Exception as e:
        print(f"❌ 清理过程中发生错误: {e}")

if __name__ == "__main__":
    main()
