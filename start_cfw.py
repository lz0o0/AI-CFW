#!/usr/bin/env python3
"""
CFW防火墙系统快速启动脚本

一键启动CFW防火墙系统，包含：
1. 环境检查
2. 系统启动
3. 状态监控
4. 日志查看
"""

import os
import sys
import json
import time
import subprocess
import threading
from pathlib import Path

class CFWQuickStart:
    """CFW快速启动器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.config_path = self.project_root / "config" / "firewall_config_extended.json"
        self.main_script = self.project_root / "main.py"
        self.is_running = False
        
    def log(self, message, level="INFO"):
        """日志输出"""
        timestamp = time.strftime("%H:%M:%S")
        symbols = {
            "INFO": "ℹ️",
            "WARN": "⚠️", 
            "ERROR": "❌",
            "SUCCESS": "✅"
        }
        symbol = symbols.get(level, "📝")
        print(f"[{timestamp}] {symbol} {message}")
    
    def check_environment(self):
        """快速环境检查"""
        self.log("检查运行环境...")
        
        # 检查Python版本
        if sys.version_info < (3, 8):
            self.log("需要Python 3.8或更高版本", "ERROR")
            return False
        
        # 检查配置文件
        if not self.config_path.exists():
            self.log(f"配置文件不存在: {self.config_path}", "ERROR")
            return False
        
        # 检查主程序
        if not self.main_script.exists():
            self.log(f"主程序不存在: {self.main_script}", "ERROR")
            return False
        
        # 检查关键依赖
        required_modules = ['cryptography', 'requests']
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            self.log(f"缺少依赖模块: {missing_modules}", "WARN")
            self.log("尝试安装依赖...")
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install"
                ] + missing_modules)
                self.log("依赖安装完成", "SUCCESS")
            except:
                self.log("依赖安装失败，请手动安装", "ERROR")
                return False
        
        self.log("环境检查通过", "SUCCESS")
        return True
    
    def show_startup_banner(self):
        """显示启动横幅"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    CFW 防火墙系统                           ║
║                  Custom Firewall System                     ║
║                                                              ║
║  🛡️  高级威胁检测   🔒 SSL/TLS 解密   🤖 AI 内容分析       ║
║  📊  实时监控       🚨 智能告警       📝 详细日志           ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def show_menu(self):
        """显示操作菜单"""
        menu = """
🚀 CFW 操作菜单:

1. 💡 快速演示 - 查看CFW功能演示
2. 🔍 效果验证 - 运行完整的效果验证测试
3. 🛡️  启动防火墙 - 启动完整的防火墙系统
4. 📊 查看威胁日志 - 查看最近的威胁检测记录
5. 📈 威胁统计 - 查看威胁统计信息
6. 📄 导出报告 - 导出威胁分析报告
7. ⚙️  配置检查 - 检查系统配置
8. 🔧 高级选项 - 更多高级功能
9. ❌ 退出

请选择操作 (1-9): """
        return input(menu).strip()
    
    def run_demo(self):
        """运行演示"""
        self.log("启动CFW功能演示...")
        demo_script = self.project_root / "demo_cfw.py"
        
        if demo_script.exists():
            try:
                subprocess.run([sys.executable, str(demo_script)], check=True)
            except subprocess.CalledProcessError as e:
                self.log(f"演示运行失败: {e}", "ERROR")
        else:
            self.log("演示脚本不存在，请先运行部署脚本", "ERROR")
    
    def run_verification(self):
        """运行效果验证"""
        self.log("启动CFW效果验证...")
        verify_script = self.project_root / "verify_effectiveness.py"
        
        if verify_script.exists():
            try:
                subprocess.run([sys.executable, str(verify_script)], check=True)
            except subprocess.CalledProcessError as e:
                self.log(f"验证运行失败: {e}", "ERROR")
        else:
            self.log("验证脚本不存在", "ERROR")
    
    def start_firewall(self):
        """启动防火墙"""
        self.log("启动CFW防火墙系统...")
        
        try:
            cmd = [
                sys.executable, str(self.main_script), 
                "start", 
                "--config", str(self.config_path)
            ]
            
            self.log("执行命令: " + " ".join(cmd))
            subprocess.run(cmd, check=True)
            
        except subprocess.CalledProcessError as e:
            self.log(f"防火墙启动失败: {e}", "ERROR")
        except KeyboardInterrupt:
            self.log("用户中断启动", "WARN")
    
    def show_threat_log(self):
        """显示威胁日志"""
        self.log("查看威胁日志...")
        
        try:
            hours = input("查看最近多少小时的记录? (默认24): ").strip()
            if not hours:
                hours = "24"
            
            cmd = [
                sys.executable, str(self.main_script),
                "threat-log",
                "--config", str(self.config_path),
                "--hours", hours
            ]
            
            subprocess.run(cmd, check=True)
            
        except subprocess.CalledProcessError as e:
            self.log(f"威胁日志查看失败: {e}", "ERROR")
    
    def show_threat_stats(self):
        """显示威胁统计"""
        self.log("查看威胁统计...")
        
        try:
            cmd = [
                sys.executable, str(self.main_script),
                "threat-stats", 
                "--config", str(self.config_path)
            ]
            
            subprocess.run(cmd, check=True)
            
        except subprocess.CalledProcessError as e:
            self.log(f"威胁统计查看失败: {e}", "ERROR")
    
    def export_report(self):
        """导出报告"""
        self.log("导出威胁报告...")
        
        try:
            hours = input("导出最近多少小时的数据? (默认48): ").strip()
            if not hours:
                hours = "48"
            
            output_file = input("报告文件名 (默认: threat_report.json): ").strip()
            if not output_file:
                output_file = "threat_report.json"
            
            cmd = [
                sys.executable, str(self.main_script),
                "export-report",
                "--config", str(self.config_path),
                "--output", output_file,
                "--hours", hours
            ]
            
            subprocess.run(cmd, check=True)
            
        except subprocess.CalledProcessError as e:
            self.log(f"报告导出失败: {e}", "ERROR")
    
    def check_config(self):
        """检查配置"""
        self.log("检查系统配置...")
        
        try:
            cmd = [
                sys.executable, str(self.main_script),
                "config-check",
                "--config", str(self.config_path)
            ]
            
            subprocess.run(cmd, check=True)
            
        except subprocess.CalledProcessError as e:
            self.log(f"配置检查失败: {e}", "ERROR")
    
    def advanced_options(self):
        """高级选项"""
        advanced_menu = """
🔧 高级选项:

1. 🔧 运行部署脚本
2. 🛠️  修改配置文件
3. 📁 打开日志目录
4. 🧹 清理日志文件
5. 📋 查看系统信息
6. 🔙 返回主菜单

请选择 (1-6): """
        
        choice = input(advanced_menu).strip()
        
        if choice == "1":
            deploy_script = self.project_root / "deploy_cfw.py"
            if deploy_script.exists():
                subprocess.run([sys.executable, str(deploy_script)])
            else:
                self.log("部署脚本不存在", "ERROR")
        
        elif choice == "2":
            self.log(f"配置文件位置: {self.config_path}")
            input("按Enter键继续...")
        
        elif choice == "3":
            logs_dir = self.project_root / "logs"
            if logs_dir.exists():
                import platform
                if platform.system() == "Windows":
                    os.startfile(str(logs_dir))
                else:
                    subprocess.run(["open" if platform.system() == "Darwin" else "xdg-open", str(logs_dir)])
            else:
                self.log("日志目录不存在", "ERROR")
        
        elif choice == "4":
            self.cleanup_logs()
        
        elif choice == "5":
            self.show_system_info()
        
        elif choice == "6":
            return
        
        else:
            self.log("无效选择", "WARN")
    
    def cleanup_logs(self):
        """清理日志文件"""
        self.log("清理日志文件...")
        
        logs_dir = self.project_root / "logs"
        if not logs_dir.exists():
            self.log("日志目录不存在", "WARN")
            return
        
        confirm = input("确定要清理所有日志文件吗? (y/N): ").strip().lower()
        if confirm != 'y':
            self.log("取消清理", "INFO")
            return
        
        try:
            import shutil
            shutil.rmtree(logs_dir)
            logs_dir.mkdir(exist_ok=True)
            (logs_dir / "threats").mkdir(exist_ok=True)
            self.log("日志文件已清理", "SUCCESS")
        except Exception as e:
            self.log(f"清理失败: {e}", "ERROR")
    
    def show_system_info(self):
        """显示系统信息"""
        self.log("系统信息:")
        
        import platform
        print(f"  操作系统: {platform.system()} {platform.release()}")
        print(f"  Python版本: {sys.version}")
        print(f"  项目路径: {self.project_root}")
        print(f"  配置文件: {self.config_path}")
        
        # 检查依赖模块
        modules_to_check = [
            'cryptography', 'requests', 'scapy', 'openai', 
            'anthropic', 'psutil', 'netifaces'
        ]
        
        print("  依赖模块:")
        for module in modules_to_check:
            try:
                __import__(module)
                print(f"    ✅ {module}")
            except ImportError:
                print(f"    ❌ {module} (未安装)")
        
        input("\n按Enter键继续...")
    
    def run(self):
        """运行主程序"""
        self.show_startup_banner()
        
        # 环境检查
        if not self.check_environment():
            self.log("环境检查失败，无法启动", "ERROR")
            return
        
        # 主循环
        while True:
            try:
                choice = self.show_menu()
                
                if choice == "1":
                    self.run_demo()
                elif choice == "2":
                    self.run_verification()
                elif choice == "3":
                    self.start_firewall()
                elif choice == "4":
                    self.show_threat_log()
                elif choice == "5":
                    self.show_threat_stats()
                elif choice == "6":
                    self.export_report()
                elif choice == "7":
                    self.check_config()
                elif choice == "8":
                    self.advanced_options()
                elif choice == "9":
                    self.log("感谢使用CFW防火墙系统！", "SUCCESS")
                    break
                else:
                    self.log("无效选择，请重新输入", "WARN")
                
                print()  # 空行分隔
                
            except KeyboardInterrupt:
                self.log("用户中断操作", "WARN")
                break
            except Exception as e:
                self.log(f"操作异常: {e}", "ERROR")

def main():
    """主函数"""
    launcher = CFWQuickStart()
    launcher.run()

if __name__ == "__main__":
    main()
