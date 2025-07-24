#!/usr/bin/env python3
"""
CFW防火墙系统部署和验证脚本

该脚本将：
1. 检查系统环境和依赖
2. 配置Python环境
3. 安装必要的依赖包
4. 验证系统功能
5. 提供部署建议
"""

import os
import sys
import subprocess
import json
import tempfile
import socket
import threading
import time
from pathlib import Path

class CFWDeploymentManager:
    """CFW部署管理器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.config_path = self.project_root / "config" / "firewall_config_extended.json"
        self.deployment_log = []
        
    def log(self, message, level="INFO"):
        """记录部署日志"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        self.deployment_log.append(log_entry)
        print(log_entry)
    
    def check_system_requirements(self):
        """检查系统需求"""
        self.log("🔍 检查系统需求...")
        
        # 检查Python版本
        python_version = sys.version_info
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
            self.log("❌ Python 3.8+ 是必需的", "ERROR")
            return False
        else:
            self.log(f"✅ Python版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        # 检查操作系统
        import platform
        os_info = platform.system()
        self.log(f"✅ 操作系统: {os_info} {platform.release()}")
        
        # 检查管理员权限（网络操作需要）
        try:
            if os_info == "Windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    self.log("⚠️ 建议以管理员权限运行以获得完整网络访问", "WARN")
            else:
                if os.geteuid() != 0:
                    self.log("⚠️ 建议以root权限运行以获得完整网络访问", "WARN")
        except:
            pass
        
        # 检查网络接口
        try:
            interfaces = socket.getaddrinfo(socket.gethostname(), None)
            self.log(f"✅ 网络接口可用: {len(interfaces)} 个接口")
        except Exception as e:
            self.log(f"⚠️ 网络接口检查失败: {e}", "WARN")
        
        return True
    
    def install_dependencies(self):
        """安装Python依赖"""
        self.log("📦 安装Python依赖...")
        
        requirements = [
            "cryptography>=3.0.0",
            "scapy>=2.4.5",
            "requests>=2.25.0",
            "openai>=1.0.0",
            "anthropic>=0.3.0",
            "psutil>=5.8.0",
            "netifaces>=0.11.0",
            "pyopenssl>=20.0.0"
        ]
        
        optional_requirements = [
            "tkinter",  # 通常已包含在Python中
            "winsound",  # Windows声音支持
            "playsound"  # 跨平台声音支持
        ]
        
        failed_packages = []
        
        for package in requirements:
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", package
                ], capture_output=True)
                self.log(f"✅ 安装成功: {package}")
            except subprocess.CalledProcessError as e:
                self.log(f"❌ 安装失败: {package} - {e}", "ERROR")
                failed_packages.append(package)
        
        # 尝试安装可选依赖
        for package in optional_requirements:
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", package
                ], capture_output=True)
                self.log(f"✅ 可选依赖安装成功: {package}")
            except subprocess.CalledProcessError:
                self.log(f"⚠️ 可选依赖安装失败: {package}", "WARN")
        
        if failed_packages:
            self.log(f"❌ 部分依赖安装失败: {failed_packages}", "ERROR")
            return False
        
        return True
    
    def create_ssl_certificates(self):
        """创建SSL证书"""
        self.log("🔐 创建SSL证书...")
        
        ssl_dir = self.project_root / "ssl_certs"
        ssl_dir.mkdir(exist_ok=True)
        
        ca_cert_path = ssl_dir / "ca.crt"
        ca_key_path = ssl_dir / "ca.key"
        
        if ca_cert_path.exists() and ca_key_path.exists():
            self.log("✅ SSL证书已存在")
            return True
        
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            # 生成私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # 创建CA证书
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CFW Firewall"),
                x509.NameAttribute(NameOID.COMMON_NAME, "CFW CA"),
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
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress("127.0.0.1"),
                ]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).sign(private_key, hashes.SHA256())
            
            # 保存证书和私钥
            with open(ca_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(ca_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            self.log("✅ SSL证书创建成功")
            return True
            
        except Exception as e:
            self.log(f"❌ SSL证书创建失败: {e}", "ERROR")
            return False
    
    def create_log_directories(self):
        """创建日志目录"""
        self.log("📁 创建日志目录...")
        
        directories = [
            "logs",
            "logs/threats",
            "logs/ssl",
            "logs/traffic"
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            dir_path.mkdir(exist_ok=True, parents=True)
            self.log(f"✅ 目录创建: {directory}")
    
    def validate_configuration(self):
        """验证配置文件"""
        self.log("⚙️ 验证配置文件...")
        
        if not self.config_path.exists():
            self.log(f"❌ 配置文件不存在: {self.config_path}", "ERROR")
            return False
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 验证必要的配置项
            required_sections = [
                'ssl',
                'dpi',
                'sensitive_data_handling',
                'logging',
                'processors'
            ]
            
            for section in required_sections:
                if section not in config:
                    self.log(f"❌ 缺少配置项: {section}", "ERROR")
                    return False
                else:
                    self.log(f"✅ 配置项验证: {section}")
            
            # 验证SSL证书路径
            ssl_config = config.get('ssl', {})
            ca_cert_path = ssl_config.get('ca_cert_path', '')
            ca_key_path = ssl_config.get('ca_key_path', '')
            
            if ca_cert_path and not os.path.exists(ca_cert_path):
                self.log(f"⚠️ SSL证书文件不存在: {ca_cert_path}", "WARN")
            
            if ca_key_path and not os.path.exists(ca_key_path):
                self.log(f"⚠️ SSL私钥文件不存在: {ca_key_path}", "WARN")
            
            self.log("✅ 配置文件验证通过")
            return True
            
        except json.JSONDecodeError as e:
            self.log(f"❌ 配置文件JSON格式错误: {e}", "ERROR")
            return False
        except Exception as e:
            self.log(f"❌ 配置文件验证失败: {e}", "ERROR")
            return False
    
    def test_threat_detection(self):
        """测试威胁检测功能"""
        self.log("🧪 测试威胁检测功能...")
        
        try:
            # 添加项目路径到系统路径
            sys.path.insert(0, str(self.project_root))
            
            from core.threat_log_manager import ThreatLogManager
            
            # 创建测试配置
            test_config = {
                "sensitive_data_handling": {
                    "strategy": "steganography",
                    "strategies": {
                        "steganography": {
                            "enabled": True,
                            "replacement_patterns": {
                                "credit_card": "****-****-****-****",
                                "email": "***@***.***"
                            }
                        }
                    },
                    "alert_settings": {
                        "enable_popup": False,  # 测试时禁用弹窗
                        "enable_sound": False,
                        "enable_email": False
                    },
                    "threat_log": {
                        "file_path": str(self.project_root / "logs" / "test_threat_log.json"),
                        "max_file_size": "10MB",
                        "backup_count": 5,
                        "retention_days": 30
                    }
                }
            }
            
            # 创建威胁管理器
            manager = ThreatLogManager(test_config["sensitive_data_handling"])
            
            # 测试用例
            test_cases = [
                {
                    "data": b"Credit card: 4532-1234-5678-9012",
                    "detected_items": [{"type": "credit_card", "match": "4532-1234-5678-9012"}],
                    "metadata": {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"}
                },
                {
                    "data": b"Email: test@example.com",
                    "detected_items": [{"type": "email", "match": "test@example.com"}],
                    "metadata": {"src_ip": "192.168.1.200", "dst_ip": "10.0.0.1"}
                }
            ]
            
            for i, test_case in enumerate(test_cases):
                result = manager.handle_sensitive_data(
                    test_case["data"],
                    test_case["metadata"],
                    test_case["detected_items"]
                )
                
                if result["action"] in ["modify", "allow"]:
                    self.log(f"✅ 测试用例 {i+1} 通过: {result['action']}")
                else:
                    self.log(f"❌ 测试用例 {i+1} 失败: {result}", "ERROR")
                    return False
            
            self.log("✅ 威胁检测功能测试通过")
            return True
            
        except ImportError as e:
            self.log(f"❌ 模块导入失败: {e}", "ERROR")
            return False
        except Exception as e:
            self.log(f"❌ 威胁检测测试失败: {e}", "ERROR")
            return False
    
    def test_ssl_processing(self):
        """测试SSL处理功能"""
        self.log("🔒 测试SSL处理功能...")
        
        try:
            # 测试SSL证书加载
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            ca_cert_path = self.project_root / "ssl_certs" / "ca.crt"
            ca_key_path = self.project_root / "ssl_certs" / "ca.key"
            
            if ca_cert_path.exists():
                with open(ca_cert_path, 'rb') as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data)
                    self.log(f"✅ SSL证书加载成功: {cert.subject}")
            
            if ca_key_path.exists():
                with open(ca_key_path, 'rb') as f:
                    key_data = f.read()
                    private_key = serialization.load_pem_private_key(key_data, password=None)
                    self.log("✅ SSL私钥加载成功")
            
            return True
            
        except Exception as e:
            self.log(f"❌ SSL处理测试失败: {e}", "ERROR")
            return False
    
    def create_demo_script(self):
        """创建演示脚本"""
        self.log("📝 创建演示脚本...")
        
        demo_script = self.project_root / "demo_cfw.py"
        
        demo_content = '''#!/usr/bin/env python3
"""
CFW防火墙系统演示脚本

该脚本演示CFW的主要功能：
1. 敏感数据检测和处理
2. SSL流量分析
3. 威胁日志记录
4. 弹窗告警
"""

import sys
import os
import time
import json
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.threat_log_manager import ThreatLogManager

def demo_sensitive_data_detection():
    """演示敏感数据检测"""
    print("\\n🔍 敏感数据检测演示")
    print("=" * 50)
    
    # 加载配置
    config_path = project_root / "config" / "firewall_config_extended.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    # 创建威胁管理器
    manager = ThreatLogManager(config["sensitive_data_handling"])
    
    # 演示数据
    test_scenarios = [
        {
            "name": "信用卡信息检测",
            "data": b"Please process payment with card 4532-1234-5678-9012",
            "detected_items": [{"type": "credit_card", "match": "4532-1234-5678-9012"}],
            "metadata": {"src_ip": "192.168.1.100", "dst_ip": "payment.server.com"}
        },
        {
            "name": "邮箱地址检测", 
            "data": b"Contact us at support@company.com for assistance",
            "detected_items": [{"type": "email", "match": "support@company.com"}],
            "metadata": {"src_ip": "192.168.1.200", "dst_ip": "mail.server.com"}
        },
        {
            "name": "社会保险号检测",
            "data": b"Employee SSN: 123-45-6789",
            "detected_items": [{"type": "ssn", "match": "123-45-6789"}],
            "metadata": {"src_ip": "192.168.1.150", "dst_ip": "hr.system.com"}
        }
    ]
    
    for scenario in test_scenarios:
        print(f"\\n🧪 {scenario['name']}")
        print(f"原始数据: {scenario['data'].decode()}")
        
        result = manager.handle_sensitive_data(
            scenario["data"],
            scenario["metadata"], 
            scenario["detected_items"]
        )
        
        print(f"处理动作: {result['action']}")
        if result.get('modified_data'):
            print(f"处理后数据: {result['modified_data'].decode()}")
        print(f"原因: {result['reason']}")
        
        time.sleep(1)  # 暂停以便观察

def demo_threat_statistics():
    """演示威胁统计"""
    print("\\n📊 威胁统计演示")
    print("=" * 50)
    
    # 加载配置
    config_path = project_root / "config" / "firewall_config_extended.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    manager = ThreatLogManager(config["sensitive_data_handling"])
    
    # 获取统计信息
    stats = manager.get_threat_stats()
    print("威胁统计信息:")
    print(f"  总威胁数: {stats['total_threats']}")
    print(f"  按等级分布: {stats['threats_by_level']}")
    print(f"  按类型分布: {stats['threats_by_type']}")
    print(f"  处理动作分布: {stats['actions_taken']}")

def demo_threat_log_export():
    """演示威胁日志导出"""
    print("\\n📤 威胁日志导出演示")
    print("=" * 50)
    
    config_path = project_root / "config" / "firewall_config_extended.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    manager = ThreatLogManager(config["sensitive_data_handling"])
    
    # 导出报告
    report_path = project_root / "demo_threat_report.json"
    success = manager.export_threat_report(str(report_path), hours=24)
    
    if success:
        print(f"✅ 威胁报告已导出到: {report_path}")
        if report_path.exists():
            with open(report_path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            print(f"报告时间范围: {report.get('time_range_hours', 0)} 小时")
            print(f"威胁数量: {len(report.get('threats', []))}")
    else:
        print("❌ 报告导出失败")

def main():
    """主演示函数"""
    print("🚀 CFW防火墙系统功能演示")
    print("=" * 60)
    
    try:
        demo_sensitive_data_detection()
        demo_threat_statistics()
        demo_threat_log_export()
        
        print("\\n✅ 演示完成！")
        print("\\n💡 提示:")
        print("  - 查看 logs/threat_log.json 了解详细威胁记录")
        print("  - 修改 config/firewall_config_extended.json 调整检测策略")
        print("  - 运行 'python main.py threat-stats' 查看实时统计")
        
    except Exception as e:
        print(f"\\n❌ 演示过程中出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
'''
        
        try:
            with open(demo_script, 'w', encoding='utf-8') as f:
                f.write(demo_content)
            self.log("✅ 演示脚本创建成功")
            return True
        except Exception as e:
            self.log(f"❌ 演示脚本创建失败: {e}", "ERROR")
            return False
    
    def generate_deployment_report(self):
        """生成部署报告"""
        self.log("📋 生成部署报告...")
        
        report_path = self.project_root / "deployment_report.txt"
        
        report_content = f"""
CFW防火墙系统部署报告
=====================

部署时间: {time.strftime('%Y-%m-%d %H:%M:%S')}
项目路径: {self.project_root}

部署日志:
--------
"""
        
        for log_entry in self.deployment_log:
            report_content += f"{log_entry}\n"
        
        report_content += f"""

下一步操作建议:
--------------

1. 基础功能测试:
   python demo_cfw.py

2. 启动防火墙系统:
   python main.py start --config config/firewall_config_extended.json

3. 查看威胁日志:
   python main.py threat-log --hours 24

4. 查看威胁统计:
   python main.py threat-stats

5. 导出威胁报告:
   python main.py export-report --output report.json --hours 48

配置说明:
--------
- 配置文件: config/firewall_config_extended.json
- 威胁检测策略: 当前为 'steganography' (隐写替换)
- 弹窗告警: 已启用
- 日志目录: logs/
- SSL证书: ssl_certs/

常见问题:
--------
1. 权限不足: 以管理员身份运行
2. 端口被占用: 修改配置文件中的端口设置
3. 依赖缺失: 运行 pip install -r requirements.txt
4. SSL证书问题: 重新运行部署脚本生成证书

技术支持:
--------
查看文档: docs/
测试脚本: tests/
演示脚本: demo_cfw.py
"""
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            self.log(f"✅ 部署报告已生成: {report_path}")
            return True
        except Exception as e:
            self.log(f"❌ 部署报告生成失败: {e}", "ERROR")
            return False
    
    def deploy(self):
        """执行完整部署流程"""
        self.log("🚀 开始CFW防火墙系统部署...")
        
        # 显示部署位置建议
        self._show_deployment_recommendations()
        
        success = True
        
        # 检查系统需求
        if not self.check_system_requirements():
            success = False
        
        # 安装依赖
        if success and not self.install_dependencies():
            success = False
        
        # 创建SSL证书
        if success:
            self.create_ssl_certificates()
        
        # 创建日志目录
        if success:
            self.create_log_directories()
        
        # 验证配置
        if success and not self.validate_configuration():
            success = False
        
        # 测试功能
        if success:
            self.test_threat_detection()
            self.test_ssl_processing()
        
        # 创建演示脚本
        if success:
            self.create_demo_script()
        
        # 生成部署报告
        self.generate_deployment_report()
        
        if success:
            self.log("🎉 CFW防火墙系统部署完成！")
            self.log("运行 'python demo_cfw.py' 开始体验功能")
            self.log("运行 'python deployment_orchestrator.py' 获取高级部署选项")
        else:
            self.log("❌ 部署过程中遇到问题，请查看日志", "ERROR")
        
        return success
    
    def _show_deployment_recommendations(self):
        """显示部署位置建议"""
        self.log("🏗️ CFW防火墙部署位置分析...")
        
        import platform
        import socket
        
        # 检测系统环境
        system_info = {
            "os": platform.system(),
            "architecture": platform.machine(),
            "cpu_count": os.cpu_count(),
            "hostname": socket.gethostname()
        }
        
        # 检测虚拟化
        is_virtual = self._detect_virtualization()
        
        # 检测容器环境
        is_container = self._detect_container()
        
        # 检测云平台
        cloud_platform = self._detect_cloud_platform()
        
        self.log("📊 系统环境分析:")
        self.log(f"  操作系统: {system_info['os']}")
        self.log(f"  架构: {system_info['architecture']}")
        self.log(f"  CPU核心: {system_info['cpu_count']}")
        self.log(f"  虚拟化: {'是' if is_virtual else '否'}")
        self.log(f"  容器环境: {is_container if is_container else '否'}")
        self.log(f"  云平台: {cloud_platform if cloud_platform else '本地环境'}")
        
        # 生成部署建议
        recommendations = []
        
        if cloud_platform:
            recommendations.append(f"☁️ 检测到{cloud_platform.upper()}云环境，建议使用云原生部署")
        
        if is_container == "kubernetes":
            recommendations.append("☸️ 检测到Kubernetes环境，建议使用DaemonSet部署")
        elif is_container == "docker":
            recommendations.append("🐳 检测到Docker环境，建议使用容器部署")
        
        if is_virtual:
            recommendations.append("🖥️ 检测到虚拟化环境，适合透明代理模式")
        else:
            recommendations.append("🏗️ 物理服务器环境，适合网关模式部署")
        
        if system_info["cpu_count"] <= 2:
            recommendations.append("📱 CPU核心较少，适合边缘设备轻量部署")
        elif system_info["cpu_count"] >= 8:
            recommendations.append("💪 CPU核心充足，支持高性能模式")
        
        self.log("💡 部署建议:")
        for rec in recommendations:
            self.log(f"  {rec}")
        
        self.log("📚 详细部署选项请参考: docs/DEPLOYMENT_OPTIONS.md")
        self.log("🔧 高级部署配置请运行: python deployment_orchestrator.py")
    
    def _detect_virtualization(self):
        """检测虚拟化环境"""
        try:
            # 检查DMI信息
            if os.path.exists("/sys/class/dmi/id/product_name"):
                with open("/sys/class/dmi/id/product_name", "r") as f:
                    product = f.read().strip().lower()
                    if any(vm in product for vm in ["vmware", "virtualbox", "kvm", "virtual"]):
                        return True
            
            # 检查CPU信息
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                    if any(vendor in cpuinfo.lower() for vendor in ["vmware", "virtualbox", "kvm", "xen"]):
                        return True
                        
            return False
        except:
            return False
    
    def _detect_container(self):
        """检测容器环境"""
        # 检查Docker环境
        if os.path.exists("/.dockerenv"):
            return "docker"
        
        # 检查Kubernetes环境
        if os.environ.get("KUBERNETES_SERVICE_HOST"):
            return "kubernetes"
        
        # 检查cgroup
        try:
            with open("/proc/1/cgroup", "r") as f:
                cgroup = f.read()
                if "docker" in cgroup or "containerd" in cgroup:
                    return "docker"
        except:
            pass
        
        return None
    
    def _detect_cloud_platform(self):
        """检测云平台"""
        try:
            import urllib.request
            
            # AWS检测
            try:
                urllib.request.urlopen("http://169.254.169.254/latest/meta-data/", timeout=2)
                return "aws"
            except:
                pass
            
            # Azure检测
            try:
                req = urllib.request.Request("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
                req.add_header("Metadata", "true")
                urllib.request.urlopen(req, timeout=2)
                return "azure"
            except:
                pass
            
            # GCP检测
            try:
                req = urllib.request.Request("http://metadata.google.internal/computeMetadata/v1/")
                req.add_header("Metadata-Flavor", "Google")
                urllib.request.urlopen(req, timeout=2)
                return "gcp"
            except:
                pass
                
        except:
            pass
        
        return None

def main():
    """主函数"""
    print("CFW防火墙系统自动部署工具")
    print("=" * 50)
    
    deployer = CFWDeploymentManager()
    deployer.deploy()

if __name__ == "__main__":
    main()
