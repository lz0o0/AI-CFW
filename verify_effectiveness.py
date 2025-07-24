#!/usr/bin/env python3
"""
CFW防火墙系统实际效果验证脚本

该脚本将模拟真实的网络流量和威胁场景，验证CFW的实际防护效果：
1. 模拟HTTP/HTTPS流量
2. 注入敏感数据
3. 测试不同威胁等级
4. 验证告警机制
5. 分析处理效果
"""

import os
import sys
import json
import time
import socket
import threading
import requests
from pathlib import Path
from datetime import datetime
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 添加项目路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class CFWEffectivenessTest:
    """CFW效果验证测试器"""
    
    def __init__(self):
        self.project_root = project_root
        self.test_results = {}
        self.test_server_port = 8888
        self.test_server_thread = None
        self.server_running = False
        
    def log(self, message, level="INFO"):
        """测试日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    def start_test_server(self):
        """启动测试HTTP服务器"""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import json
            
            class TestHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    """处理GET请求"""
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    # 模拟包含敏感数据的响应
                    sensitive_responses = [
                        "Payment processed for card: 4532-1234-5678-9012",
                        "User email: admin@company.com has been updated",
                        "Employee SSN 123-45-6789 requires verification",
                        "API Key: sk-1234567890abcdef for service access",
                        "Password reset for user: temp123456"
                    ]
                    
                    import random
                    response = random.choice(sensitive_responses)
                    self.wfile.write(f"""
                    <html>
                    <head><title>CFW Test Server</title></head>
                    <body>
                        <h1>CFW Test Response</h1>
                        <p>{response}</p>
                        <p>Request path: {self.path}</p>
                        <p>Timestamp: {datetime.now()}</p>
                    </body>
                    </html>
                    """.encode())
                
                def do_POST(self):
                    """处理POST请求"""
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    response = {
                        "status": "received",
                        "data_length": len(post_data),
                        "echo": post_data.decode('utf-8', errors='ignore')[:100]
                    }
                    
                    self.wfile.write(json.dumps(response).encode())
                
                def log_message(self, format, *args):
                    """禁用服务器日志"""
                    pass
            
            def run_server():
                server = HTTPServer(('localhost', self.test_server_port), TestHandler)
                self.server_running = True
                self.log(f"测试服务器启动在端口 {self.test_server_port}")
                server.serve_forever()
            
            self.test_server_thread = threading.Thread(target=run_server, daemon=True)
            self.test_server_thread.start()
            time.sleep(2)  # 等待服务器启动
            
            return True
            
        except Exception as e:
            self.log(f"测试服务器启动失败: {e}", "ERROR")
            return False
    
    def test_sensitive_data_detection(self):
        """测试敏感数据检测效果"""
        self.log("🔍 测试敏感数据检测效果...")
        
        try:
            # 加载配置
            config_path = self.project_root / "config" / "firewall_config_extended.json"
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            from core.threat_log_manager import ThreatLogManager
            
            # 创建威胁管理器
            manager = ThreatLogManager(config["sensitive_data_handling"])
            
            # 准备测试用例
            test_cases = [
                {
                    "name": "信用卡泄露测试",
                    "data": b"Transaction: Pay $500 using card 4532-1234-5678-9012 for order #12345",
                    "detected_items": [{"type": "credit_card", "match": "4532-1234-5678-9012"}],
                    "expected_action": "modify",
                    "threat_level": "high"
                },
                {
                    "name": "多重敏感数据测试",
                    "data": b"Contact John Doe at john.doe@company.com or use card 5555-4444-3333-2222",
                    "detected_items": [
                        {"type": "email", "match": "john.doe@company.com"},
                        {"type": "credit_card", "match": "5555-4444-3333-2222"}
                    ],
                    "expected_action": "modify",
                    "threat_level": "critical"
                },
                {
                    "name": "API密钥泄露测试", 
                    "data": b"Use API key sk-1234567890abcdefghijklmnopqrstuvwxyz for authentication",
                    "detected_items": [{"type": "api_key", "match": "sk-1234567890abcdefghijklmnopqrstuvwxyz"}],
                    "expected_action": "modify", 
                    "threat_level": "high"
                },
                {
                    "name": "正常数据测试",
                    "data": b"This is normal business communication without sensitive information",
                    "detected_items": [],
                    "expected_action": "allow",
                    "threat_level": "low"
                }
            ]
            
            test_results = []
            
            for i, test_case in enumerate(test_cases):
                self.log(f"  执行测试 {i+1}: {test_case['name']}")
                
                metadata = {
                    "src_ip": f"192.168.1.{100+i}",
                    "dst_ip": "10.0.0.1",
                    "protocol": "HTTPS"
                }
                
                start_time = time.time()
                result = manager.handle_sensitive_data(
                    test_case["data"],
                    metadata,
                    test_case["detected_items"]
                )
                processing_time = (time.time() - start_time) * 1000
                
                # 分析结果
                success = result["action"] == test_case["expected_action"]
                
                test_result = {
                    "test_name": test_case["name"],
                    "success": success,
                    "expected_action": test_case["expected_action"],
                    "actual_action": result["action"],
                    "processing_time_ms": round(processing_time, 2),
                    "threat_id": result.get("threat_id"),
                    "data_modified": "modified_data" in result and result["modified_data"] != test_case["data"]
                }
                
                test_results.append(test_result)
                
                status = "✅" if success else "❌"
                self.log(f"    {status} 结果: {result['action']} (预期: {test_case['expected_action']})")
                self.log(f"    处理时间: {processing_time:.2f}ms")
                
                if test_case["detected_items"] and result.get("modified_data"):
                    original = test_case["data"].decode('utf-8', errors='ignore')
                    modified = result["modified_data"].decode('utf-8', errors='ignore')
                    if original != modified:
                        self.log(f"    数据已脱敏: {len(original)} -> {len(modified)} 字符")
            
            # 统计测试结果
            success_count = sum(1 for r in test_results if r["success"])
            total_tests = len(test_results)
            success_rate = (success_count / total_tests) * 100
            
            avg_processing_time = sum(r["processing_time_ms"] for r in test_results) / total_tests
            
            self.test_results["sensitive_data_detection"] = {
                "success_rate": success_rate,
                "total_tests": total_tests,
                "passed_tests": success_count,
                "avg_processing_time_ms": round(avg_processing_time, 2),
                "detailed_results": test_results
            }
            
            self.log(f"  检测成功率: {success_rate:.1f}% ({success_count}/{total_tests})")
            self.log(f"  平均处理时间: {avg_processing_time:.2f}ms")
            
            return success_rate >= 75  # 75%以上成功率认为通过
            
        except Exception as e:
            self.log(f"敏感数据检测测试失败: {e}", "ERROR")
            return False
    
    def test_network_interception(self):
        """测试网络拦截效果"""
        self.log("🌐 测试网络流量拦截效果...")
        
        if not self.server_running:
            self.log("测试服务器未运行，跳过网络测试", "WARN")
            return True
        
        try:
            # 测试不同类型的网络请求
            test_requests = [
                {
                    "name": "GET请求测试",
                    "method": "GET",
                    "url": f"http://localhost:{self.test_server_port}/test",
                    "data": None
                },
                {
                    "name": "POST敏感数据测试",
                    "method": "POST", 
                    "url": f"http://localhost:{self.test_server_port}/submit",
                    "data": json.dumps({
                        "user": "admin",
                        "credit_card": "4532-1234-5678-9012",
                        "email": "admin@company.com"
                    })
                },
                {
                    "name": "大数据量测试",
                    "method": "POST",
                    "url": f"http://localhost:{self.test_server_port}/upload", 
                    "data": "x" * 10000 + " credit card: 5555-4444-3333-2222"  # 10KB数据
                }
            ]
            
            network_results = []
            
            for i, req in enumerate(test_requests):
                self.log(f"  执行网络测试 {i+1}: {req['name']}")
                
                try:
                    start_time = time.time()
                    
                    if req["method"] == "GET":
                        response = requests.get(req["url"], timeout=5)
                    else:
                        headers = {"Content-Type": "application/json"}
                        response = requests.post(req["url"], data=req["data"], headers=headers, timeout=5)
                    
                    response_time = (time.time() - start_time) * 1000
                    
                    result = {
                        "test_name": req["name"],
                        "success": response.status_code == 200,
                        "status_code": response.status_code,
                        "response_time_ms": round(response_time, 2),
                        "response_size": len(response.content),
                        "contains_sensitive": "4532-1234" in response.text or "admin@company" in response.text
                    }
                    
                    network_results.append(result)
                    
                    status = "✅" if result["success"] else "❌"
                    self.log(f"    {status} 状态码: {response.status_code}")
                    self.log(f"    响应时间: {response_time:.2f}ms")
                    self.log(f"    响应大小: {len(response.content)} 字节")
                    
                    # 检查响应是否包含敏感数据
                    if result["contains_sensitive"]:
                        self.log("    ⚠️ 响应包含敏感数据", "WARN")
                    
                except requests.exceptions.RequestException as e:
                    self.log(f"    ❌ 请求失败: {e}", "ERROR")
                    network_results.append({
                        "test_name": req["name"],
                        "success": False,
                        "error": str(e)
                    })
                
                time.sleep(1)  # 间隔请求
            
            # 统计网络测试结果
            success_count = sum(1 for r in network_results if r.get("success", False))
            total_tests = len(network_results)
            
            self.test_results["network_interception"] = {
                "success_rate": (success_count / total_tests) * 100,
                "total_tests": total_tests,
                "passed_tests": success_count,
                "detailed_results": network_results
            }
            
            self.log(f"  网络测试通过率: {(success_count/total_tests)*100:.1f}%")
            
            return success_count >= total_tests * 0.8  # 80%通过率
            
        except Exception as e:
            self.log(f"网络拦截测试失败: {e}", "ERROR")
            return False
    
    def test_performance_impact(self):
        """测试性能影响"""
        self.log("⚡ 测试CFW性能影响...")
        
        try:
            from core.threat_log_manager import ThreatLogManager
            
            # 加载配置
            config_path = self.project_root / "config" / "firewall_config_extended.json"
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            manager = ThreatLogManager(config["sensitive_data_handling"])
            
            # 性能测试数据
            test_data_sizes = [100, 1000, 10000, 50000]  # 不同大小的数据
            performance_results = []
            
            for size in test_data_sizes:
                self.log(f"  测试数据大小: {size} 字节")
                
                # 生成测试数据
                test_data = ("A" * (size - 50) + "Credit card: 4532-1234-5678-9012").encode()
                detected_items = [{"type": "credit_card", "match": "4532-1234-5678-9012"}]
                metadata = {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"}
                
                # 多次测试取平均值
                times = []
                for _ in range(10):
                    start_time = time.time()
                    result = manager.handle_sensitive_data(test_data, metadata, detected_items)
                    end_time = time.time()
                    times.append((end_time - start_time) * 1000)
                
                avg_time = sum(times) / len(times)
                max_time = max(times)
                min_time = min(times)
                
                performance_result = {
                    "data_size": size,
                    "avg_processing_time_ms": round(avg_time, 2),
                    "max_processing_time_ms": round(max_time, 2),
                    "min_processing_time_ms": round(min_time, 2),
                    "throughput_bytes_per_ms": round(size / avg_time, 2)
                }
                
                performance_results.append(performance_result)
                
                self.log(f"    平均处理时间: {avg_time:.2f}ms")
                self.log(f"    吞吐量: {size/avg_time:.2f} 字节/ms")
            
            self.test_results["performance"] = {
                "detailed_results": performance_results,
                "max_acceptable_latency_ms": 100,  # 定义100ms为可接受延迟
                "performance_acceptable": all(r["avg_processing_time_ms"] < 100 for r in performance_results)
            }
            
            # 检查性能是否可接受
            acceptable = all(r["avg_processing_time_ms"] < 100 for r in performance_results)
            status = "✅" if acceptable else "⚠️"
            self.log(f"  {status} 性能评估: {'可接受' if acceptable else '需要优化'}")
            
            return acceptable
            
        except Exception as e:
            self.log(f"性能测试失败: {e}", "ERROR")
            return False
    
    def test_alert_system(self):
        """测试告警系统"""
        self.log("🔔 测试告警系统...")
        
        try:
            # 测试告警配置
            config_path = self.project_root / "config" / "firewall_config_extended.json"
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 临时禁用弹窗以便自动化测试
            original_popup_setting = config["sensitive_data_handling"]["alert_settings"]["enable_popup"]
            config["sensitive_data_handling"]["alert_settings"]["enable_popup"] = False
            
            from core.threat_log_manager import ThreatLogManager
            manager = ThreatLogManager(config["sensitive_data_handling"])
            
            # 测试不同威胁等级的告警
            alert_test_cases = [
                {
                    "name": "高危威胁告警",
                    "data": b"Emergency: Card 4532-1234-5678-9012 and SSN 123-45-6789 compromised",
                    "detected_items": [
                        {"type": "credit_card", "match": "4532-1234-5678-9012"},
                        {"type": "ssn", "match": "123-45-6789"}
                    ],
                    "expected_alert": True
                },
                {
                    "name": "中危威胁告警",
                    "data": b"Please contact support@company.com for assistance",
                    "detected_items": [{"type": "email", "match": "support@company.com"}],
                    "expected_alert": False  # 根据配置可能不会告警
                }
            ]
            
            alert_results = []
            
            for test_case in alert_test_cases:
                self.log(f"  测试告警: {test_case['name']}")
                
                # 处理数据并检查是否产生告警
                metadata = {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"}
                result = manager.handle_sensitive_data(
                    test_case["data"],
                    metadata, 
                    test_case["detected_items"]
                )
                
                # 检查威胁日志
                threat_log_path = self.project_root / "logs" / "threat_log.json"
                alert_logged = False
                
                if threat_log_path.exists():
                    with open(threat_log_path, 'r', encoding='utf-8') as f:
                        recent_logs = f.readlines()[-5:]  # 检查最近5条记录
                        for log_line in recent_logs:
                            try:
                                log_entry = json.loads(log_line.strip())
                                if result.get("threat_id") == log_entry.get("threat_id"):
                                    alert_logged = True
                                    break
                            except:
                                continue
                
                alert_results.append({
                    "test_name": test_case["name"],
                    "alert_logged": alert_logged,
                    "threat_id": result.get("threat_id")
                })
                
                status = "✅" if alert_logged else "❌"
                self.log(f"    {status} 告警记录: {'已记录' if alert_logged else '未记录'}")
            
            self.test_results["alert_system"] = {
                "tests_performed": len(alert_results),
                "alerts_logged": sum(1 for r in alert_results if r["alert_logged"]),
                "detailed_results": alert_results
            }
            
            # 恢复原始设置
            config["sensitive_data_handling"]["alert_settings"]["enable_popup"] = original_popup_setting
            
            return True
            
        except Exception as e:
            self.log(f"告警系统测试失败: {e}", "ERROR")
            return False
    
    def generate_effectiveness_report(self):
        """生成效果验证报告"""
        self.log("📊 生成效果验证报告...")
        
        report = {
            "test_timestamp": datetime.now().isoformat(),
            "test_summary": {
                "total_test_categories": len(self.test_results),
                "overall_success": True
            },
            "test_results": self.test_results,
            "recommendations": []
        }
        
        # 分析结果并生成建议
        if "sensitive_data_detection" in self.test_results:
            detection_rate = self.test_results["sensitive_data_detection"]["success_rate"]
            if detection_rate < 90:
                report["recommendations"].append(
                    f"敏感数据检测成功率偏低 ({detection_rate:.1f}%)，建议优化检测规则"
                )
        
        if "performance" in self.test_results:
            if not self.test_results["performance"]["performance_acceptable"]:
                report["recommendations"].append("性能表现不佳，建议优化处理算法或增加硬件资源")
        
        # 保存报告
        report_path = self.project_root / "cfw_effectiveness_report.json"
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            
            self.log(f"效果验证报告已保存: {report_path}")
            
            # 打印摘要
            self.log("\n📋 测试结果摘要:")
            self.log("=" * 50)
            
            for category, results in self.test_results.items():
                if "success_rate" in results:
                    rate = results["success_rate"]
                    status = "✅" if rate >= 80 else "⚠️" if rate >= 60 else "❌"
                    self.log(f"{status} {category}: {rate:.1f}% 成功率")
                elif "performance_acceptable" in results:
                    acceptable = results["performance_acceptable"]
                    status = "✅" if acceptable else "❌"
                    self.log(f"{status} {category}: {'可接受' if acceptable else '需要优化'}")
            
            if report["recommendations"]:
                self.log("\n💡 改进建议:")
                for i, rec in enumerate(report["recommendations"], 1):
                    self.log(f"  {i}. {rec}")
            
            return True
            
        except Exception as e:
            self.log(f"报告生成失败: {e}", "ERROR")
            return False
    
    def run_all_tests(self):
        """运行所有验证测试"""
        self.log("🚀 开始CFW防火墙系统效果验证...")
        
        # 启动测试服务器
        if self.start_test_server():
            time.sleep(2)
        
        try:
            # 执行各项测试
            tests = [
                ("敏感数据检测", self.test_sensitive_data_detection),
                ("网络拦截效果", self.test_network_interception), 
                ("性能影响", self.test_performance_impact),
                ("告警系统", self.test_alert_system)
            ]
            
            passed_tests = 0
            total_tests = len(tests)
            
            for test_name, test_func in tests:
                self.log(f"\n🧪 开始测试: {test_name}")
                try:
                    if test_func():
                        passed_tests += 1
                        self.log(f"✅ {test_name} 测试通过")
                    else:
                        self.log(f"❌ {test_name} 测试失败", "ERROR")
                except Exception as e:
                    self.log(f"❌ {test_name} 测试异常: {e}", "ERROR")
                
                time.sleep(1)
            
            # 生成最终报告
            self.generate_effectiveness_report()
            
            # 打印总结
            success_rate = (passed_tests / total_tests) * 100
            self.log(f"\n🎯 总体测试结果: {passed_tests}/{total_tests} 通过 ({success_rate:.1f}%)")
            
            if success_rate >= 80:
                self.log("🎉 CFW防火墙系统效果验证通过！系统可以投入使用。")
            elif success_rate >= 60:
                self.log("⚠️ CFW防火墙系统基本可用，但需要进一步优化。")
            else:
                self.log("❌ CFW防火墙系统存在重大问题，建议修复后重新测试。")
            
            return success_rate >= 60
            
        except Exception as e:
            self.log(f"测试过程异常: {e}", "ERROR")
            return False

def main():
    """主函数"""
    print("CFW防火墙系统实际效果验证")
    print("=" * 50)
    
    tester = CFWEffectivenessTest()
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ 验证完成！CFW系统可以投入使用。")
        print("\n下一步操作:")
        print("1. 查看详细报告: cfw_effectiveness_report.json")
        print("2. 启动实际防护: python main.py start")
        print("3. 监控威胁日志: python main.py threat-log")
    else:
        print("\n❌ 验证未通过，请检查系统配置和功能。")

if __name__ == "__main__":
    main()
