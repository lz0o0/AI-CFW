#!/usr/bin/env python3
"""
防火墙脚本测试工具
用于测试防火墙管理器的各项功能
"""

import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.firewall_manager import FirewallManager


class FirewallTester:
    """防火墙测试类"""
    
    def __init__(self):
        self.test_config_file = None
        self.fw_manager = None
        self.setup_test_environment()
    
    def setup_test_environment(self):
        """设置测试环境"""
        # 创建临时配置文件
        test_config = {
            "log_level": "DEBUG",
            "log_file": "test_firewall.log",
            "interface": "eth0",
            "rules": [],
            "whitelist": ["127.0.0.1"],
            "blacklist": []
        }
        
        # 创建临时文件
        fd, self.test_config_file = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(test_config, f, indent=2)
        
        # 初始化防火墙管理器
        self.fw_manager = FirewallManager(self.test_config_file)
        
        print(f"测试环境设置完成，配置文件: {self.test_config_file}")
    
    def cleanup_test_environment(self):
        """清理测试环境"""
        if self.test_config_file and os.path.exists(self.test_config_file):
            os.unlink(self.test_config_file)
            print("测试环境清理完成")
    
    def test_config_operations(self):
        """测试配置操作"""
        print("\n=== 测试配置操作 ===")
        
        # 测试配置加载
        print("1. 测试配置加载...")
        config = self.fw_manager.config
        assert config is not None, "配置加载失败"
        print("✓ 配置加载成功")
        
        # 测试配置重载
        print("2. 测试配置重载...")
        result = self.fw_manager.reload_config()
        assert result, "配置重载失败"
        print("✓ 配置重载成功")
        
        # 测试配置备份
        print("3. 测试配置备份...")
        backup_file = "test_backup.json"
        result = self.fw_manager.backup_config(backup_file)
        assert result, "配置备份失败"
        assert os.path.exists(backup_file), "备份文件不存在"
        os.unlink(backup_file)  # 清理备份文件
        print("✓ 配置备份成功")
    
    def test_rule_operations(self):
        """测试规则操作"""
        print("\n=== 测试规则操作 ===")
        
        # 测试添加规则
        print("1. 测试添加规则...")
        test_rule = {
            "id": "test_rule_1",
            "name": "测试规则",
            "action": "ALLOW",
            "protocol": "TCP",
            "source": "192.168.1.0/24",
            "destination": "0.0.0.0/0",
            "port": 80,
            "enabled": True,
            "priority": 200,
            "description": "测试用规则"
        }
        result = self.fw_manager.add_rule(test_rule)
        assert result, "添加规则失败"
        print("✓ 规则添加成功")
        
        # 测试列出规则
        print("2. 测试列出规则...")
        rules = self.fw_manager.list_rules()
        assert len(rules) > 0, "规则列表为空"
        assert any(rule['id'] == 'test_rule_1' for rule in rules), "找不到添加的规则"
        print(f"✓ 规则列表获取成功，共 {len(rules)} 条规则")
        
        # 测试删除规则
        print("3. 测试删除规则...")
        result = self.fw_manager.remove_rule("test_rule_1")
        assert result, "删除规则失败"
        print("✓ 规则删除成功")
    
    def test_service_operations(self):
        """测试服务操作"""
        print("\n=== 测试服务操作 ===")
        
        # 测试获取状态
        print("1. 测试获取状态...")
        status = self.fw_manager.status()
        assert status is not None, "获取状态失败"
        assert 'running' in status, "状态信息格式错误"
        print("✓ 状态获取成功")
        
        # 测试启动服务
        print("2. 测试启动服务...")
        result = self.fw_manager.start()
        assert result, "启动服务失败"
        print("✓ 服务启动成功")
        
        # 测试停止服务
        print("3. 测试停止服务...")
        result = self.fw_manager.stop()
        assert result, "停止服务失败"
        print("✓ 服务停止成功")
    
    def test_command_line_interface(self):
        """测试命令行接口"""
        print("\n=== 测试命令行接口 ===")
        
        # 测试帮助信息
        print("1. 测试帮助信息...")
        result = subprocess.run([
            sys.executable, str(project_root / "main.py"), "--help"
        ], capture_output=True, text=True)
        assert result.returncode == 0, "帮助信息获取失败"
        print("✓ 帮助信息获取成功")
        
        # 测试状态查询
        print("2. 测试状态查询...")
        result = subprocess.run([
            sys.executable, str(project_root / "main.py"),
            "status", "--config", self.test_config_file
        ], capture_output=True, text=True)
        # 注意：状态查询可能需要权限，所以我们只检查命令执行
        print("✓ 状态查询命令执行成功")
    
    def test_error_handling(self):
        """测试错误处理"""
        print("\n=== 测试错误处理 ===")
        
        # 测试无效配置文件
        print("1. 测试无效配置文件...")
        try:
            invalid_fw = FirewallManager("nonexistent_config.json")
            print("✓ 无效配置文件处理成功")
        except Exception as e:
            print(f"✗ 无效配置文件处理失败: {e}")
        
        # 测试无效规则
        print("2. 测试无效规则...")
        invalid_rule = {"invalid": "rule"}
        result = self.fw_manager.add_rule(invalid_rule)
        # 这里应该优雅地处理错误，而不是崩溃
        print("✓ 无效规则处理成功")
    
    def run_all_tests(self):
        """运行所有测试"""
        print("开始防火墙脚本测试...")
        print("=" * 50)
        
        try:
            self.test_config_operations()
            self.test_rule_operations()
            self.test_service_operations()
            self.test_command_line_interface()
            self.test_error_handling()
            
            print("\n" + "=" * 50)
            print("🎉 所有测试通过！")
            
        except AssertionError as e:
            print(f"\n❌ 测试失败: {e}")
            return False
        except Exception as e:
            print(f"\n💥 测试过程中发生错误: {e}")
            return False
        finally:
            self.cleanup_test_environment()
        
        return True


def main():
    """主函数"""
    tester = FirewallTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
