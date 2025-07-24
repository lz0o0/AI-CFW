#!/usr/bin/env python3
"""
威胁管理功能测试脚本

测试敏感数据处理的不同策略：
1. 隐写替换
2. 拦截阻断
3. 静默记录
"""

import json
import os
import sys
import tempfile
from datetime import datetime

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.threat_log_manager import ThreatLogManager


def create_test_config():
    """创建测试配置"""
    config = {
        "threat_detection": {
            "threat_log_dir": "logs/threats",
            "log_rotation_days": 30,
            "sensitive_patterns": [
                {"pattern": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", "type": "credit_card"},
                {"pattern": r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b", "type": "ssn"},
                {"pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "type": "email"}
            ],
            "processing_strategy": "steganography",
            "show_popup_alerts": True,
            "steganography_text": "这是正常的业务数据传输内容。",
            "replacement_patterns": {
                "credit_card": "XXXX-XXXX-XXXX-XXXX",
                "ssn": "XXX-XX-XXXX",
                "email": "[EMAIL_PROTECTED]"
            }
        }
    }
    return config


def test_steganography_strategy():
    """测试隐写策略"""
    print("=== 测试隐写策略 ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config = create_test_config()
        config['threat_detection']['threat_log_dir'] = temp_dir
        config['threat_detection']['processing_strategy'] = 'steganography'
        
        manager = ThreatLogManager(config['threat_detection'])
        
        test_data = "用户信用卡号：4532-1234-5678-9012，请核实身份。"
        
        result = manager.process_sensitive_data(
            data=test_data,
            source_ip="192.168.1.100",
            dest_ip="10.0.0.50",
            threat_type="credit_card",
            risk_level="high"
        )
        
        print(f"原始数据: {test_data}")
        print(f"处理后数据: {result['processed_data']}")
        print(f"处理策略: {result['action_taken']}")
        print()


def test_block_strategy():
    """测试拦截策略"""
    print("=== 测试拦截策略 ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config = create_test_config()
        config['threat_detection']['threat_log_dir'] = temp_dir
        config['threat_detection']['processing_strategy'] = 'block'
        
        manager = ThreatLogManager(config['threat_detection'])
        
        test_data = "员工SSN：123-45-6789，薪资信息保密。"
        
        result = manager.process_sensitive_data(
            data=test_data,
            source_ip="192.168.1.200",
            dest_ip="10.0.0.60",
            threat_type="ssn",
            risk_level="critical"
        )
        
        print(f"原始数据: {test_data}")
        print(f"处理后数据: {result['processed_data']}")
        print(f"处理策略: {result['action_taken']}")
        print()


def test_silent_strategy():
    """测试静默策略"""
    print("=== 测试静默策略 ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config = create_test_config()
        config['threat_detection']['threat_log_dir'] = temp_dir
        config['threat_detection']['processing_strategy'] = 'silent'
        
        manager = ThreatLogManager(config['threat_detection'])
        
        test_data = "联系邮箱：john.doe@company.com，请及时回复。"
        
        result = manager.process_sensitive_data(
            data=test_data,
            source_ip="192.168.1.150",
            dest_ip="10.0.0.70",
            threat_type="email",
            risk_level="medium"
        )
        
        print(f"原始数据: {test_data}")
        print(f"处理后数据: {result['processed_data']}")
        print(f"处理策略: {result['action_taken']}")
        print()


def test_threat_log_analysis():
    """测试威胁日志分析"""
    print("=== 测试威胁日志分析 ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config = create_test_config()
        config['threat_detection']['threat_log_dir'] = temp_dir
        
        manager = ThreatLogManager(config['threat_detection'])
        
        # 生成多条测试记录
        test_cases = [
            ("4532-1234-5678-9012", "192.168.1.100", "credit_card", "high"),
            ("123-45-6789", "192.168.1.200", "ssn", "critical"),
            ("user@test.com", "192.168.1.150", "email", "medium"),
            ("5555-4444-3333-2222", "192.168.1.300", "credit_card", "high")
        ]
        
        for data, ip, threat_type, risk in test_cases:
            manager.process_sensitive_data(
                data=data,
                source_ip=ip,
                dest_ip="10.0.0.1",
                threat_type=threat_type,
                risk_level=risk
            )
        
        # 读取并分析日志
        log_file = os.path.join(temp_dir, "threat_log.json")
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                entries = [json.loads(line.strip()) for line in f if line.strip()]
            
            print(f"生成威胁记录数量: {len(entries)}")
            
            threat_types = {}
            for entry in entries:
                threat_type = entry['threat_type']
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            print("威胁类型统计:")
            for threat_type, count in threat_types.items():
                print(f"  {threat_type}: {count} 次")
        print()


def main():
    """主测试函数"""
    print("CFW 威胁管理功能测试")
    print("=" * 50)
    
    try:
        test_steganography_strategy()
        test_block_strategy()
        test_silent_strategy()
        test_threat_log_analysis()
        
        print("✓ 所有测试完成")
        
    except Exception as e:
        print(f"✗ 测试过程中出错: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
