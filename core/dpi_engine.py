"""
深度包检测引擎 - 负责分析网络流量内容
"""

import re
import logging
import threading
import time
from typing import Dict, Any, List, Optional, Tuple, Pattern
from enum import Enum
import json
from collections import defaultdict


class TrafficType(Enum):
    """流量类型枚举"""
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """威胁等级枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DPIEngine:
    """深度包检测引擎主类"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化DPI引擎
        
        Args:
            config: 配置字典
        """
        self.config = config
        self.logger = logging.getLogger('DPIEngine')
        
        # DPI规则
        self.detection_rules = self._load_detection_rules()
        self.threat_patterns = self._load_threat_patterns()
        self.llm_patterns = self._load_llm_patterns()
        
        # 运行状态
        self.is_running = False
        
        # 统计信息
        self.stats = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'llm_traffic_detected': 0,
            'protocol_stats': defaultdict(int),
            'threat_stats': defaultdict(int),
            'analysis_time_total': 0.0,
            'start_time': None
        }
        
        # 检测缓存
        self.detection_cache = {}
        self.cache_lock = threading.Lock()
        self.max_cache_size = 1000
        
        self.logger.info("DPI引擎初始化完成")
    
    def _load_detection_rules(self) -> Dict[str, List[Pattern]]:
        """加载检测规则"""
        rules = {
            'http': [
                re.compile(rb'GET\s+.*HTTP/1\.[01]', re.IGNORECASE),
                re.compile(rb'POST\s+.*HTTP/1\.[01]', re.IGNORECASE),
                re.compile(rb'PUT\s+.*HTTP/1\.[01]', re.IGNORECASE),
                re.compile(rb'DELETE\s+.*HTTP/1\.[01]', re.IGNORECASE),
            ],
            'https': [
                re.compile(rb'\x16\x03[\x00-\x03]'),  # TLS handshake
                re.compile(rb'\x15\x03[\x00-\x03]'),  # TLS alert
                re.compile(rb'\x17\x03[\x00-\x03]'),  # TLS application data
            ],
            'ftp': [
                re.compile(rb'220\s+.*FTP', re.IGNORECASE),
                re.compile(rb'USER\s+\w+', re.IGNORECASE),
                re.compile(rb'PASS\s+\w+', re.IGNORECASE),
            ],
            'smtp': [
                re.compile(rb'220\s+.*SMTP', re.IGNORECASE),
                re.compile(rb'HELO\s+', re.IGNORECASE),
                re.compile(rb'MAIL FROM:', re.IGNORECASE),
                re.compile(rb'RCPT TO:', re.IGNORECASE),
            ],
            'dns': [
                re.compile(rb'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'),  # DNS query
                re.compile(rb'\x81\x80\x00\x01'),  # DNS response
            ]
        }
        
        self.logger.info(f"加载了 {len(rules)} 类检测规则")
        return rules
    
    def _load_threat_patterns(self) -> Dict[str, List[Pattern]]:
        """加载威胁检测模式"""
        patterns = {
            'sql_injection': [
                re.compile(rb'(union\s+select|select\s+.*from|insert\s+into|update\s+.*set|delete\s+from)', re.IGNORECASE),
                re.compile(rb'(\'\s*or\s*\'\s*=\s*\'|\'\s*or\s*1\s*=\s*1)', re.IGNORECASE),
                re.compile(rb'(drop\s+table|drop\s+database)', re.IGNORECASE),
            ],
            'xss': [
                re.compile(rb'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
                re.compile(rb'javascript:', re.IGNORECASE),
                re.compile(rb'on\w+\s*=\s*["\'].*?["\']', re.IGNORECASE),
            ],
            'malware_signatures': [
                re.compile(rb'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*'),  # EICAR
                re.compile(rb'wannacry|petya|ransomware', re.IGNORECASE),
                re.compile(rb'metasploit|meterpreter', re.IGNORECASE),
            ],
            'suspicious_commands': [
                re.compile(rb'(cmd\.exe|powershell\.exe|bash|sh)\s+', re.IGNORECASE),
                re.compile(rb'(wget|curl|nc|netcat)\s+', re.IGNORECASE),
                re.compile(rb'(base64|certutil)\s+', re.IGNORECASE),
            ]
        }
        
        self.logger.info(f"加载了 {len(patterns)} 类威胁模式")
        return patterns
    
    def _load_llm_patterns(self) -> Dict[str, List[Pattern]]:
        """加载LLM流量检测模式"""
        patterns = {
            'openai_api': [
                re.compile(rb'api\.openai\.com', re.IGNORECASE),
                re.compile(rb'Bearer\s+sk-[a-zA-Z0-9]{48}', re.IGNORECASE),
                re.compile(rb'"model"\s*:\s*"gpt-[34]', re.IGNORECASE),
                re.compile(rb'/v1/(chat/)?completions', re.IGNORECASE),
            ],
            'anthropic_api': [
                re.compile(rb'api\.anthropic\.com', re.IGNORECASE),
                re.compile(rb'x-api-key\s*:\s*sk-ant-', re.IGNORECASE),
                re.compile(rb'"model"\s*:\s*"claude-', re.IGNORECASE),
            ],
            'google_ai': [
                re.compile(rb'generativelanguage\.googleapis\.com', re.IGNORECASE),
                re.compile(rb'"model"\s*:\s*"gemini-', re.IGNORECASE),
                re.compile(rb'/v1beta/models/', re.IGNORECASE),
            ],
            'local_llm': [
                re.compile(rb'ollama|llamacpp|text-generation-webui', re.IGNORECASE),
                re.compile(rb'localhost:[0-9]{4,5}/(api|v1)', re.IGNORECASE),
                re.compile(rb'"temperature"\s*:\s*[0-9.]+', re.IGNORECASE),
            ],
            'ai_content': [
                re.compile(rb'"prompt"\s*:\s*".*?"', re.IGNORECASE | re.DOTALL),
                re.compile(rb'"messages"\s*:\s*\[', re.IGNORECASE),
                re.compile(rb'"role"\s*:\s*"(user|assistant|system)"', re.IGNORECASE),
                re.compile(rb'"content"\s*:\s*".*?"', re.IGNORECASE | re.DOTALL),
            ]
        }
        
        self.logger.info(f"加载了 {len(patterns)} 类LLM检测模式")
        return patterns
    
    def start(self) -> bool:
        """
        启动DPI引擎
        
        Returns:
            bool: 启动是否成功
        """
        if self.is_running:
            self.logger.warning("DPI引擎已在运行")
            return False
        
        try:
            self.logger.info("启动DPI引擎")
            self.is_running = True
            self.stats['start_time'] = time.time()
            
            self.logger.info("DPI引擎启动成功")
            return True
            
        except Exception as e:
            self.logger.error(f"DPI引擎启动失败: {e}")
            return False
    
    def stop(self) -> bool:
        """
        停止DPI引擎
        
        Returns:
            bool: 停止是否成功
        """
        if not self.is_running:
            self.logger.warning("DPI引擎未在运行")
            return False
        
        try:
            self.logger.info("停止DPI引擎")
            self.is_running = False
            
            # 清理缓存
            with self.cache_lock:
                self.detection_cache.clear()
            
            self.logger.info("DPI引擎已停止")
            return True
            
        except Exception as e:
            self.logger.error(f"DPI引擎停止失败: {e}")
            return False
    
    def analyze_packet(self, packet_data: bytes, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        分析数据包
        
        Args:
            packet_data: 数据包数据
            metadata: 元数据（如源IP、目标IP等）
            
        Returns:
            Dict: 分析结果
        """
        start_time = time.time()
        
        try:
            # 检查缓存
            cache_key = hash(packet_data[:100])  # 使用前100字节作为缓存键
            with self.cache_lock:
                if cache_key in self.detection_cache:
                    return self.detection_cache[cache_key]
            
            result = {
                'packet_size': len(packet_data),
                'protocol': self._detect_protocol(packet_data),
                'threats': self._detect_threats(packet_data),
                'llm_indicators': self._detect_llm_traffic(packet_data),
                'analysis_time': 0.0,
                'metadata': metadata or {}
            }
            
            # 更新统计信息
            self.stats['packets_analyzed'] += 1
            self.stats['protocol_stats'][result['protocol']] += 1
            
            if result['threats']:
                self.stats['threats_detected'] += 1
                for threat in result['threats']:
                    self.stats['threat_stats'][threat['type']] += 1
            
            if result['llm_indicators']:
                self.stats['llm_traffic_detected'] += 1
            
            # 记录分析时间
            analysis_time = time.time() - start_time
            result['analysis_time'] = analysis_time
            self.stats['analysis_time_total'] += analysis_time
            
            # 添加到缓存
            with self.cache_lock:
                if len(self.detection_cache) >= self.max_cache_size:
                    # 清理旧缓存项
                    oldest_key = next(iter(self.detection_cache))
                    del self.detection_cache[oldest_key]
                
                self.detection_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            self.logger.error(f"数据包分析失败: {e}")
            return {
                'packet_size': len(packet_data),
                'protocol': TrafficType.UNKNOWN.value,
                'threats': [],
                'llm_indicators': [],
                'analysis_time': time.time() - start_time,
                'error': str(e)
            }
    
    def _detect_protocol(self, packet_data: bytes) -> str:
        """检测协议类型"""
        for protocol, patterns in self.detection_rules.items():
            for pattern in patterns:
                if pattern.search(packet_data):
                    return protocol
        
        return TrafficType.UNKNOWN.value
    
    def _detect_threats(self, packet_data: bytes) -> List[Dict[str, Any]]:
        """检测威胁"""
        threats = []
        
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(packet_data)
                if matches:
                    threat = {
                        'type': threat_type,
                        'level': self._assess_threat_level(threat_type),
                        'matches': len(matches),
                        'pattern_matched': pattern.pattern.decode('utf-8', errors='ignore')[:100]
                    }
                    threats.append(threat)
        
        return threats
    
    def _detect_llm_traffic(self, packet_data: bytes) -> List[Dict[str, Any]]:
        """检测LLM相关流量"""
        indicators = []
        
        for indicator_type, patterns in self.llm_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(packet_data)
                if matches:
                    indicator = {
                        'type': indicator_type,
                        'confidence': self._calculate_llm_confidence(indicator_type, matches),
                        'matches': len(matches),
                        'pattern_matched': pattern.pattern.decode('utf-8', errors='ignore')[:100]
                    }
                    indicators.append(indicator)
        
        return indicators
    
    def _assess_threat_level(self, threat_type: str) -> str:
        """评估威胁等级"""
        threat_levels = {
            'sql_injection': ThreatLevel.HIGH.value,
            'xss': ThreatLevel.MEDIUM.value,
            'malware_signatures': ThreatLevel.CRITICAL.value,
            'suspicious_commands': ThreatLevel.HIGH.value
        }
        
        return threat_levels.get(threat_type, ThreatLevel.LOW.value)
    
    def _calculate_llm_confidence(self, indicator_type: str, matches: List) -> float:
        """计算LLM流量检测置信度"""
        base_confidence = {
            'openai_api': 0.95,
            'anthropic_api': 0.95,
            'google_ai': 0.90,
            'local_llm': 0.80,
            'ai_content': 0.70
        }
        
        confidence = base_confidence.get(indicator_type, 0.50)
        
        # 根据匹配数量调整置信度
        match_bonus = min(len(matches) * 0.05, 0.20)
        confidence = min(confidence + match_bonus, 1.0)
        
        return round(confidence, 2)
    
    def analyze_flow(self, packets: List[bytes], metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        分析数据流
        
        Args:
            packets: 数据包列表
            metadata: 流元数据
            
        Returns:
            Dict: 流分析结果
        """
        try:
            flow_result = {
                'total_packets': len(packets),
                'total_bytes': sum(len(p) for p in packets),
                'protocols': set(),
                'threats': [],
                'llm_indicators': [],
                'flow_metadata': metadata or {}
            }
            
            # 分析每个数据包
            for packet in packets:
                packet_result = self.analyze_packet(packet, metadata)
                flow_result['protocols'].add(packet_result['protocol'])
                flow_result['threats'].extend(packet_result['threats'])
                flow_result['llm_indicators'].extend(packet_result['llm_indicators'])
            
            # 转换协议集合为列表
            flow_result['protocols'] = list(flow_result['protocols'])
            
            # 去重和统计
            flow_result['unique_threats'] = len(set(t['type'] for t in flow_result['threats']))
            flow_result['unique_llm_indicators'] = len(set(i['type'] for i in flow_result['llm_indicators']))
            
            return flow_result
            
        except Exception as e:
            self.logger.error(f"数据流分析失败: {e}")
            return {
                'total_packets': len(packets),
                'total_bytes': sum(len(p) for p in packets),
                'error': str(e)
            }
    
    def get_status(self) -> Dict[str, Any]:
        """
        获取DPI引擎状态
        
        Returns:
            Dict: 状态信息
        """
        return {
            'running': self.is_running,
            'detection_rules_loaded': len(self.detection_rules),
            'threat_patterns_loaded': len(self.threat_patterns),
            'llm_patterns_loaded': len(self.llm_patterns),
            'cache_size': len(self.detection_cache),
            'max_cache_size': self.max_cache_size
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取统计信息
        
        Returns:
            Dict: 统计信息
        """
        stats = self.stats.copy()
        
        # 计算平均分析时间
        if stats['packets_analyzed'] > 0:
            stats['avg_analysis_time'] = stats['analysis_time_total'] / stats['packets_analyzed']
        else:
            stats['avg_analysis_time'] = 0
        
        # 计算运行时间
        if stats['start_time']:
            stats['uptime'] = time.time() - stats['start_time']
        else:
            stats['uptime'] = 0
        
        # 转换defaultdict为普通dict
        stats['protocol_stats'] = dict(stats['protocol_stats'])
        stats['threat_stats'] = dict(stats['threat_stats'])
        
        return stats
    
    def add_custom_rule(self, rule_type: str, pattern: str, is_regex: bool = True) -> bool:
        """
        添加自定义检测规则
        
        Args:
            rule_type: 规则类型
            pattern: 匹配模式
            is_regex: 是否为正则表达式
            
        Returns:
            bool: 添加是否成功
        """
        try:
            if is_regex:
                compiled_pattern = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
            else:
                compiled_pattern = re.compile(re.escape(pattern.encode() if isinstance(pattern, str) else pattern))
            
            if rule_type not in self.detection_rules:
                self.detection_rules[rule_type] = []
            
            self.detection_rules[rule_type].append(compiled_pattern)
            self.logger.info(f"添加自定义规则: {rule_type} - {pattern}")
            return True
            
        except Exception as e:
            self.logger.error(f"添加自定义规则失败: {e}")
            return False
    
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
            
            # 重新加载规则
            self.detection_rules = self._load_detection_rules()
            self.threat_patterns = self._load_threat_patterns()
            self.llm_patterns = self._load_llm_patterns()
            
            # 清理缓存
            with self.cache_lock:
                self.detection_cache.clear()
            
            self.logger.info("DPI引擎配置重载成功")
            return True
        except Exception as e:
            self.logger.error(f"DPI引擎配置重载失败: {e}")
            return False


def main():
    """主函数，用于直接运行测试"""
    config = {}
    
    dpi = DPIEngine(config)
    
    print("=== DPI引擎测试 ===")
    print(f"初始状态: {dpi.get_status()}")
    
    print("\n启动DPI引擎...")
    if dpi.start():
        print("启动成功")
        
        # 测试数据包分析
        test_packets = [
            b'GET /api/chat HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-test123\r\n\r\n',
            b'POST /v1/completions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"model": "gpt-3.5-turbo"}',
            b'SELECT * FROM users WHERE id=1 OR 1=1',
            b'<script>alert("xss")</script>',
        ]
        
        print("\n分析测试数据包...")
        for i, packet in enumerate(test_packets):
            print(f"\n--- 数据包 {i+1} ---")
            result = dpi.analyze_packet(packet)
            print(f"协议: {result['protocol']}")
            print(f"威胁数量: {len(result['threats'])}")
            print(f"LLM指标数量: {len(result['llm_indicators'])}")
            print(f"分析时间: {result['analysis_time']:.4f}秒")
        
        print(f"\n最终统计: {dpi.get_statistics()}")
        
        print("\n停止DPI引擎...")
        if dpi.stop():
            print("停止成功")
    else:
        print("启动失败")


if __name__ == "__main__":
    main()
