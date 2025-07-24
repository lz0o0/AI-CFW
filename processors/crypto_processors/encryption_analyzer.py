"""
加密算法分析器

分析SSL/TLS连接中使用的加密算法、协议版本和安全特性
"""

import logging
from typing import Dict, Any, Optional, List
import struct

from ..base_processor import BaseProcessor


class EncryptionAnalyzer(BaseProcessor):
    """加密算法分析器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("encryption_analyzer", config)
        
        # TLS版本映射
        self.tls_versions = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0", 
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3"
        }
        
        # 密码套件映射（部分常用的）
        self.cipher_suites = {
            0x0001: "TLS_RSA_WITH_NULL_MD5",
            0x0002: "TLS_RSA_WITH_NULL_SHA",
            0x0004: "TLS_RSA_WITH_RC4_128_MD5",
            0x0005: "TLS_RSA_WITH_RC4_128_SHA",
            0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0x1303: "TLS_CHACHA20_POLY1305_SHA256"
        }
        
        # 弱加密算法
        self.weak_ciphers = {
            "NULL", "RC4", "DES", "3DES", "MD5"
        }
        
        # 安全评级
        self.security_ratings = {
            "weak": ["NULL", "RC4", "DES", "3DES", "MD5"],
            "medium": ["CBC", "SHA1"],
            "strong": ["GCM", "CCM", "POLY1305", "SHA256", "SHA384"],
            "excellent": ["TLS 1.3", "ECDHE", "AES", "CHACHA20"]
        }
        
        self.logger.info("加密算法分析器初始化完成")
    
    def process_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析加密数据包
        
        Args:
            packet_data: TLS数据包
            metadata: 元数据
            
        Returns:
            分析结果
        """
        try:
            analysis_result = {
                'action': 'allow',
                'reason': 'Encryption analysis completed',
                'confidence': 0.5,
                'encryption_analysis': {
                    'tls_version': 'unknown',
                    'cipher_suite': 'unknown',
                    'security_level': 'unknown',
                    'vulnerabilities': [],
                    'recommendations': []
                }
            }
            
            # 分析TLS握手消息
            tls_info = self._analyze_tls_handshake(packet_data)
            if tls_info:
                analysis_result['encryption_analysis'].update(tls_info)
                
                # 安全评估
                security_assessment = self._assess_security(tls_info)
                analysis_result['encryption_analysis'].update(security_assessment)
                
                # 根据安全等级调整处理决策
                if security_assessment.get('security_level') == 'weak':
                    analysis_result['action'] = 'block'
                    analysis_result['reason'] = 'Weak encryption detected'
                    analysis_result['confidence'] = 0.8
                elif security_assessment.get('security_level') == 'medium':
                    analysis_result['reason'] = 'Medium security encryption'
                    analysis_result['confidence'] = 0.6
            
            self.stats['packets_processed'] += 1
            if analysis_result['action'] == 'block':
                self.stats['packets_blocked'] += 1
            else:
                self.stats['packets_allowed'] += 1
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"加密分析异常: {e}")
            return {
                'action': 'allow',
                'reason': f'Analysis error: {str(e)}',
                'confidence': 0.0
            }
    
    def _analyze_tls_handshake(self, data: bytes) -> Optional[Dict[str, Any]]:
        """分析TLS握手消息"""
        if len(data) < 5:
            return None
        
        try:
            # TLS记录头部格式：类型(1) + 版本(2) + 长度(2)
            content_type = data[0]
            version = struct.unpack('>H', data[1:3])[0]
            length = struct.unpack('>H', data[3:5])[0]
            
            tls_info = {
                'record_type': content_type,
                'tls_version': self.tls_versions.get(version, f"Unknown (0x{version:04x})"),
                'record_length': length
            }
            
            # 如果是握手消息 (content_type == 22)
            if content_type == 22 and len(data) > 9:
                handshake_type = data[5]
                handshake_length = struct.unpack('>I', b'\x00' + data[6:9])[0]
                
                tls_info.update({
                    'handshake_type': handshake_type,
                    'handshake_length': handshake_length
                })
                
                # Client Hello 消息 (handshake_type == 1)
                if handshake_type == 1:
                    client_hello_info = self._parse_client_hello(data[9:])
                    if client_hello_info:
                        tls_info.update(client_hello_info)
                
                # Server Hello 消息 (handshake_type == 2)
                elif handshake_type == 2:
                    server_hello_info = self._parse_server_hello(data[9:])
                    if server_hello_info:
                        tls_info.update(server_hello_info)
            
            return tls_info
            
        except Exception as e:
            self.logger.debug(f"TLS握手分析失败: {e}")
            return None
    
    def _parse_client_hello(self, data: bytes) -> Optional[Dict[str, Any]]:
        """解析Client Hello消息"""
        if len(data) < 34:
            return None
        
        try:
            # Client Hello格式：版本(2) + 随机数(32) + 会话ID长度(1) + ...
            client_version = struct.unpack('>H', data[0:2])[0]
            session_id_length = data[34]
            
            info = {
                'client_version': self.tls_versions.get(client_version, f"Unknown (0x{client_version:04x})"),
                'session_id_length': session_id_length
            }
            
            # 跳过会话ID，解析密码套件
            offset = 35 + session_id_length
            if offset + 2 <= len(data):
                cipher_suites_length = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                
                cipher_suites = []
                for i in range(0, cipher_suites_length, 2):
                    if offset + i + 2 <= len(data):
                        suite_id = struct.unpack('>H', data[offset+i:offset+i+2])[0]
                        suite_name = self.cipher_suites.get(suite_id, f"Unknown (0x{suite_id:04x})")
                        cipher_suites.append(suite_name)
                
                info['cipher_suites'] = cipher_suites
            
            return info
            
        except Exception as e:
            self.logger.debug(f"Client Hello解析失败: {e}")
            return None
    
    def _parse_server_hello(self, data: bytes) -> Optional[Dict[str, Any]]:
        """解析Server Hello消息"""
        if len(data) < 38:
            return None
        
        try:
            # Server Hello格式：版本(2) + 随机数(32) + 会话ID长度(1) + 会话ID + 密码套件(2) + ...
            server_version = struct.unpack('>H', data[0:2])[0]
            session_id_length = data[34]
            
            offset = 35 + session_id_length
            if offset + 2 <= len(data):
                selected_cipher = struct.unpack('>H', data[offset:offset+2])[0]
                cipher_name = self.cipher_suites.get(selected_cipher, f"Unknown (0x{selected_cipher:04x})")
                
                return {
                    'server_version': self.tls_versions.get(server_version, f"Unknown (0x{server_version:04x})"),
                    'selected_cipher': cipher_name,
                    'selected_cipher_id': selected_cipher
                }
            
        except Exception as e:
            self.logger.debug(f"Server Hello解析失败: {e}")
            return None
    
    def _assess_security(self, tls_info: Dict[str, Any]) -> Dict[str, Any]:
        """评估加密安全性"""
        vulnerabilities = []
        recommendations = []
        security_score = 0
        
        # 检查TLS版本
        tls_version = tls_info.get('tls_version', '')
        if 'SSL' in tls_version or 'TLS 1.0' in tls_version or 'TLS 1.1' in tls_version:
            vulnerabilities.append("Outdated TLS version")
            recommendations.append("Upgrade to TLS 1.2 or 1.3")
            security_score -= 30
        elif 'TLS 1.2' in tls_version:
            security_score += 20
        elif 'TLS 1.3' in tls_version:
            security_score += 30
        
        # 检查密码套件
        selected_cipher = tls_info.get('selected_cipher', '')
        cipher_suites = tls_info.get('cipher_suites', [])
        
        # 检查选定的密码套件
        for weak_cipher in self.weak_ciphers:
            if weak_cipher in selected_cipher:
                vulnerabilities.append(f"Weak cipher: {weak_cipher}")
                recommendations.append(f"Avoid {weak_cipher} cipher")
                security_score -= 20
        
        # 检查是否支持弱密码套件
        weak_suites_supported = []
        for suite in cipher_suites:
            for weak_cipher in self.weak_ciphers:
                if weak_cipher in suite:
                    weak_suites_supported.append(suite)
        
        if weak_suites_supported:
            vulnerabilities.append("Supports weak cipher suites")
            recommendations.append("Disable weak cipher suites")
            security_score -= 10
        
        # 检查前向保密
        if 'ECDHE' in selected_cipher or 'DHE' in selected_cipher:
            security_score += 15
        else:
            vulnerabilities.append("No forward secrecy")
            recommendations.append("Use ECDHE or DHE cipher suites")
            security_score -= 15
        
        # 检查认证加密
        if 'GCM' in selected_cipher or 'CCM' in selected_cipher or 'POLY1305' in selected_cipher:
            security_score += 15
        elif 'CBC' in selected_cipher:
            vulnerabilities.append("CBC mode cipher")
            recommendations.append("Use GCM or other AEAD ciphers")
            security_score -= 5
        
        # 确定安全等级
        if security_score >= 50:
            security_level = 'excellent'
        elif security_score >= 20:
            security_level = 'strong'
        elif security_score >= -10:
            security_level = 'medium'
        else:
            security_level = 'weak'
        
        return {
            'security_level': security_level,
            'security_score': security_score,
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations
        }
