"""
证书分析器

分析SSL/TLS证书的有效性、安全性和信任状态
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import hashlib

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID, SignatureAlgorithmOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from ..base_processor import BaseProcessor


class CertificateAnalyzer(BaseProcessor):
    """证书分析器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("certificate_analyzer", config)
        
        self.cert_config = self.config.get('certificate_analysis', {})
        self.check_revocation = self.cert_config.get('check_revocation', False)
        self.check_ct_logs = self.cert_config.get('check_ct_logs', False)
        self.trust_store_path = self.cert_config.get('trust_store_path', None)
        
        # 弱签名算法
        self.weak_signature_algorithms = {
            'md5', 'sha1', 'md2', 'md4'
        }
        
        # 弱密钥长度阈值
        self.min_key_lengths = {
            'rsa': 2048,
            'dsa': 2048,
            'ec': 256
        }
        
        # 证书用途映射
        self.key_usage_names = {
            'digital_signature': '数字签名',
            'content_commitment': '内容承诺',
            'key_encipherment': '密钥加密',
            'data_encipherment': '数据加密',
            'key_agreement': '密钥协商',
            'key_cert_sign': '证书签名',
            'crl_sign': 'CRL签名',
            'encipher_only': '仅加密',
            'decipher_only': '仅解密'
        }
        
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("cryptography库未安装，证书分析功能不可用")
            self.available = False
        else:
            self.available = True
            self.logger.info("证书分析器初始化完成")
    
    def process_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析证书数据包
        
        Args:
            packet_data: 包含证书的数据包
            metadata: 元数据
            
        Returns:
            分析结果
        """
        if not self.available:
            return {
                'action': 'allow',
                'reason': 'Certificate analysis not available',
                'confidence': 0.0
            }
        
        try:
            analysis_result = {
                'action': 'allow',
                'reason': 'Certificate analysis completed',
                'confidence': 0.5,
                'certificate_analysis': {
                    'certificates_found': 0,
                    'certificate_details': [],
                    'chain_valid': False,
                    'trust_status': 'unknown',
                    'security_issues': [],
                    'recommendations': []
                }
            }
            
            # 提取并分析证书
            certificates = self._extract_certificates(packet_data)
            if certificates:
                analysis_result['certificate_analysis']['certificates_found'] = len(certificates)
                
                for i, cert in enumerate(certificates):
                    cert_analysis = self._analyze_certificate(cert)
                    cert_analysis['position'] = i  # 0为叶子证书，1为中间CA等
                    analysis_result['certificate_analysis']['certificate_details'].append(cert_analysis)
                
                # 分析证书链
                chain_analysis = self._analyze_certificate_chain(certificates)
                analysis_result['certificate_analysis'].update(chain_analysis)
                
                # 安全评估
                security_assessment = self._assess_certificate_security(
                    analysis_result['certificate_analysis']
                )
                analysis_result['certificate_analysis'].update(security_assessment)
                
                # 根据安全评估调整处理决策
                if security_assessment.get('risk_level') == 'high':
                    analysis_result['action'] = 'block'
                    analysis_result['reason'] = 'High-risk certificate detected'
                    analysis_result['confidence'] = 0.8
                elif security_assessment.get('risk_level') == 'medium':
                    analysis_result['reason'] = 'Medium-risk certificate'
                    analysis_result['confidence'] = 0.6
            
            self.stats['packets_processed'] += 1
            if analysis_result['action'] == 'block':
                self.stats['packets_blocked'] += 1
            else:
                self.stats['packets_allowed'] += 1
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"证书分析异常: {e}")
            return {
                'action': 'allow',
                'reason': f'Certificate analysis error: {str(e)}',
                'confidence': 0.0
            }
    
    def _extract_certificates(self, data: bytes) -> List[x509.Certificate]:
        """从数据包中提取证书"""
        certificates = []
        
        try:
            # 尝试多种证书格式
            
            # 1. 尝试DER格式
            try:
                cert = x509.load_der_x509_certificate(data)
                certificates.append(cert)
                return certificates
            except Exception:
                pass
            
            # 2. 尝试PEM格式
            try:
                cert = x509.load_pem_x509_certificate(data)
                certificates.append(cert)
                return certificates
            except Exception:
                pass
            
            # 3. 在TLS Certificate消息中查找证书
            certificates.extend(self._extract_from_tls_certificate(data))
            
        except Exception as e:
            self.logger.debug(f"证书提取失败: {e}")
        
        return certificates
    
    def _extract_from_tls_certificate(self, data: bytes) -> List[x509.Certificate]:
        """从TLS Certificate消息中提取证书"""
        certificates = []
        
        try:
            # 查找可能的证书数据
            # TLS Certificate消息格式较复杂，这里简化处理
            offset = 0
            while offset < len(data) - 3:
                # 查找可能的证书长度字段
                if offset + 3 < len(data):
                    cert_length = int.from_bytes(data[offset:offset+3], 'big')
                    if 100 < cert_length < 10000 and offset + 3 + cert_length <= len(data):
                        cert_data = data[offset+3:offset+3+cert_length]
                        try:
                            cert = x509.load_der_x509_certificate(cert_data)
                            certificates.append(cert)
                        except Exception:
                            pass
                offset += 1
                
        except Exception as e:
            self.logger.debug(f"TLS证书提取失败: {e}")
        
        return certificates
    
    def _analyze_certificate(self, cert: x509.Certificate) -> Dict[str, Any]:
        """分析单个证书"""
        analysis = {
            'subject': {},
            'issuer': {},
            'serial_number': '',
            'valid_from': '',
            'valid_to': '',
            'days_to_expiry': 0,
            'signature_algorithm': '',
            'public_key_algorithm': '',
            'public_key_size': 0,
            'key_usage': [],
            'extended_key_usage': [],
            'san_domains': [],
            'fingerprint_sha256': '',
            'is_ca': False,
            'is_self_signed': False,
            'issues': []
        }
        
        try:
            # 基本信息
            analysis['subject'] = self._parse_name(cert.subject)
            analysis['issuer'] = self._parse_name(cert.issuer)
            analysis['serial_number'] = str(cert.serial_number)
            
            # 有效期
            analysis['valid_from'] = cert.not_valid_before.isoformat()
            analysis['valid_to'] = cert.not_valid_after.isoformat()
            
            days_to_expiry = (cert.not_valid_after - datetime.utcnow()).days
            analysis['days_to_expiry'] = days_to_expiry
            
            # 签名算法
            analysis['signature_algorithm'] = cert.signature_algorithm_oid._name
            
            # 公钥信息
            public_key = cert.public_key()
            analysis['public_key_algorithm'] = public_key.__class__.__name__
            
            if hasattr(public_key, 'key_size'):
                analysis['public_key_size'] = public_key.key_size
            elif hasattr(public_key, 'curve'):
                analysis['public_key_size'] = public_key.curve.key_size
            
            # 指纹
            fingerprint = hashlib.sha256(cert.public_bytes()).hexdigest()
            analysis['fingerprint_sha256'] = fingerprint
            
            # 是否为CA证书
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
                analysis['is_ca'] = basic_constraints.value.ca
            except x509.ExtensionNotFound:
                analysis['is_ca'] = False
            
            # 密钥用途
            try:
                key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
                for usage_name in self.key_usage_names:
                    if hasattr(key_usage.value, usage_name) and getattr(key_usage.value, usage_name):
                        analysis['key_usage'].append(self.key_usage_names[usage_name])
            except x509.ExtensionNotFound:
                pass
            
            # 扩展密钥用途
            try:
                ext_key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
                analysis['extended_key_usage'] = [usage._name for usage in ext_key_usage.value]
            except x509.ExtensionNotFound:
                pass
            
            # SAN域名
            try:
                san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                analysis['san_domains'] = [name.value for name in san.value if isinstance(name, x509.DNSName)]
            except x509.ExtensionNotFound:
                pass
            
            # 检查是否自签名
            analysis['is_self_signed'] = cert.issuer == cert.subject
            
            # 检查证书问题
            analysis['issues'] = self._check_certificate_issues(cert, analysis)
            
        except Exception as e:
            self.logger.error(f"证书分析失败: {e}")
            analysis['issues'].append(f"Analysis error: {str(e)}")
        
        return analysis
    
    def _parse_name(self, name: x509.Name) -> Dict[str, str]:
        """解析证书名称"""
        name_dict = {}
        for attribute in name:
            oid_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
            name_dict[oid_name] = attribute.value
        return name_dict
    
    def _check_certificate_issues(self, cert: x509.Certificate, analysis: Dict[str, Any]) -> List[str]:
        """检查证书问题"""
        issues = []
        
        # 检查过期时间
        if analysis['days_to_expiry'] < 0:
            issues.append("Certificate has expired")
        elif analysis['days_to_expiry'] < 30:
            issues.append("Certificate expires within 30 days")
        
        # 检查签名算法
        sig_alg = analysis['signature_algorithm'].lower()
        if any(weak_alg in sig_alg for weak_alg in self.weak_signature_algorithms):
            issues.append(f"Weak signature algorithm: {analysis['signature_algorithm']}")
        
        # 检查密钥长度
        key_alg = analysis['public_key_algorithm'].lower()
        key_size = analysis['public_key_size']
        
        if 'rsa' in key_alg and key_size < self.min_key_lengths['rsa']:
            issues.append(f"RSA key too short: {key_size} bits")
        elif 'dsa' in key_alg and key_size < self.min_key_lengths['dsa']:
            issues.append(f"DSA key too short: {key_size} bits")
        elif 'ec' in key_alg and key_size < self.min_key_lengths['ec']:
            issues.append(f"EC key too short: {key_size} bits")
        
        # 检查证书有效期开始时间
        if cert.not_valid_before > datetime.utcnow():
            issues.append("Certificate not yet valid")
        
        # 检查是否自签名（对于非CA证书）
        if analysis['is_self_signed'] and not analysis['is_ca']:
            issues.append("Self-signed certificate")
        
        return issues
    
    def _analyze_certificate_chain(self, certificates: List[x509.Certificate]) -> Dict[str, Any]:
        """分析证书链"""
        chain_analysis = {
            'chain_length': len(certificates),
            'chain_valid': False,
            'chain_issues': []
        }
        
        if not certificates:
            return chain_analysis
        
        try:
            # 简化的证书链验证
            if len(certificates) == 1:
                # 单个证书
                cert = certificates[0]
                if cert.issuer == cert.subject:
                    chain_analysis['chain_issues'].append("Self-signed certificate")
                else:
                    chain_analysis['chain_issues'].append("Incomplete certificate chain")
            else:
                # 多个证书，检查链的连续性
                for i in range(len(certificates) - 1):
                    current_cert = certificates[i]
                    next_cert = certificates[i + 1]
                    
                    if current_cert.issuer != next_cert.subject:
                        chain_analysis['chain_issues'].append(f"Chain break between certificate {i} and {i+1}")
                
                # 检查根证书是否自签名
                root_cert = certificates[-1]
                if root_cert.issuer != root_cert.subject:
                    chain_analysis['chain_issues'].append("Root certificate is not self-signed")
            
            # 如果没有发现链问题，认为链有效
            chain_analysis['chain_valid'] = len(chain_analysis['chain_issues']) == 0
            
        except Exception as e:
            chain_analysis['chain_issues'].append(f"Chain analysis error: {str(e)}")
        
        return chain_analysis
    
    def _assess_certificate_security(self, cert_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """评估证书安全性"""
        security_issues = []
        recommendations = []
        risk_score = 0
        
        # 检查所有证书的问题
        for cert_detail in cert_analysis.get('certificate_details', []):
            issues = cert_detail.get('issues', [])
            security_issues.extend(issues)
            
            # 根据问题类型计算风险分数
            for issue in issues:
                if 'expired' in issue.lower():
                    risk_score += 30
                elif 'weak' in issue.lower():
                    risk_score += 20
                elif 'self-signed' in issue.lower():
                    risk_score += 15
                elif 'short' in issue.lower():
                    risk_score += 10
                else:
                    risk_score += 5
        
        # 检查证书链问题
        chain_issues = cert_analysis.get('chain_issues', [])
        security_issues.extend(chain_issues)
        risk_score += len(chain_issues) * 10
        
        # 生成建议
        if any('expired' in issue.lower() for issue in security_issues):
            recommendations.append("Renew expired certificates")
        
        if any('weak' in issue.lower() for issue in security_issues):
            recommendations.append("Update to stronger cryptographic algorithms")
        
        if any('self-signed' in issue.lower() for issue in security_issues):
            recommendations.append("Use certificates from trusted CA")
        
        if any('chain' in issue.lower() for issue in security_issues):
            recommendations.append("Fix certificate chain configuration")
        
        # 确定风险等级
        if risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 20:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'security_issues': list(set(security_issues)),  # 去重
            'recommendations': list(set(recommendations)),   # 去重
            'risk_level': risk_level,
            'risk_score': risk_score
        }
