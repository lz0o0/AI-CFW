"""
SSL解密内容处理器

专门处理SSL/TLS解密后的流量内容
支持：HTTP/HTTPS内容分析、API调用监控、敏感数据检测
"""

import logging
import json
import re
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, parse_qs
import base64

from ..base_processor import BaseProcessor


class SSLContentProcessor(BaseProcessor):
    """SSL解密内容处理器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("ssl_content_processor", config)
        
        self.ssl_config = self.config.get('ssl_processing', {})
        self.enable_ai_analysis = self.ssl_config.get('enable_ai_analysis', True)
        self.enable_api_monitoring = self.ssl_config.get('enable_api_monitoring', True)
        self.enable_data_leak_detection = self.ssl_config.get('enable_data_leak_detection', True)
        
        # HTTP协议解析规则
        self.http_patterns = {
            'request_line': re.compile(rb'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/([0-9.]+)'),
            'header': re.compile(rb'^([^:\r\n]+):\s*([^\r\n]*)'),
            'content_type': re.compile(rb'Content-Type:\s*([^\r\n;]+)', re.IGNORECASE),
            'content_length': re.compile(rb'Content-Length:\s*(\d+)', re.IGNORECASE),
            'authorization': re.compile(rb'Authorization:\s*([^\r\n]+)', re.IGNORECASE),
        }
        
        # API端点模式
        self.api_patterns = {
            'openai': re.compile(r'/v1/(chat/completions|completions|embeddings|images/generations)'),
            'anthropic': re.compile(r'/v1/(messages|complete)'),
            'google_ai': re.compile(r'/v1/(models|generateContent)'),
            'rest_api': re.compile(r'/api/v\d+/'),
            'graphql': re.compile(r'/graphql'),
        }
        
        # 敏感数据模式
        self.sensitive_patterns = {
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),
            'api_key': re.compile(r'\b[A-Za-z0-9]{32,}\b'),
            'jwt_token': re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
        }
        
        # AI分析器（如果启用）
        self.ai_analyzer = None
        if self.enable_ai_analysis:
            self._init_ai_analyzer()
        
        # 威胁日志管理器
        self.threat_manager = None
        self._init_threat_manager()
        
        self.logger.info("SSL内容处理器初始化完成")
    
    def _init_ai_analyzer(self):
        """初始化AI分析器"""
        try:
            from ..ai_content_analyzer import AIContentAnalyzer
            ai_config = self.config.get('ai_analysis', {})
            self.ai_analyzer = AIContentAnalyzer(ai_config)
            self.logger.info("AI分析器初始化成功")
        except ImportError as e:
            self.logger.warning(f"AI分析器初始化失败: {e}")
            self.enable_ai_analysis = False
    
    def _init_threat_manager(self):
        """初始化威胁日志管理器"""
        try:
            from ...core.threat_log_manager import ThreatLogManager
            self.threat_manager = ThreatLogManager(self.config)
            self.logger.info("威胁日志管理器初始化成功")
        except ImportError as e:
            self.logger.warning(f"威胁日志管理器初始化失败: {e}")
        except Exception as e:
            self.logger.error(f"威胁日志管理器初始化异常: {e}")
    
    def process_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理SSL解密后的数据包
        
        Args:
            packet_data: 解密后的数据包内容
            metadata: 数据包元数据
            
        Returns:
            处理结果字典
        """
        try:
            # 解析HTTP协议内容
            http_info = self._parse_http_content(packet_data)
            
            # 构建基础结果
            result = {
                'action': 'allow',
                'reason': 'SSL content processed',
                'confidence': 0.3,
                'ssl_analysis': {
                    'http_info': http_info,
                    'api_detected': False,
                    'sensitive_data_found': False,
                    'threat_indicators': []
                }
            }
            
            # API监控
            if self.enable_api_monitoring and http_info:
                api_analysis = self._analyze_api_calls(http_info, packet_data)
                result['ssl_analysis']['api_analysis'] = api_analysis
                if api_analysis.get('is_api_call', False):
                    result['ssl_analysis']['api_detected'] = True
            
            # 敏感数据检测
            if self.enable_data_leak_detection:
                sensitive_analysis = self._detect_sensitive_data(packet_data)
                result['ssl_analysis']['sensitive_analysis'] = sensitive_analysis
                if sensitive_analysis.get('sensitive_data_found', False):
                    result['ssl_analysis']['sensitive_data_found'] = True
                    result['confidence'] = 0.8
                    
                    # 使用威胁管理器处理敏感数据
                    if self.threat_manager and sensitive_analysis.get('matches'):
                        threat_result = self.threat_manager.handle_sensitive_data(
                            packet_data, metadata, sensitive_analysis['matches']
                        )
                        
                        # 根据威胁管理器的决策更新处理结果
                        if threat_result['action'] == 'block':
                            result['action'] = 'block'
                            result['reason'] = threat_result['reason']
                            result['confidence'] = 0.9
                        elif threat_result['action'] == 'modify':
                            result['action'] = 'modify'
                            result['modified_data'] = threat_result['modified_data']
                            result['reason'] = threat_result['reason']
                            result['confidence'] = 0.8
                        
                        result['ssl_analysis']['threat_id'] = threat_result.get('threat_id')
            
            # AI智能分析
            if self.enable_ai_analysis and self.ai_analyzer:
                ai_result = self._perform_ai_analysis(packet_data, metadata, http_info)
                result['ssl_analysis']['ai_analysis'] = ai_result
                
                # 根据AI分析结果调整处理决策
                if ai_result.get('threat_level') in ['high', 'critical']:
                    result['action'] = 'block'
                    result['reason'] = f"AI detected threat: {ai_result.get('threat_level')}"
                    result['confidence'] = 0.9
            
            # 威胁指标综合评估
            threat_score = self._calculate_threat_score(result['ssl_analysis'])
            if threat_score > 0.7:
                result['action'] = 'block'
                result['reason'] = f"High threat score: {threat_score:.2f}"
                result['confidence'] = threat_score
            
            self.stats['packets_processed'] += 1
            if result['action'] == 'block':
                self.stats['packets_blocked'] += 1
            else:
                self.stats['packets_allowed'] += 1
            
            return result
            
        except Exception as e:
            self.logger.error(f"SSL内容处理异常: {e}")
            return {
                'action': 'allow',
                'reason': f'Processing error: {str(e)}',
                'confidence': 0.0
            }
    
    def _parse_http_content(self, data: bytes) -> Optional[Dict[str, Any]]:
        """解析HTTP协议内容"""
        try:
            # 尝试将数据按行分割
            lines = data.split(b'\r\n')
            if not lines:
                return None
            
            # 解析请求行或响应行
            first_line = lines[0]
            http_info = {}
            
            # 检查是否为HTTP请求
            request_match = self.http_patterns['request_line'].match(first_line)
            if request_match:
                method, path, version = request_match.groups()
                http_info.update({
                    'type': 'request',
                    'method': method.decode('utf-8', errors='ignore'),
                    'path': path.decode('utf-8', errors='ignore'),
                    'version': version.decode('utf-8', errors='ignore'),
                    'headers': {},
                    'body': None
                })
            else:
                # 检查是否为HTTP响应
                if first_line.startswith(b'HTTP/'):
                    parts = first_line.split(b' ', 2)
                    if len(parts) >= 2:
                        http_info.update({
                            'type': 'response',
                            'version': parts[0].decode('utf-8', errors='ignore'),
                            'status_code': parts[1].decode('utf-8', errors='ignore'),
                            'status_text': parts[2].decode('utf-8', errors='ignore') if len(parts) > 2 else '',
                            'headers': {},
                            'body': None
                        })
            
            if not http_info:
                return None
            
            # 解析HTTP头部
            header_end_index = -1
            for i, line in enumerate(lines[1:], 1):
                if line == b'':  # 空行表示头部结束
                    header_end_index = i
                    break
                
                header_match = self.http_patterns['header'].match(line)
                if header_match:
                    name, value = header_match.groups()
                    header_name = name.decode('utf-8', errors='ignore').lower()
                    header_value = value.decode('utf-8', errors='ignore')
                    http_info['headers'][header_name] = header_value
            
            # 提取HTTP主体
            if header_end_index > 0 and header_end_index + 1 < len(lines):
                body_lines = lines[header_end_index + 1:]
                body_data = b'\r\n'.join(body_lines)
                if body_data:
                    http_info['body'] = body_data
            
            return http_info
            
        except Exception as e:
            self.logger.debug(f"HTTP解析失败: {e}")
            return None
    
    def _analyze_api_calls(self, http_info: Dict[str, Any], raw_data: bytes) -> Dict[str, Any]:
        """分析API调用"""
        analysis = {
            'is_api_call': False,
            'api_type': 'unknown',
            'endpoint': '',
            'method': '',
            'parameters': {},
            'payload': None
        }
        
        if not http_info or http_info.get('type') != 'request':
            return analysis
        
        path = http_info.get('path', '')
        method = http_info.get('method', '')
        
        # 检测API类型
        for api_type, pattern in self.api_patterns.items():
            if pattern.search(path):
                analysis.update({
                    'is_api_call': True,
                    'api_type': api_type,
                    'endpoint': path,
                    'method': method
                })
                break
        
        # 解析API参数
        if '?' in path:
            url_parts = path.split('?', 1)
            if len(url_parts) == 2:
                try:
                    params = parse_qs(url_parts[1])
                    analysis['parameters'] = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
                except Exception as e:
                    self.logger.debug(f"参数解析失败: {e}")
        
        # 解析请求体（JSON、表单数据等）
        if http_info.get('body'):
            body_data = http_info['body']
            content_type = http_info.get('headers', {}).get('content-type', '')
            
            try:
                if 'application/json' in content_type:
                    # JSON数据
                    json_str = body_data.decode('utf-8', errors='ignore')
                    analysis['payload'] = json.loads(json_str)
                elif 'application/x-www-form-urlencoded' in content_type:
                    # 表单数据
                    form_str = body_data.decode('utf-8', errors='ignore')
                    analysis['payload'] = parse_qs(form_str)
                else:
                    # 其他类型，保存原始数据（限制大小）
                    if len(body_data) < 1024:
                        analysis['payload'] = body_data.decode('utf-8', errors='ignore')
            except Exception as e:
                self.logger.debug(f"请求体解析失败: {e}")
        
        return analysis
    
    def _detect_sensitive_data(self, data: bytes) -> Dict[str, Any]:
        """检测敏感数据"""
        analysis = {
            'sensitive_data_found': False,
            'data_types': [],
            'matches': [],
            'risk_level': 'low'
        }
        
        try:
            # 转换为文本进行模式匹配
            text_data = data.decode('utf-8', errors='ignore')
            
            # 检测各种敏感数据模式
            for data_type, pattern in self.sensitive_patterns.items():
                matches = pattern.findall(text_data)
                if matches:
                    analysis['sensitive_data_found'] = True
                    analysis['data_types'].append(data_type)
                    
                    # 为威胁管理器准备详细的匹配信息
                    for match in matches[:5]:  # 限制匹配项数量
                        analysis['matches'].append({
                            'type': data_type,
                            'match': match,
                            'position': text_data.find(match),
                            'context': self._get_match_context(text_data, match, 20)
                        })
            
            # 评估风险等级
            if len(analysis['data_types']) >= 3:
                analysis['risk_level'] = 'critical'
            elif len(analysis['data_types']) >= 2:
                analysis['risk_level'] = 'high'
            elif analysis['sensitive_data_found']:
                analysis['risk_level'] = 'medium'
            
        except Exception as e:
            self.logger.debug(f"敏感数据检测失败: {e}")
        
        return analysis
    
    def _get_match_context(self, text: str, match: str, context_length: int) -> str:
        """获取匹配项的上下文"""
        try:
            match_pos = text.find(match)
            if match_pos == -1:
                return match
            
            start = max(0, match_pos - context_length)
            end = min(len(text), match_pos + len(match) + context_length)
            
            context = text[start:end]
            # 替换匹配项为星号以保护敏感信息
            context = context.replace(match, '*' * len(match))
            
            return context
        except Exception:
            return match
    
    def _perform_ai_analysis(self, data: bytes, metadata: Dict[str, Any], http_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """执行AI智能分析"""
        if not self.ai_analyzer:
            return {'error': 'AI analyzer not available'}
        
        try:
            # 准备分析内容
            text_content = data.decode('utf-8', errors='ignore')
            
            # 构建增强的元数据
            enhanced_metadata = {
                **metadata,
                'ssl_decrypted': True,
                'http_info': http_info
            }
            
            # 选择分析类型
            analysis_types = ['security_scan', 'threat_detection']
            if http_info and http_info.get('type') == 'request':
                analysis_types.append('behavior')
            
            # 执行AI分析
            ai_result = self.ai_analyzer.analyze_content(
                text_content, 
                analysis_types, 
                enhanced_metadata
            )
            
            return ai_result
            
        except Exception as e:
            self.logger.error(f"AI分析失败: {e}")
            return {'error': str(e)}
    
    def _calculate_threat_score(self, ssl_analysis: Dict[str, Any]) -> float:
        """计算威胁评分"""
        score = 0.0
        
        # 敏感数据检测权重
        sensitive_analysis = ssl_analysis.get('sensitive_analysis', {})
        if sensitive_analysis.get('sensitive_data_found', False):
            risk_level = sensitive_analysis.get('risk_level', 'low')
            risk_scores = {'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.9}
            score += risk_scores.get(risk_level, 0.0)
        
        # AI分析权重
        ai_analysis = ssl_analysis.get('ai_analysis', {})
        if ai_analysis and not ai_analysis.get('error'):
            threat_level = ai_analysis.get('threat_level', 'low')
            threat_scores = {'low': 0.1, 'medium': 0.4, 'high': 0.7, 'critical': 0.9}
            ai_score = threat_scores.get(threat_level, 0.0)
            confidence = ai_analysis.get('confidence_score', 0.5)
            score += ai_score * confidence
        
        # API调用风险权重
        api_analysis = ssl_analysis.get('api_analysis', {})
        if api_analysis.get('is_api_call', False):
            # API调用本身增加少量风险
            score += 0.1
            
            # 特定API类型风险评估
            api_type = api_analysis.get('api_type', '')
            if api_type in ['openai', 'anthropic']:  # AI服务API风险较高
                score += 0.2
        
        return min(score, 1.0)  # 确保分数不超过1.0
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        return {
            **self.stats,
            'ai_analysis_enabled': self.enable_ai_analysis,
            'api_monitoring_enabled': self.enable_api_monitoring,
            'data_leak_detection_enabled': self.enable_data_leak_detection,
            'ai_analyzer_available': self.ai_analyzer is not None
        }
