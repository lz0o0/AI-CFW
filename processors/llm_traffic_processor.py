"""
LLM流量检测处理器

专门用于检测和分析可能的LLM（大语言模型）相关流量
"""

import re
import json
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
import base64

from .base_processor import BaseProcessor


class LLMTrafficProcessor(BaseProcessor):
    """LLM流量检测处理器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("llm_traffic_detector", config)
        
        # LLM服务的已知特征
        self.llm_indicators = {
            # 域名特征
            'domains': [
                'openai.com', 'api.openai.com',
                'anthropic.com', 'claude.ai',
                'cohere.ai', 'cohere.com',
                'huggingface.co',
                'replicate.com',
                'together.ai',
                'fireworks.ai',
                'groq.com',
                'mistral.ai',
                'perplexity.ai'
            ],
            
            # API端点特征
            'api_endpoints': [
                '/v1/chat/completions',
                '/v1/completions',
                '/v1/embeddings',
                '/v1/images/generations',
                '/api/v1/chat',
                '/api/v1/complete',
                '/v1/engines/',
                '/chat/completions'
            ],
            
            # 请求头特征
            'headers': [
                'authorization: bearer sk-',
                'authorization: bearer eyj',  # JWT tokens
                'openai-organization',
                'anthropic-version',
                'x-api-key',
                'cohere-version'
            ],
            
            # 内容特征
            'content_patterns': [
                r'"model":\s*"(gpt-|claude-|command-|text-)',
                r'"messages":\s*\[',
                r'"prompt":\s*"',
                r'"max_tokens":\s*\d+',
                r'"temperature":\s*[\d.]+',
                r'"top_p":\s*[\d.]+',
                r'"frequency_penalty"',
                r'"presence_penalty"',
                r'"system":\s*"',
                r'"user":\s*"',
                r'"assistant":\s*"'
            ]
        }
        
        # 配置选项
        self.block_llm_traffic = config.get('block_llm_traffic', False)
        self.log_llm_requests = config.get('log_llm_requests', True)
        self.extract_prompts = config.get('extract_prompts', True)
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        
        # 统计信息
        self.llm_stats = {
            'llm_requests_detected': 0,
            'llm_requests_blocked': 0,
            'llm_providers': {},
            'extracted_prompts': []
        }
    
    def process_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """处理数据包，检测LLM流量"""
        try:
            # 基本检查
            if not self._is_http_traffic(metadata):
                return {'action': 'allow', 'reason': '非HTTP流量'}
            
            # 解析HTTP内容
            http_content = self._extract_http_content(packet_data)
            if not http_content:
                return {'action': 'allow', 'reason': '无法解析HTTP内容'}
            
            # LLM流量检测
            detection_result = self._detect_llm_traffic(http_content, metadata)
            
            if detection_result['is_llm_traffic']:
                self.llm_stats['llm_requests_detected'] += 1
                
                # 更新提供商统计
                provider = detection_result.get('provider', 'unknown')
                self.llm_stats['llm_providers'][provider] = \
                    self.llm_stats['llm_providers'].get(provider, 0) + 1
                
                # 提取和记录提示词
                if self.extract_prompts and detection_result.get('extracted_data'):
                    self._log_extracted_data(detection_result['extracted_data'], metadata)
                
                # 决定处理动作
                if self.block_llm_traffic:
                    self.llm_stats['llm_requests_blocked'] += 1
                    return {
                        'action': 'block',
                        'reason': f'检测到LLM流量 - 提供商: {provider}',
                        'confidence': detection_result['confidence'],
                        'details': detection_result
                    }
                else:
                    if self.log_llm_requests:
                        self.logger.info(f"检测到LLM流量: {provider} - 置信度: {detection_result['confidence']:.2f}")
                    
                    return {
                        'action': 'allow',
                        'reason': f'LLM流量已记录 - 提供商: {provider}',
                        'confidence': detection_result['confidence'],
                        'details': detection_result
                    }
            
            return {'action': 'allow', 'reason': '非LLM流量'}
            
        except Exception as e:
            self.logger.error(f"LLM流量检测错误: {e}")
            return {'action': 'allow', 'reason': f'检测错误: {str(e)}'}
    
    def _is_http_traffic(self, metadata: Dict[str, Any]) -> bool:
        """检查是否为HTTP流量"""
        dest_port = metadata.get('dest_port', 0)
        protocol = metadata.get('protocol', '').lower()
        
        return (protocol == 'tcp' and dest_port in [80, 443, 8080, 8443]) or \
               metadata.get('is_http', False)
    
    def _extract_http_content(self, packet_data: bytes) -> Optional[str]:
        """提取HTTP内容"""
        try:
            # 简化的HTTP内容提取
            content = packet_data.decode('utf-8', errors='ignore')
            
            # 查找HTTP请求/响应的开始
            if 'HTTP/' in content or any(method in content for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                return content
                
            return None
        except Exception:
            return None
    
    def _detect_llm_traffic(self, http_content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """检测LLM流量"""
        confidence = 0.0
        indicators = []
        provider = 'unknown'
        extracted_data = {}
        
        # 检查域名
        domain_confidence = self._check_domain_indicators(http_content, metadata)
        if domain_confidence > 0:
            confidence += domain_confidence * 0.4
            indicators.append('domain_match')
            provider = self._identify_provider_by_domain(http_content)
        
        # 检查API端点
        endpoint_confidence = self._check_endpoint_indicators(http_content)
        if endpoint_confidence > 0:
            confidence += endpoint_confidence * 0.3
            indicators.append('api_endpoint_match')
        
        # 检查请求头
        header_confidence = self._check_header_indicators(http_content)
        if header_confidence > 0:
            confidence += header_confidence * 0.2
            indicators.append('header_match')
        
        # 检查内容模式
        content_confidence, content_data = self._check_content_patterns(http_content)
        if content_confidence > 0:
            confidence += content_confidence * 0.1
            indicators.append('content_pattern_match')
            extracted_data.update(content_data)
        
        # 确保置信度不超过1.0
        confidence = min(confidence, 1.0)
        
        return {
            'is_llm_traffic': confidence >= self.confidence_threshold,
            'confidence': confidence,
            'indicators': indicators,
            'provider': provider,
            'extracted_data': extracted_data
        }
    
    def _check_domain_indicators(self, http_content: str, metadata: Dict[str, Any]) -> float:
        """检查域名指标"""
        # 从Host头提取域名
        host_match = re.search(r'Host:\s*([^\r\n]+)', http_content, re.IGNORECASE)
        if host_match:
            host = host_match.group(1).strip().lower()
            for domain in self.llm_indicators['domains']:
                if domain in host:
                    return 1.0
        
        # 从URL提取域名
        url_matches = re.findall(r'https?://([^/\s]+)', http_content)
        for url_domain in url_matches:
            url_domain = url_domain.lower()
            for domain in self.llm_indicators['domains']:
                if domain in url_domain:
                    return 1.0
        
        return 0.0
    
    def _check_endpoint_indicators(self, http_content: str) -> float:
        """检查API端点指标"""
        for endpoint in self.llm_indicators['api_endpoints']:
            if endpoint in http_content:
                return 1.0
        return 0.0
    
    def _check_header_indicators(self, http_content: str) -> float:
        """检查请求头指标"""
        content_lower = http_content.lower()
        for header_pattern in self.llm_indicators['headers']:
            if header_pattern in content_lower:
                return 1.0
        return 0.0
    
    def _check_content_patterns(self, http_content: str) -> tuple:
        """检查内容模式"""
        confidence = 0.0
        extracted_data = {}
        matches = 0
        
        for pattern in self.llm_indicators['content_patterns']:
            if re.search(pattern, http_content, re.IGNORECASE):
                matches += 1
        
        if matches > 0:
            confidence = min(matches / len(self.llm_indicators['content_patterns']), 1.0)
            
            # 尝试提取JSON数据
            try:
                # 查找JSON内容
                json_match = re.search(r'\{.*\}', http_content, re.DOTALL)
                if json_match:
                    json_data = json.loads(json_match.group())
                    extracted_data = self._extract_llm_data_from_json(json_data)
            except Exception:
                pass
        
        return confidence, extracted_data
    
    def _extract_llm_data_from_json(self, json_data: dict) -> dict:
        """从JSON数据中提取LLM相关信息"""
        extracted = {}
        
        # 提取模型信息
        if 'model' in json_data:
            extracted['model'] = json_data['model']
        
        # 提取消息/提示词
        if 'messages' in json_data:
            extracted['messages'] = json_data['messages']
        elif 'prompt' in json_data:
            extracted['prompt'] = json_data['prompt']
        
        # 提取参数
        for param in ['max_tokens', 'temperature', 'top_p', 'frequency_penalty', 'presence_penalty']:
            if param in json_data:
                extracted[param] = json_data[param]
        
        return extracted
    
    def _identify_provider_by_domain(self, http_content: str) -> str:
        """根据域名识别LLM提供商"""
        content_lower = http_content.lower()
        
        if 'openai.com' in content_lower:
            return 'OpenAI'
        elif 'anthropic.com' in content_lower or 'claude.ai' in content_lower:
            return 'Anthropic'
        elif 'cohere.ai' in content_lower or 'cohere.com' in content_lower:
            return 'Cohere'
        elif 'huggingface.co' in content_lower:
            return 'HuggingFace'
        elif 'replicate.com' in content_lower:
            return 'Replicate'
        elif 'together.ai' in content_lower:
            return 'Together AI'
        elif 'fireworks.ai' in content_lower:
            return 'Fireworks AI'
        elif 'groq.com' in content_lower:
            return 'Groq'
        elif 'mistral.ai' in content_lower:
            return 'Mistral AI'
        elif 'perplexity.ai' in content_lower:
            return 'Perplexity'
        
        return 'unknown'
    
    def _log_extracted_data(self, extracted_data: dict, metadata: Optional[Dict[str, Any]] = None):
        """记录提取的数据"""
        if extracted_data:
            import time
            # 限制存储的提示词数量
            if len(self.llm_stats['extracted_prompts']) < 100:
                self.llm_stats['extracted_prompts'].append({
                    'timestamp': metadata.get('timestamp') if metadata else time.time(),
                    'data': extracted_data
                })
            
            self.logger.info(f"提取的LLM数据: {json.dumps(extracted_data, ensure_ascii=False)[:200]}...")
    
    def get_processor_info(self) -> Dict[str, Any]:
        """获取处理器信息"""
        return {
            'name': self.name,
            'version': '1.0.0',
            'description': 'LLM流量检测和分析处理器',
            'config': {
                'block_llm_traffic': self.block_llm_traffic,
                'log_llm_requests': self.log_llm_requests,
                'extract_prompts': self.extract_prompts,
                'confidence_threshold': self.confidence_threshold
            },
            'supported_providers': list(set([
                self._identify_provider_by_domain(domain) 
                for domain in self.llm_indicators['domains']
            ])),
            'detection_features': [
                'Domain matching',
                'API endpoint detection',
                'Header analysis',
                'Content pattern matching',
                'Prompt extraction'
            ],
            'llm_stats': self.llm_stats
        }
    
    def validate_config(self) -> bool:
        """验证配置"""
        try:
            # 检查置信度阈值
            if not (0.0 <= self.confidence_threshold <= 1.0):
                self.logger.error("confidence_threshold必须在0.0-1.0之间")
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"配置验证失败: {e}")
            return False
    
    def get_llm_statistics(self) -> Dict[str, Any]:
        """获取LLM检测统计信息"""
        return {
            'detection_stats': self.llm_stats,
            'top_providers': sorted(
                self.llm_stats['llm_providers'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            'recent_prompts': self.llm_stats['extracted_prompts'][-10:]  # 最近10个提示词
        }
