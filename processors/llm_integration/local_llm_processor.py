"""
本地LLM处理器

用于接入本地部署的大语言模型进行流量内容分析
支持：Ollama, text-generation-webui, vLLM等本地服务
"""

import logging
import json
import time
import hashlib
import requests
from typing import Dict, Any, List, Optional

from .prompt_templates import PromptTemplates


class LocalLLMProcessor:
    """本地LLM处理器"""
    
    def __init__(self, config: Dict[str, Any]):
        """初始化本地LLM处理器"""
        self.config = config
        self.logger = logging.getLogger('LocalLLMProcessor')
        
        # 本地LLM配置
        self.api_endpoint = config.get('api_endpoint', 'http://localhost:11434')
        self.model_name = config.get('model_name', 'llama2')
        self.api_type = config.get('api_type', 'ollama')  # ollama, text-generation-webui, vllm
        self.timeout = config.get('timeout', 30)
        self.max_tokens = config.get('max_tokens', 1000)
        self.temperature = config.get('temperature', 0.3)
        
        # 缓存配置
        self.enable_cache = config.get('enable_cache', True)
        self.cache = {}
        self.max_cache_size = config.get('max_cache_size', 500)
        
        # 提示词模板
        self.templates = PromptTemplates()
        
        # 检查连接
        self.available = self._check_connection()
        
        if self.available:
            self.logger.info(f"本地LLM处理器初始化成功，类型: {self.api_type}, 模型: {self.model_name}")
        else:
            self.logger.warning(f"本地LLM服务连接失败: {self.api_endpoint}")
    
    def _check_connection(self) -> bool:
        """检查与本地LLM服务的连接"""
        try:
            if self.api_type == 'ollama':
                response = requests.get(f"{self.api_endpoint}/api/tags", timeout=5)
                return response.status_code == 200
            elif self.api_type == 'text-generation-webui':
                response = requests.get(f"{self.api_endpoint}/api/v1/models", timeout=5)
                return response.status_code == 200
            elif self.api_type == 'vllm':
                response = requests.get(f"{self.api_endpoint}/v1/models", timeout=5)
                return response.status_code == 200
            else:
                # 通用HTTP检查
                response = requests.get(self.api_endpoint, timeout=5)
                return response.status_code in [200, 404]  # 404也算连接成功
        except Exception as e:
            self.logger.debug(f"连接检查失败: {e}")
            return False
    
    def analyze_content(self, content: str, analysis_types: List[str], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """分析内容"""
        if not self.available:
            return {'error': '本地LLM服务不可用'}
        
        try:
            # 检查缓存
            cache_key = self._generate_cache_key(content, analysis_types)
            if self.enable_cache and cache_key in self.cache:
                return self.cache[cache_key]
            
            # 构建分析结果
            analysis_result = {
                'threat_level': 'low',
                'threats': [],
                'sensitive_data': False,
                'content_classification': 'unknown',
                'confidence_score': 0.0,
                'analysis_details': {}
            }
            
            # 执行分析
            for analysis_type in analysis_types:
                try:
                    type_result = self._analyze_by_type(content, analysis_type, metadata)
                    analysis_result['analysis_details'][analysis_type] = type_result
                    self._merge_analysis_results(analysis_result, type_result)
                except Exception as e:
                    self.logger.error(f"本地LLM分析类型 {analysis_type} 失败: {e}")
                    analysis_result['analysis_details'][analysis_type] = {'error': str(e)}
            
            # 缓存结果
            if self.enable_cache:
                self._cache_result(cache_key, analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"本地LLM内容分析失败: {e}")
            return {'error': str(e)}
    
    def _analyze_by_type(self, content: str, analysis_type: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """根据分析类型执行具体分析"""
        prompt_template = self.templates.get_template(analysis_type)
        if not prompt_template:
            raise ValueError(f"未找到分析类型 {analysis_type} 的提示词模板")
        
        # 构建完整提示词
        full_prompt = prompt_template.format(
            content=content[:2500],  # 本地模型通常上下文较小
            source_ip=metadata.get('src_ip', 'unknown'),
            dest_ip=metadata.get('dst_ip', 'unknown'),
            protocol=metadata.get('protocol', 'unknown')
        )
        
        # 根据API类型调用对应接口
        if self.api_type == 'ollama':
            response_text = self._call_ollama_api(full_prompt)
        elif self.api_type == 'text-generation-webui':
            response_text = self._call_textgen_api(full_prompt)
        elif self.api_type == 'vllm':
            response_text = self._call_vllm_api(full_prompt)
        else:
            raise ValueError(f"不支持的API类型: {self.api_type}")
        
        try:
            # 尝试解析JSON响应
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # 如果不是JSON，进行文本解析
            result = self._parse_text_response(response_text, analysis_type)
        
        return result
    
    def _call_ollama_api(self, prompt: str) -> str:
        """调用Ollama API"""
        data = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens
            }
        }
        
        response = requests.post(
            f"{self.api_endpoint}/api/generate",
            json=data,
            timeout=self.timeout
        )
        response.raise_for_status()
        
        result = response.json()
        return result.get('response', '')
    
    def _call_textgen_api(self, prompt: str) -> str:
        """调用text-generation-webui API"""
        data = {
            "prompt": prompt,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stop": []
        }
        
        response = requests.post(
            f"{self.api_endpoint}/api/v1/completions",
            json=data,
            timeout=self.timeout
        )
        response.raise_for_status()
        
        result = response.json()
        choices = result.get('choices', [])
        if choices:
            return choices[0].get('text', '')
        return ''
    
    def _call_vllm_api(self, prompt: str) -> str:
        """调用vLLM API"""
        data = {
            "model": self.model_name,
            "prompt": prompt,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature
        }
        
        response = requests.post(
            f"{self.api_endpoint}/v1/completions",
            json=data,
            timeout=self.timeout
        )
        response.raise_for_status()
        
        result = response.json()
        choices = result.get('choices', [])
        if choices:
            return choices[0].get('text', '')
        return ''
    
    def _parse_text_response(self, response_text: str, analysis_type: str) -> Dict[str, Any]:
        """解析文本响应为标准格式"""
        result = {
            'threat_level': 'low',
            'threats': [],
            'confidence': 0.5,
            'raw_response': response_text
        }
        
        response_lower = response_text.lower()
        
        # 威胁等级检测（本地模型可能输出不太标准）
        if any(word in response_lower for word in ['high', 'critical', 'severe', '高', '严重']):
            result['threat_level'] = 'high'
            result['confidence'] = 0.8
        elif any(word in response_lower for word in ['medium', 'moderate', '中', '中等']):
            result['threat_level'] = 'medium'
            result['confidence'] = 0.6
        
        # 威胁类型提取
        threat_keywords = {
            'malware': ['malware', 'virus', 'trojan', '恶意', '病毒', '木马'],
            'injection': ['injection', 'sql', 'xss', '注入'],
            'ddos': ['ddos', 'denial', '拒绝服务'],
            'suspicious': ['suspicious', 'anomaly', '可疑', '异常']
        }
        
        for threat_type, keywords in threat_keywords.items():
            if any(keyword in response_lower for keyword in keywords):
                result['threats'].append(threat_type)
        
        # 敏感数据检测
        sensitive_keywords = ['password', 'credit card', 'ssn', '密码', '信用卡', '身份证']
        if any(keyword in response_lower for keyword in sensitive_keywords):
            result['sensitive_data'] = True
        
        return result
    
    def _merge_analysis_results(self, main_result: Dict[str, Any], type_result: Dict[str, Any]):
        """合并分析结果"""
        # 威胁等级合并
        threat_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        current_level = threat_levels.get(main_result['threat_level'], 0)
        new_level = threat_levels.get(type_result.get('threat_level', 'low'), 0)
        
        if new_level > current_level:
            main_result['threat_level'] = type_result.get('threat_level', 'low')
        
        # 威胁列表合并
        if type_result.get('threats'):
            main_result['threats'].extend(type_result['threats'])
        
        # 敏感数据检测
        if type_result.get('sensitive_data', False):
            main_result['sensitive_data'] = True
        
        # 置信度更新
        if type_result.get('confidence'):
            current_confidence = main_result['confidence_score']
            new_confidence = type_result['confidence']
            main_result['confidence_score'] = max(current_confidence, new_confidence)
    
    def _generate_cache_key(self, content: str, analysis_types: List[str]) -> str:
        """生成缓存键"""
        content_hash = hashlib.md5(content.encode()).hexdigest()
        types_str = ','.join(sorted(analysis_types))
        return f"local:{content_hash}:{types_str}"
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """缓存结果"""
        if len(self.cache) >= self.max_cache_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        self.cache[cache_key] = result
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'available': self.available,
            'api_type': self.api_type,
            'model_name': self.model_name,
            'api_endpoint': self.api_endpoint,
            'cache_size': len(self.cache)
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """测试连接并返回详细信息"""
        try:
            if self.api_type == 'ollama':
                response = requests.get(f"{self.api_endpoint}/api/tags", timeout=5)
                if response.status_code == 200:
                    models = response.json().get('models', [])
                    return {
                        'connected': True,
                        'available_models': [m.get('name', '') for m in models]
                    }
            
            return {'connected': self._check_connection(), 'details': 'Basic connection test'}
            
        except Exception as e:
            return {'connected': False, 'error': str(e)}
