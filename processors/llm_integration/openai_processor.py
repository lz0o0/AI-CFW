"""
OpenAI API集成处理器

用于接入OpenAI的GPT模型进行流量内容分析
支持：GPT-4, GPT-3.5-turbo, text-embedding等模型
"""

import logging
import json
import asyncio
from typing import Dict, Any, List, Optional
import hashlib
import time

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .prompt_templates import PromptTemplates


class OpenAIProcessor:
    """OpenAI API处理器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化OpenAI处理器
        
        Args:
            config: OpenAI配置字典
        """
        self.config = config
        self.logger = logging.getLogger('OpenAIProcessor')
        
        if not OPENAI_AVAILABLE:
            self.logger.error("OpenAI库未安装，请运行: pip install openai")
            self.available = False
            return
        
        # OpenAI配置
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'gpt-3.5-turbo')
        self.max_tokens = config.get('max_tokens', 1000)
        self.temperature = config.get('temperature', 0.3)
        self.timeout = config.get('timeout', 30)
        
        # 速率限制
        self.rate_limit = config.get('rate_limit', 60)  # 每分钟请求数
        self.request_times = []
        
        # 缓存配置
        self.enable_cache = config.get('enable_cache', True)
        self.cache = {}
        self.max_cache_size = config.get('max_cache_size', 1000)
        
        # 提示词模板
        self.templates = PromptTemplates()
        
        if self.api_key:
            openai.api_key = self.api_key
            self.available = True
            self.logger.info(f"OpenAI处理器初始化成功，模型: {self.model}")
        else:
            self.logger.error("OpenAI API密钥未配置")
            self.available = False
    
    def analyze_content(self, content: str, analysis_types: List[str], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析内容
        
        Args:
            content: 要分析的文本内容
            analysis_types: 分析类型列表
            metadata: 元数据
            
        Returns:
            分析结果字典
        """
        if not self.available:
            return {'error': 'OpenAI处理器不可用'}
        
        try:
            # 检查速率限制
            if not self._check_rate_limit():
                return {'error': 'Rate limit exceeded'}
            
            # 检查缓存
            cache_key = self._generate_cache_key(content, analysis_types)
            if self.enable_cache and cache_key in self.cache:
                self.logger.debug("返回缓存结果")
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
            
            # 执行不同类型的分析
            for analysis_type in analysis_types:
                try:
                    type_result = self._analyze_by_type(content, analysis_type, metadata)
                    analysis_result['analysis_details'][analysis_type] = type_result
                    
                    # 合并结果
                    self._merge_analysis_results(analysis_result, type_result)
                    
                except Exception as e:
                    self.logger.error(f"分析类型 {analysis_type} 失败: {e}")
                    analysis_result['analysis_details'][analysis_type] = {'error': str(e)}
            
            # 缓存结果
            if self.enable_cache:
                self._cache_result(cache_key, analysis_result)
            
            self._record_request_time()
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"OpenAI内容分析失败: {e}")
            return {'error': str(e)}
    
    def _analyze_by_type(self, content: str, analysis_type: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """根据分析类型执行具体分析"""
        
        # 获取对应的提示词模板
        prompt_template = self.templates.get_template(analysis_type)
        if not prompt_template:
            raise ValueError(f"未找到分析类型 {analysis_type} 的提示词模板")
        
        # 构建完整提示词
        full_prompt = prompt_template.format(
            content=content[:2000],  # 限制内容长度
            source_ip=metadata.get('src_ip', 'unknown'),
            dest_ip=metadata.get('dst_ip', 'unknown'),
            protocol=metadata.get('protocol', 'unknown')
        )
        
        # 调用OpenAI API
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "你是一个网络安全专家，专门分析网络流量内容。请以JSON格式返回分析结果。"},
                {"role": "user", "content": full_prompt}
            ],
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            timeout=self.timeout
        )
        
        # 解析响应
        response_text = response.choices[0].message.content.strip()
        
        try:
            # 尝试解析JSON响应
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # 如果不是JSON，进行简单解析
            result = self._parse_text_response(response_text, analysis_type)
        
        return result
    
    def _parse_text_response(self, response_text: str, analysis_type: str) -> Dict[str, Any]:
        """解析文本响应为标准格式"""
        result = {
            'threat_level': 'low',
            'threats': [],
            'confidence': 0.5,
            'raw_response': response_text
        }
        
        # 简单的文本解析逻辑
        response_lower = response_text.lower()
        
        if any(word in response_lower for word in ['高威胁', 'high threat', 'critical', '严重']):
            result['threat_level'] = 'high'
            result['confidence'] = 0.8
        elif any(word in response_lower for word in ['中威胁', 'medium threat', '中等']):
            result['threat_level'] = 'medium'
            result['confidence'] = 0.6
        
        # 提取威胁类型
        threat_keywords = ['恶意软件', 'malware', '病毒', 'virus', 'ddos', '注入', 'injection']
        for keyword in threat_keywords:
            if keyword in response_lower:
                result['threats'].append(keyword)
        
        return result
    
    def _merge_analysis_results(self, main_result: Dict[str, Any], type_result: Dict[str, Any]):
        """合并分析结果"""
        # 更新威胁等级（取最高）
        threat_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        current_level = threat_levels.get(main_result['threat_level'], 0)
        new_level = threat_levels.get(type_result.get('threat_level', 'low'), 0)
        
        if new_level > current_level:
            main_result['threat_level'] = type_result.get('threat_level', 'low')
        
        # 合并威胁列表
        if type_result.get('threats'):
            main_result['threats'].extend(type_result['threats'])
        
        # 检测敏感数据
        if type_result.get('sensitive_data', False):
            main_result['sensitive_data'] = True
        
        # 更新置信度（取平均值）
        if type_result.get('confidence'):
            current_confidence = main_result['confidence_score']
            new_confidence = type_result['confidence']
            main_result['confidence_score'] = (current_confidence + new_confidence) / 2
    
    def _check_rate_limit(self) -> bool:
        """检查速率限制"""
        current_time = time.time()
        
        # 清理过期的请求时间
        self.request_times = [t for t in self.request_times if current_time - t < 60]
        
        # 检查是否超过速率限制
        return len(self.request_times) < self.rate_limit
    
    def _record_request_time(self):
        """记录请求时间"""
        self.request_times.append(time.time())
    
    def _generate_cache_key(self, content: str, analysis_types: List[str]) -> str:
        """生成缓存键"""
        content_hash = hashlib.md5(content.encode()).hexdigest()
        types_str = ','.join(sorted(analysis_types))
        return f"{content_hash}:{types_str}"
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """缓存结果"""
        if len(self.cache) >= self.max_cache_size:
            # 删除最旧的缓存项
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        
        self.cache[cache_key] = result
    
    async def analyze_content_async(self, content: str, analysis_types: List[str], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """异步分析内容"""
        return await asyncio.get_event_loop().run_in_executor(
            None, self.analyze_content, content, analysis_types, metadata
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'available': self.available,
            'model': self.model,
            'cache_size': len(self.cache),
            'requests_in_last_minute': len(self.request_times),
            'rate_limit': self.rate_limit
        }
