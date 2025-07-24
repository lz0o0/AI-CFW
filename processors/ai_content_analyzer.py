"""
AI内容分析器 - 使用大模型分析解密后的流量内容

支持接入多种大模型进行智能分析：
- 内容安全分析
- 威胁检测
- 数据泄露检测
- 异常行为识别
"""

import json
import logging
import asyncio
from typing import Dict, Any, Optional, List, Union
from enum import Enum
from .base_processor import BaseProcessor


class AnalysisType(Enum):
    """分析类型枚举"""
    SECURITY_SCAN = "security_scan"        # 安全扫描
    THREAT_DETECTION = "threat_detection"  # 威胁检测
    DATA_LEAK_DETECTION = "data_leak"      # 数据泄露检测
    CONTENT_CLASSIFICATION = "classification"  # 内容分类
    BEHAVIOR_ANALYSIS = "behavior"         # 行为分析
    CUSTOM_ANALYSIS = "custom"             # 自定义分析


class AIContentAnalyzer(BaseProcessor):
    """AI内容分析器主类"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("ai_content_analyzer", config)
        
        self.ai_config = self.config.get('ai_analysis', {})
        self.enabled_models = self.ai_config.get('enabled_models', ['openai'])
        self.analysis_types = self.ai_config.get('analysis_types', ['security_scan'])
        self.batch_size = self.ai_config.get('batch_size', 10)
        self.max_content_length = self.ai_config.get('max_content_length', 4000)
        
        # 初始化AI模型处理器
        self.model_processors = {}
        self._init_model_processors()
        
        # 分析队列
        self.analysis_queue = asyncio.Queue()
        self.results_cache = {}
        
        self.logger.info(f"AI内容分析器初始化完成，启用模型: {self.enabled_models}")
    
    def _init_model_processors(self):
        """初始化AI模型处理器"""
        try:
            if 'openai' in self.enabled_models:
                from .llm_integration.openai_processor import OpenAIProcessor
                self.model_processors['openai'] = OpenAIProcessor(self.ai_config.get('openai', {}))
            
            if 'claude' in self.enabled_models:
                from .llm_integration.claude_processor import ClaudeProcessor
                self.model_processors['claude'] = ClaudeProcessor(self.ai_config.get('claude', {}))
            
            if 'local_llm' in self.enabled_models:
                from .llm_integration.local_llm_processor import LocalLLMProcessor
                self.model_processors['local_llm'] = LocalLLMProcessor(self.ai_config.get('local_llm', {}))
                
        except ImportError as e:
            self.logger.warning(f"部分AI模型处理器导入失败: {e}")
    
    def process_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理数据包并进行AI分析
        
        Args:
            packet_data: 解密后的数据包内容
            metadata: 数据包元数据
            
        Returns:
            处理结果字典
        """
        try:
            # 提取文本内容
            text_content = self._extract_text_content(packet_data, metadata)
            if not text_content:
                return {
                    'action': 'allow',
                    'reason': 'No text content to analyze',
                    'confidence': 0.0
                }
            
            # 执行AI分析
            analysis_results = self._analyze_content(text_content, metadata)
            
            # 根据分析结果决定处理动作
            action, reason, confidence = self._determine_action(analysis_results)
            
            self.stats['packets_processed'] += 1
            if action == 'block':
                self.stats['packets_blocked'] += 1
            elif action == 'allow':
                self.stats['packets_allowed'] += 1
            
            return {
                'action': action,
                'reason': reason,
                'confidence': confidence,
                'ai_analysis': analysis_results,
                'details': {
                    'content_length': len(text_content),
                    'models_used': list(self.model_processors.keys()),
                    'analysis_types': self.analysis_types
                }
            }
            
        except Exception as e:
            self.logger.error(f"AI内容分析异常: {e}")
            return {
                'action': 'allow',
                'reason': f'Analysis error: {str(e)}',
                'confidence': 0.0
            }
    
    def _extract_text_content(self, packet_data: bytes, metadata: Dict[str, Any]) -> Optional[str]:
        """从数据包中提取文本内容"""
        try:
            # 尝试UTF-8解码
            text_content = packet_data.decode('utf-8', errors='ignore')
            
            # 限制内容长度
            if len(text_content) > self.max_content_length:
                text_content = text_content[:self.max_content_length]
            
            # 过滤空内容或无意义内容
            if len(text_content.strip()) < 10:
                return None
            
            return text_content
            
        except Exception as e:
            self.logger.debug(f"文本提取失败: {e}")
            return None
    
    def _analyze_content(self, content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """对内容进行AI分析"""
        analysis_results = {
            'overall_threat_level': 'low',
            'detected_threats': [],
            'content_classification': 'unknown',
            'sensitive_data_detected': False,
            'model_results': {}
        }
        
        # 对每个启用的模型进行分析
        for model_name, processor in self.model_processors.items():
            try:
                model_result = processor.analyze_content(content, self.analysis_types, metadata)
                analysis_results['model_results'][model_name] = model_result
                
                # 合并威胁检测结果
                if model_result.get('threats'):
                    analysis_results['detected_threats'].extend(model_result['threats'])
                
                # 更新整体威胁等级
                model_threat_level = model_result.get('threat_level', 'low')
                if self._compare_threat_level(model_threat_level, analysis_results['overall_threat_level']):
                    analysis_results['overall_threat_level'] = model_threat_level
                
                # 检测敏感数据
                if model_result.get('sensitive_data', False):
                    analysis_results['sensitive_data_detected'] = True
                
            except Exception as e:
                self.logger.error(f"模型 {model_name} 分析失败: {e}")
                analysis_results['model_results'][model_name] = {'error': str(e)}
        
        return analysis_results
    
    def _determine_action(self, analysis_results: Dict[str, Any]) -> tuple:
        """根据分析结果确定处理动作"""
        threat_level = analysis_results.get('overall_threat_level', 'low')
        detected_threats = analysis_results.get('detected_threats', [])
        sensitive_data = analysis_results.get('sensitive_data_detected', False)
        
        # 高威胁等级直接阻断
        if threat_level in ['high', 'critical']:
            return 'block', f'High threat level detected: {threat_level}', 0.9
        
        # 检测到多个威胁
        if len(detected_threats) >= 3:
            return 'block', f'Multiple threats detected: {len(detected_threats)}', 0.8
        
        # 敏感数据泄露
        if sensitive_data and threat_level != 'low':
            return 'block', 'Sensitive data leak detected', 0.85
        
        # 中等威胁记录日志但允许通过
        if threat_level == 'medium':
            return 'allow', f'Medium threat logged: {detected_threats}', 0.6
        
        return 'allow', 'Content analysis passed', 0.3
    
    def _compare_threat_level(self, level1: str, level2: str) -> bool:
        """比较威胁等级，返回level1是否比level2更严重"""
        threat_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        return threat_order.get(level1, 0) > threat_order.get(level2, 0)
    
    async def batch_analyze(self, content_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量分析内容"""
        results = []
        for item in content_batch:
            result = self._analyze_content(item['content'], item['metadata'])
            results.append(result)
        return results
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """获取分析统计信息"""
        return {
            **self.stats,
            'enabled_models': list(self.model_processors.keys()),
            'analysis_types': self.analysis_types,
            'cache_size': len(self.results_cache)
        }
