"""
基础流量处理器接口

所有自定义流量处理器都应该继承这个基类
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging


class BaseProcessor(ABC):
    """基础流量处理器抽象类"""
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化处理器
        
        Args:
            name: 处理器名称
            config: 处理器配置字典
        """
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(f"processor.{name}")
        self.is_enabled = True
        self.stats = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_blocked': 0,
            'packets_modified': 0
        }
    
    @abstractmethod
    def process_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理数据包
        
        Args:
            packet_data: 原始数据包数据
            metadata: 数据包元数据（IP、端口、协议等）
            
        Returns:
            处理结果字典，包含:
            - action: 'allow', 'block', 'modify'
            - modified_data: 如果action为'modify'，包含修改后的数据
            - reason: 处理原因
            - confidence: 置信度 (0.0-1.0)
            - details: 详细信息
        """
        pass
    
    @abstractmethod
    def get_processor_info(self) -> Dict[str, Any]:
        """
        获取处理器信息
        
        Returns:
            包含处理器信息的字典
        """
        pass
    
    def enable(self):
        """启用处理器"""
        self.is_enabled = True
        self.logger.info(f"处理器 {self.name} 已启用")
    
    def disable(self):
        """禁用处理器"""
        self.is_enabled = False
        self.logger.info(f"处理器 {self.name} 已禁用")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取处理器统计信息"""
        return {
            'name': self.name,
            'enabled': self.is_enabled,
            'stats': self.stats.copy()
        }
    
    def reset_stats(self):
        """重置统计信息"""
        self.stats = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_blocked': 0,
            'packets_modified': 0
        }
        self.logger.info(f"处理器 {self.name} 统计信息已重置")
    
    def update_stats(self, action: str):
        """更新统计信息"""
        self.stats['packets_processed'] += 1
        if action == 'allow':
            self.stats['packets_allowed'] += 1
        elif action == 'block':
            self.stats['packets_blocked'] += 1
        elif action == 'modify':
            self.stats['packets_modified'] += 1
    
    def validate_config(self) -> bool:
        """
        验证处理器配置
        
        Returns:
            配置是否有效
        """
        return True
    
    def initialize(self) -> bool:
        """
        初始化处理器资源
        
        Returns:
            初始化是否成功
        """
        return True
    
    def cleanup(self):
        """清理处理器资源"""
        pass


class ProcessorManager:
    """处理器管理器"""
    
    def __init__(self):
        self.processors = []
        self.logger = logging.getLogger("processor_manager")
    
    def register_processor(self, processor: BaseProcessor) -> bool:
        """
        注册处理器
        
        Args:
            processor: 处理器实例
            
        Returns:
            注册是否成功
        """
        try:
            if not isinstance(processor, BaseProcessor):
                raise ValueError("处理器必须继承BaseProcessor类")
            
            if not processor.validate_config():
                raise ValueError(f"处理器 {processor.name} 配置无效")
            
            if not processor.initialize():
                raise ValueError(f"处理器 {processor.name} 初始化失败")
            
            self.processors.append(processor)
            self.logger.info(f"处理器 {processor.name} 注册成功")
            return True
            
        except Exception as e:
            self.logger.error(f"注册处理器失败: {e}")
            return False
    
    def unregister_processor(self, processor_name: str) -> bool:
        """
        注销处理器
        
        Args:
            processor_name: 处理器名称
            
        Returns:
            注销是否成功
        """
        for i, processor in enumerate(self.processors):
            if processor.name == processor_name:
                processor.cleanup()
                del self.processors[i]
                self.logger.info(f"处理器 {processor_name} 注销成功")
                return True
        
        self.logger.warning(f"未找到处理器: {processor_name}")
        return False
    
    def process_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        使用所有启用的处理器处理数据包
        
        Args:
            packet_data: 数据包数据
            metadata: 数据包元数据
            
        Returns:
            综合处理结果
        """
        results = []
        current_data = packet_data
        
        for processor in self.processors:
            if not processor.is_enabled:
                continue
            
            try:
                result = processor.process_packet(current_data, metadata)
                results.append({
                    'processor': processor.name,
                    'result': result
                })
                
                # 更新统计
                processor.update_stats(result.get('action', 'allow'))
                
                # 如果数据被修改，使用修改后的数据继续处理
                if result.get('action') == 'modify' and 'modified_data' in result:
                    current_data = result['modified_data']
                
                # 如果任何处理器要求阻止，立即停止处理
                if result.get('action') == 'block':
                    break
                    
            except Exception as e:
                self.logger.error(f"处理器 {processor.name} 处理错误: {e}")
                continue
        
        # 综合处理结果
        return self._combine_results(results, current_data)
    
    def _combine_results(self, results: list, final_data: bytes) -> Dict[str, Any]:
        """综合多个处理器的结果"""
        if not results:
            return {'action': 'allow', 'data': final_data}
        
        # 如果有任何处理器要求阻止，则阻止
        for result_info in results:
            if result_info['result'].get('action') == 'block':
                return {
                    'action': 'block',
                    'reason': result_info['result'].get('reason', '被处理器阻止'),
                    'processor': result_info['processor'],
                    'details': results
                }
        
        # 检查是否有修改
        data_modified = final_data != results[0]['result'].get('original_data', final_data)
        
        return {
            'action': 'modify' if data_modified else 'allow',
            'data': final_data,
            'details': results
        }
    
    def get_all_stats(self) -> Dict[str, Any]:
        """获取所有处理器的统计信息"""
        return {
            'total_processors': len(self.processors),
            'enabled_processors': len([p for p in self.processors if p.is_enabled]),
            'processors': [p.get_stats() for p in self.processors]
        }
    
    def reset_all_stats(self):
        """重置所有处理器的统计信息"""
        for processor in self.processors:
            processor.reset_stats()
        self.logger.info("所有处理器统计信息已重置")
