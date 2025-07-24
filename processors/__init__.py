"""
CFW防火墙处理器模块

用于扩展防火墙的流量处理能力：
- 基础处理器接口
- LLM流量检测处理器
- 自定义处理器插件
"""

from .base_processor import BaseProcessor, ProcessorManager
from .llm_traffic_processor import LLMTrafficProcessor

__version__ = "1.0.0"
__all__ = ["BaseProcessor", "ProcessorManager", "LLMTrafficProcessor"]
