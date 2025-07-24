"""
LLM集成模块初始化文件
"""

from .openai_processor import OpenAIProcessor
from .claude_processor import ClaudeProcessor  
from .local_llm_processor import LocalLLMProcessor
from .prompt_templates import PromptTemplates

__all__ = [
    'OpenAIProcessor',
    'ClaudeProcessor', 
    'LocalLLMProcessor',
    'PromptTemplates'
]
