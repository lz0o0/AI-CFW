# CFW防火墙系统 - AI与加密分析扩展使用指南

## 📋 概述

CFW防火墙系统现已支持强大的AI智能分析和加密流量处理功能，可以深度分析解密后的SSL/TLS流量内容，并使用大语言模型进行智能威胁检测。

## 🚀 新增功能

### 1. AI智能内容分析
- **支持的AI模型**: OpenAI GPT、Anthropic Claude、本地LLM (Ollama等)
- **分析类型**: 安全扫描、威胁检测、数据泄露检测、行为分析、内容分类
- **实时处理**: 毫秒级响应，支持批量分析
- **智能缓存**: 避免重复分析，提高性能

### 2. SSL/TLS解密内容处理
- **HTTP协议解析**: 自动解析请求/响应头和内容
- **API调用监控**: 识别各种API调用模式
- **敏感数据检测**: 信用卡、身份证、API密钥等
- **威胁指标计算**: 综合评估安全风险

### 3. 加密算法分析
- **TLS版本检测**: SSL 3.0 到 TLS 1.3 全支持
- **密码套件分析**: 识别弱加密算法
- **安全评级**: 自动评估加密强度
- **漏洞检测**: 发现过时或不安全的配置

### 4. 数字证书分析
- **证书链验证**: 完整性和有效性检查
- **到期时间监控**: 提前发现即将过期的证书
- **弱签名检测**: 识别MD5、SHA1等弱签名
- **自签名证书识别**: 检测潜在安全风险

## 💻 使用方法

### 快速开始

1. **安装依赖**
```bash
python main.py install-deps
```

2. **配置AI模型** (编辑 `config/firewall_config_extended.json`)
```json
{
  "ai_analysis": {
    "enabled_models": ["openai", "local_llm"],
    "openai": {
      "api_key": "your-openai-api-key",
      "model": "gpt-3.5-turbo"
    },
    "local_llm": {
      "api_endpoint": "http://localhost:11434",
      "model_name": "llama2",
      "api_type": "ollama"
    }
  }
}
```

3. **测试AI连接**
```bash
python main.py test-ai --config config/firewall_config_extended.json
```

4. **检查配置**
```bash
python main.py config-check --config config/firewall_config_extended.json
```

### 启动不同模式

#### 1. AI智能分析模式
```bash
python main.py ai-analysis --config config/firewall_config_extended.json
```
- 启用所有AI分析功能
- 支持多模型并行分析
- 实时威胁检测和内容分类

#### 2. 加密分析模式
```bash
python main.py crypto-analysis --config config/firewall_config_extended.json
```
- SSL/TLS协议分析
- 证书安全评估
- 加密算法强度检测

#### 3. 综合分析模式
```bash
python main.py start --mode direct --config config/firewall_config_extended.json
```
- 同时启用所有分析功能
- 流量拦截 + AI分析 + 加密分析

## 🔧 配置详解

### AI分析配置

```json
{
  "ai_analysis": {
    "enabled_models": ["openai", "claude", "local_llm"],
    "analysis_types": ["security_scan", "threat_detection", "data_leak", "behavior"],
    "batch_size": 10,
    "max_content_length": 4000,
    
    "openai": {
      "api_key": "sk-xxx",
      "model": "gpt-3.5-turbo",
      "max_tokens": 1000,
      "temperature": 0.3,
      "rate_limit": 60,
      "enable_cache": true
    },
    
    "claude": {
      "api_key": "claude-xxx",
      "model": "claude-3-sonnet-20240229",
      "max_tokens": 1000,
      "rate_limit": 50
    },
    
    "local_llm": {
      "api_endpoint": "http://localhost:11434",
      "model_name": "llama2",
      "api_type": "ollama",
      "timeout": 30
    }
  }
}
```

### SSL处理配置

```json
{
  "ssl_processing": {
    "enable_ai_analysis": true,
    "enable_api_monitoring": true,
    "enable_data_leak_detection": true
  },
  
  "ssl": {
    "enable_interception": true,
    "ca_cert_path": "./ssl_certs/ca.crt",
    "ca_key_path": "./ssl_certs/ca.key",
    "enable_content_analysis": true
  }
}
```

### 处理器配置

```json
{
  "processors": {
    "enabled": [
      "ssl_content_processor",
      "ai_content_analyzer", 
      "encryption_analyzer",
      "certificate_analyzer"
    ]
  }
}
```

## 📊 监控和日志

### 查看系统状态
```bash
python main.py status --config config/firewall_config_extended.json
```

输出示例：
```
=== 防火墙状态 ===
运行状态: 运行中
高级功能可用: 是
流量处理模式: direct
SSL拦截: 启用
DPI引擎: 启用
AI分析: 启用

=== 组件状态 ===
ai_content_analyzer: 运行中
ssl_content_processor: 运行中
encryption_analyzer: 运行中
certificate_analyzer: 运行中

=== AI模型状态 ===
OpenAI: 可用 (gpt-3.5-turbo)
Claude: 可用 (claude-3-sonnet)
本地LLM: 可用 (llama2@localhost:11434)
```

### 日志分析

日志文件位置: `logs/firewall.log`

关键日志标识:
- `[AI_ANALYSIS]` - AI分析结果
- `[SSL_DECRYPT]` - SSL解密事件
- `[THREAT_DETECTED]` - 威胁检测
- `[CERT_ANALYSIS]` - 证书分析
- `[API_CALL]` - API调用监控

## 🛡️ 安全策略配置

### 威胁阻断规则

```json
{
  "security": {
    "block_weak_encryption": true,
    "block_expired_certificates": false,
    "block_self_signed": false,
    "block_high_threat": true,
    "alert_on_sensitive_data": true
  }
}
```

### 威胁等级说明

- **LOW**: 正常流量，允许通过
- **MEDIUM**: 可疑流量，记录日志但允许通过
- **HIGH**: 高威胁流量，阻断并告警
- **CRITICAL**: 严重威胁，立即阻断并记录详细信息

## 🔗 AI模型集成

### 支持的本地LLM服务

1. **Ollama**
```bash
# 安装Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# 下载模型
ollama pull llama2
ollama pull mistral

# 配置
"local_llm": {
  "api_endpoint": "http://localhost:11434",
  "model_name": "llama2",
  "api_type": "ollama"
}
```

2. **text-generation-webui**
```bash
# 配置
"local_llm": {
  "api_endpoint": "http://localhost:5000",
  "model_name": "your-model",
  "api_type": "text-generation-webui"
}
```

3. **vLLM**
```bash
# 配置
"local_llm": {
  "api_endpoint": "http://localhost:8000",
  "model_name": "model-name",
  "api_type": "vllm"
}
```

## 📈 性能优化

### 配置建议

```json
{
  "performance": {
    "max_worker_threads": 10,
    "queue_size": 1000,
    "batch_processing": true,
    "enable_caching": true,
    "cache_ttl": 3600
  }
}
```

### 缓存策略

- AI分析结果缓存1小时
- 证书分析结果缓存24小时
- 加密算法分析结果缓存6小时

## 🚨 告警配置

```json
{
  "monitoring": {
    "enable_alerts": true,
    "alert_thresholds": {
      "threat_detection_rate": 0.1,
      "blocked_connections": 100,
      "processing_latency": 1000
    }
  }
}
```

## 🔍 故障排除

### 常见问题

1. **AI模型连接失败**
   - 检查API密钥配置
   - 验证网络连接
   - 确认服务端点可达

2. **SSL拦截不工作**
   - 检查CA证书是否存在
   - 验证证书是否已部署到客户端
   - 确认SSL拦截已启用

3. **性能问题**
   - 调整批处理大小
   - 启用缓存机制
   - 减少并发处理线程

### 调试命令

```bash
# 详细日志
python main.py start --log-level DEBUG

# 测试特定功能
python main.py test-ai
python main.py config-check

# 查看组件状态
python main.py status
```

## 📚 扩展开发

### 自定义处理器

在 `processors/` 目录下创建新的处理器:

```python
from processors.base_processor import BaseProcessor

class CustomProcessor(BaseProcessor):
    def process_packet(self, packet_data, metadata):
        # 自定义处理逻辑
        return {'action': 'allow', 'reason': 'Custom analysis'}
```

### 自定义AI提示词

编辑 `processors/llm_integration/prompt_templates.py`:

```python
def add_custom_template(self):
    self.templates['custom_analysis'] = """
    自定义分析提示词模板...
    """
```

这个扩展指南为您的CFW防火墙系统提供了强大的AI分析和加密处理能力，可以显著提升网络安全防护水平。
