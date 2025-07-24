# CFW 威胁管理功能使用指南

## 📋 功能概述

CFW防火墙系统现在支持灵活的敏感数据处理策略，当检测到敏感信息时，可以选择不同的处理方式：

1. **隐写替换** - 使用隐写技术替换敏感信息
2. **拦截阻断** - 完全阻止包含敏感信息的传输
3. **静默记录** - 允许传输但记录到威胁日志

## 🚀 快速开始

### 1. 配置敏感数据处理策略

编辑 `config/firewall_config_extended.json` 文件：

```json
{
  "threat_detection": {
    "processing_strategy": "steganography",  // 可选: steganography, block, silent
    "show_popup_alerts": true,               // 是否显示弹窗告警
    "threat_log_dir": "logs/threats",        // 威胁日志目录
    "sensitive_patterns": [
      {
        "pattern": "\\b\\d{4}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}\\b",
        "type": "credit_card"
      },
      {
        "pattern": "\\b\\d{3}[\\s\\-]?\\d{2}[\\s\\-]?\\d{4}\\b", 
        "type": "ssn"
      }
    ],
    "steganography_text": "这是正常的业务数据传输内容。",
    "replacement_patterns": {
      "credit_card": "XXXX-XXXX-XXXX-XXXX",
      "ssn": "XXX-XX-XXXX"
    }
  }
}
```

### 2. 启动防火墙系统

```bash
# 启动完整防火墙系统
python main.py start --config config/firewall_config_extended.json

# 或只启动威胁检测
python main.py start --config config/firewall_config_extended.json --mode threat-detection
```

### 3. 查看威胁日志

```bash
# 查看最近24小时的威胁记录
python main.py threat-log --config config/firewall_config_extended.json --hours 24

# 查看威胁统计信息
python main.py threat-stats --config config/firewall_config_extended.json

# 导出威胁报告
python main.py export-report --config config/firewall_config_extended.json --output threat_report.json --hours 48
```

## 📊 处理策略详解

### 隐写替换 (Steganography)
- **功能**: 将敏感信息替换为预设的隐写文本
- **适用场景**: 需要保持通信流畅但隐藏敏感信息
- **示例**: 
  - 原文: "信用卡号：4532-1234-5678-9012"
  - 处理后: "这是正常的业务数据传输内容。"

### 拦截阻断 (Block)
- **功能**: 完全阻止包含敏感信息的数据传输
- **适用场景**: 高安全环境，零容忍敏感信息泄露
- **示例**: 返回 "[BLOCKED: SENSITIVE_DATA_DETECTED]"

### 静默记录 (Silent)
- **功能**: 允许数据正常传输，但记录到威胁日志
- **适用场景**: 监控模式，需要了解敏感信息流向
- **示例**: 数据不变，但在威胁日志中记录详细信息

## 🔔 告警系统

### 弹窗告警
当 `show_popup_alerts` 设置为 `true` 时，系统会显示GUI弹窗：

- **高风险**: 红色边框，警告图标
- **中风险**: 橙色边框，注意图标  
- **低风险**: 黄色边框，信息图标

### 威胁日志
所有威胁检测都会记录到独立的威胁日志文件：

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "threat_type": "credit_card",
  "risk_level": "high",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "dest_ip": "10.0.0.1",
  "dest_port": 443,
  "action_taken": "steganography_replaced",
  "details": "检测到信用卡号码模式",
  "data_hash": "abc123...",
  "match_position": 15,
  "match_context": "信用卡号：[MATCH]，请核实"
}
```

## 🛠️ 高级配置

### 自定义敏感模式
添加新的检测模式：

```json
{
  "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
  "type": "email",
  "risk_level": "medium",
  "description": "电子邮箱地址"
}
```

### 日志轮换设置
```json
{
  "log_rotation_days": 30,        // 日志保留天数
  "max_log_size_mb": 100,         // 单个日志文件最大大小
  "compress_old_logs": true       // 是否压缩旧日志
}
```

## 📈 监控和分析

### 威胁趋势分析
```bash
# 查看威胁类型分布
python main.py threat-stats --config config/firewall_config_extended.json

# 输出示例:
# 威胁类型分布:
#   credit_card: 15 次
#   ssn: 8 次
#   email: 23 次
```

### 导出详细报告
```bash
# 导出JSON格式报告
python main.py export-report --config config/firewall_config_extended.json --output weekly_report.json --hours 168

# 生成CSV格式（可用于Excel分析）
python main.py export-report --config config/firewall_config_extended.json --output report.csv --format csv --hours 72
```

## 🔧 故障排除

### 常见问题

1. **弹窗不显示**
   - 检查 `show_popup_alerts` 设置
   - 确认GUI环境可用（非服务器环境）

2. **威胁日志为空**
   - 检查日志目录权限
   - 验证敏感模式配置

3. **性能影响**
   - 调整检测模式数量
   - 优化正则表达式复杂度

### 调试模式
```bash
# 启用详细日志
python main.py start --config config/firewall_config_extended.json --log-level DEBUG

# 测试威胁检测
python tests/test_threat_management.py
```

## 📚 扩展开发

### 添加新的处理策略
1. 在 `ThreatLogManager` 类中添加新策略
2. 更新配置文件schema
3. 实现具体的处理逻辑

### 集成外部系统
- SIEM系统集成
- 企业安全平台对接
- 自定义告警渠道

---

**注意**: 敏感数据处理涉及隐私和合规问题，请确保符合相关法律法规要求。
