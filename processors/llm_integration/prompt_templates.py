"""
提示词模板管理器

为不同的分析类型提供专业的提示词模板
"""

from typing import Dict, Optional


class PromptTemplates:
    """提示词模板管理类"""
    
    def __init__(self):
        """初始化提示词模板"""
        self.templates = {
            'security_scan': """
请分析以下网络流量内容的安全性：

流量内容:
{content}

来源IP: {source_ip}
目标IP: {dest_ip}
协议: {protocol}

请从以下角度进行安全分析：
1. 是否包含恶意代码或攻击载荷
2. 是否存在SQL注入、XSS等攻击特征
3. 是否包含病毒、木马等恶意软件特征
4. 是否存在DDoS攻击模式
5. 总体威胁等级评估

请以JSON格式返回结果：
{{
    "threat_level": "low/medium/high/critical",
    "threats": ["威胁类型列表"],
    "confidence": 0.0-1.0,
    "details": "详细分析说明"
}}
            """,
            
            'threat_detection': """
请检测以下网络流量中的威胁特征：

流量内容:
{content}

网络信息:
- 来源: {source_ip}
- 目标: {dest_ip}
- 协议: {protocol}

重点检测：
1. 恶意域名和IP
2. 可疑的网络行为模式
3. 异常的数据传输
4. 潜在的APT攻击特征
5. 恶意文件下载或上传

返回JSON格式：
{{
    "threat_detected": true/false,
    "threat_type": "威胁类型",
    "severity": "low/medium/high/critical",
    "indicators": ["威胁指标列表"],
    "confidence": 0.0-1.0
}}
            """,
            
            'data_leak': """
请检测以下内容是否存在数据泄露风险：

内容:
{content}

检测重点：
1. 个人身份信息（PII）
2. 信用卡号、银行账户等金融信息
3. 密码、API密钥等认证信息
4. 企业敏感数据
5. 医疗健康信息

请以JSON格式返回：
{{
    "sensitive_data_detected": true/false,
    "data_types": ["检测到的敏感数据类型"],
    "risk_level": "low/medium/high/critical",
    "details": "具体说明",
    "confidence": 0.0-1.0
}}
            """,
            
            'classification': """
请对以下网络流量内容进行分类：

内容:
{content}

分类维度：
1. 内容类型（文本、图片、视频、文档等）
2. 应用类别（社交、办公、娱乐、金融等）
3. 业务类型（正常业务、可疑活动、恶意行为）
4. 数据敏感性（公开、内部、机密、绝密）

JSON格式返回：
{{
    "content_type": "内容类型",
    "application_category": "应用类别", 
    "business_type": "业务类型",
    "sensitivity_level": "敏感级别",
    "confidence": 0.0-1.0
}}
            """,
            
            'behavior': """
请分析以下网络行为的异常性：

流量数据:
{content}

行为分析重点：
1. 访问模式是否异常
2. 数据传输量是否正常
3. 时间模式是否可疑
4. 访问频率是否异常
5. 是否存在自动化行为特征

返回JSON：
{{
    "behavior_type": "行为类型",
    "anomaly_score": 0.0-1.0,
    "suspicious_patterns": ["可疑模式列表"],
    "risk_assessment": "low/medium/high",
    "recommendations": ["建议措施"]
}}
            """,
            
            'custom_analysis': """
请对以下内容进行综合分析：

内容:
{content}

请提供：
1. 内容摘要
2. 关键特征提取
3. 安全评估
4. 合规性检查
5. 建议处理方式

JSON格式：
{{
    "summary": "内容摘要",
    "key_features": ["关键特征"],
    "security_assessment": "安全评估",
    "compliance_status": "合规状态", 
    "recommended_action": "建议动作",
    "confidence": 0.0-1.0
}}
            """
        }
    
    def get_template(self, analysis_type: str) -> Optional[str]:
        """
        获取指定类型的提示词模板
        
        Args:
            analysis_type: 分析类型
            
        Returns:
            提示词模板字符串，如果不存在返回None
        """
        return self.templates.get(analysis_type)
    
    def add_template(self, analysis_type: str, template: str):
        """
        添加新的提示词模板
        
        Args:
            analysis_type: 分析类型
            template: 提示词模板
        """
        self.templates[analysis_type] = template
    
    def get_all_types(self) -> list:
        """获取所有可用的分析类型"""
        return list(self.templates.keys())
    
    def update_template(self, analysis_type: str, template: str) -> bool:
        """
        更新现有的提示词模板
        
        Args:
            analysis_type: 分析类型
            template: 新的提示词模板
            
        Returns:
            更新是否成功
        """
        if analysis_type in self.templates:
            self.templates[analysis_type] = template
            return True
        return False
