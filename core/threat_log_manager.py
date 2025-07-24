"""
威胁日志管理器

专门处理敏感数据检测、威胁记录和告警功能
支持多种处理策略：隐写替换、拦截阻断、静默记录
"""

import os
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from enum import Enum
import hashlib
import tkinter as tk
from tkinter import messagebox
import queue
import time


class SensitiveDataStrategy(Enum):
    """敏感数据处理策略枚举"""
    STEGANOGRAPHY = "steganography"  # 隐写替换
    BLOCK = "block"                  # 拦截阻断
    SILENT_LOG = "silent_log"        # 静默记录


class ThreatLevel(Enum):
    """威胁等级枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLogManager:
    """威胁日志管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化威胁日志管理器
        
        Args:
            config: 配置字典
        """
        self.config = config
        self.logger = logging.getLogger('ThreatLogManager')
        
        # 敏感数据处理配置
        self.sensitive_config = config.get('sensitive_data_handling', {})
        self.strategy = SensitiveDataStrategy(self.sensitive_config.get('strategy', 'steganography'))
        self.strategies_config = self.sensitive_config.get('strategies', {})
        
        # 告警配置
        self.alert_config = self.sensitive_config.get('alert_settings', {})
        self.enable_popup = self.alert_config.get('enable_popup', True)
        self.popup_timeout = self.alert_config.get('popup_timeout', 10)
        self.enable_sound = self.alert_config.get('enable_sound', False)
        self.enable_email = self.alert_config.get('enable_email', False)
        
        # 威胁日志配置
        self.threat_log_config = self.sensitive_config.get('threat_log', {})
        self.threat_log_path = self.threat_log_config.get('file_path', './logs/threat_log.json')
        self.max_file_size = self._parse_size(self.threat_log_config.get('max_file_size', '50MB'))
        self.backup_count = self.threat_log_config.get('backup_count', 10)
        self.retention_days = self.threat_log_config.get('retention_days', 30)
        
        # 创建日志目录
        os.makedirs(os.path.dirname(self.threat_log_path), exist_ok=True)
        
        # 弹窗队列和线程
        self.popup_queue = queue.Queue()
        self.popup_thread = None
        if self.enable_popup:
            self._start_popup_thread()
        
        # 威胁统计
        self.threat_stats = {
            'total_threats': 0,
            'threats_by_level': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'threats_by_type': {},
            'actions_taken': {'steganography': 0, 'block': 0, 'silent_log': 0}
        }
        
        self.logger.info("威胁日志管理器初始化完成")
    
    def handle_sensitive_data(self, data: bytes, metadata: Dict[str, Any], 
                            detected_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        处理敏感数据检测结果
        
        Args:
            data: 原始数据
            metadata: 元数据
            detected_items: 检测到的敏感数据项
            
        Returns:
            处理结果字典
        """
        try:
            # 评估威胁等级
            threat_level = self._assess_threat_level(detected_items)
            
            # 创建威胁记录
            threat_record = self._create_threat_record(
                data, metadata, detected_items, threat_level
            )
            
            # 记录到威胁日志
            self._log_threat(threat_record)
            
            # 根据策略处理数据
            result = self._apply_strategy(data, detected_items, threat_record)
            
            # 触发告警
            if self._should_alert(threat_level):
                self._trigger_alert(threat_record)
            
            # 更新统计信息
            self._update_stats(threat_level, detected_items, result['action'])
            
            return result
            
        except Exception as e:
            self.logger.error(f"敏感数据处理失败: {e}")
            return {
                'action': 'allow',
                'modified_data': data,
                'reason': f'处理异常: {str(e)}',
                'threat_id': None
            }
    
    def _assess_threat_level(self, detected_items: List[Dict[str, Any]]) -> ThreatLevel:
        """评估威胁等级"""
        if not detected_items:
            return ThreatLevel.LOW
        
        # 威胁等级评分规则
        score = 0
        high_risk_types = ['credit_card', 'ssn', 'api_key', 'password']
        medium_risk_types = ['email', 'phone']
        
        for item in detected_items:
            data_type = item.get('type', '')
            if data_type in high_risk_types:
                score += 3
            elif data_type in medium_risk_types:
                score += 1
            else:
                score += 0.5
        
        # 多种敏感数据类型增加风险
        unique_types = len(set(item.get('type', '') for item in detected_items))
        if unique_types >= 3:
            score += 2
        
        # 确定威胁等级
        if score >= 8:
            return ThreatLevel.CRITICAL
        elif score >= 5:
            return ThreatLevel.HIGH
        elif score >= 2:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _create_threat_record(self, data: bytes, metadata: Dict[str, Any], 
                            detected_items: List[Dict[str, Any]], 
                            threat_level: ThreatLevel) -> Dict[str, Any]:
        """创建威胁记录"""
        threat_id = hashlib.md5(
            f"{datetime.now().isoformat()}{metadata.get('src_ip', '')}{len(data)}".encode()
        ).hexdigest()[:16]
        
        return {
            'threat_id': threat_id,
            'timestamp': datetime.now().isoformat(),
            'threat_level': threat_level.value,
            'detected_items': detected_items,
            'metadata': {
                'src_ip': metadata.get('src_ip', 'unknown'),
                'dst_ip': metadata.get('dst_ip', 'unknown'),
                'protocol': metadata.get('protocol', 'unknown'),
                'data_size': len(data)
            },
            'data_sample': data[:200].decode('utf-8', errors='ignore'),  # 只保存前200字符样本
            'action_taken': None,  # 将在应用策略时填充
            'alert_sent': False,
            'notes': []
        }
    
    def _apply_strategy(self, data: bytes, detected_items: List[Dict[str, Any]], 
                       threat_record: Dict[str, Any]) -> Dict[str, Any]:
        """应用处理策略"""
        strategy_config = self.strategies_config.get(self.strategy.value, {})
        
        if not strategy_config.get('enabled', True):
            # 策略被禁用，默认允许通过但记录
            threat_record['action_taken'] = 'allowed_disabled_strategy'
            return {
                'action': 'allow',
                'modified_data': data,
                'reason': f'策略 {self.strategy.value} 已禁用',
                'threat_id': threat_record['threat_id']
            }
        
        if self.strategy == SensitiveDataStrategy.STEGANOGRAPHY:
            return self._apply_steganography(data, detected_items, threat_record)
        elif self.strategy == SensitiveDataStrategy.BLOCK:
            return self._apply_block(data, detected_items, threat_record)
        elif self.strategy == SensitiveDataStrategy.SILENT_LOG:
            return self._apply_silent_log(data, detected_items, threat_record)
        else:
            # 未知策略，默认静默记录
            return self._apply_silent_log(data, detected_items, threat_record)
    
    def _apply_steganography(self, data: bytes, detected_items: List[Dict[str, Any]], 
                           threat_record: Dict[str, Any]) -> Dict[str, Any]:
        """应用隐写替换策略"""
        try:
            modified_data = data.decode('utf-8', errors='ignore')
            replacement_patterns = self.strategies_config.get('steganography', {}).get('replacement_patterns', {})
            
            replacements_made = []
            
            for item in detected_items:
                data_type = item.get('type', '')
                original_value = item.get('match', '')
                replacement = replacement_patterns.get(data_type, '***REDACTED***')
                
                if original_value in modified_data:
                    modified_data = modified_data.replace(original_value, replacement)
                    replacements_made.append({
                        'type': data_type,
                        'original_length': len(original_value),
                        'replacement': replacement
                    })
            
            threat_record['action_taken'] = 'steganography'
            threat_record['replacements'] = replacements_made
            
            return {
                'action': 'modify',
                'modified_data': modified_data.encode('utf-8'),
                'reason': f'敏感数据已隐写替换 (替换了 {len(replacements_made)} 项)',
                'threat_id': threat_record['threat_id']
            }
            
        except Exception as e:
            self.logger.error(f"隐写替换失败: {e}")
            threat_record['action_taken'] = 'steganography_failed'
            return {
                'action': 'allow',
                'modified_data': data,
                'reason': f'隐写替换失败: {str(e)}',
                'threat_id': threat_record['threat_id']
            }
    
    def _apply_block(self, data: bytes, detected_items: List[Dict[str, Any]], 
                    threat_record: Dict[str, Any]) -> Dict[str, Any]:
        """应用拦截阻断策略"""
        block_message = self.strategies_config.get('block', {}).get(
            'block_message', 'Connection blocked due to sensitive data detection'
        )
        
        threat_record['action_taken'] = 'blocked'
        threat_record['block_reason'] = f'检测到 {len(detected_items)} 项敏感数据'
        
        return {
            'action': 'block',
            'modified_data': None,
            'reason': block_message,
            'threat_id': threat_record['threat_id']
        }
    
    def _apply_silent_log(self, data: bytes, detected_items: List[Dict[str, Any]], 
                         threat_record: Dict[str, Any]) -> Dict[str, Any]:
        """应用静默记录策略"""
        threat_record['action_taken'] = 'silent_logged'
        threat_record['notes'].append('使用静默记录策略，允许流量通过但记录威胁')
        
        return {
            'action': 'allow',
            'modified_data': data,
            'reason': f'敏感数据已记录 (检测到 {len(detected_items)} 项)',
            'threat_id': threat_record['threat_id']
        }
    
    def _should_alert(self, threat_level: ThreatLevel) -> bool:
        """判断是否应该发送告警"""
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            return True
        
        # 检查配置中的告警阈值
        alert_threshold = self.alert_config.get('alert_threshold', 'medium')
        
        if alert_threshold == 'low':
            return True
        elif alert_threshold == 'medium':
            return threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        elif alert_threshold == 'high':
            return threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        else:  # critical
            return threat_level == ThreatLevel.CRITICAL
    
    def _trigger_alert(self, threat_record: Dict[str, Any]):
        """触发告警"""
        try:
            threat_record['alert_sent'] = True
            
            # 弹窗告警
            if self.enable_popup:
                self.popup_queue.put(threat_record)
            
            # 声音告警
            if self.enable_sound:
                self._play_alert_sound()
            
            # 邮件告警
            if self.enable_email:
                self._send_email_alert(threat_record)
                
        except Exception as e:
            self.logger.error(f"触发告警失败: {e}")
    
    def _start_popup_thread(self):
        """启动弹窗线程"""
        def popup_worker():
            while True:
                try:
                    threat_record = self.popup_queue.get(timeout=1)
                    self._show_popup_alert(threat_record)
                except queue.Empty:
                    continue
                except Exception as e:
                    self.logger.error(f"弹窗线程异常: {e}")
        
        self.popup_thread = threading.Thread(target=popup_worker, daemon=True)
        self.popup_thread.start()
    
    def _show_popup_alert(self, threat_record: Dict[str, Any]):
        """显示弹窗告警"""
        try:
            # 创建弹窗内容
            threat_level = threat_record['threat_level'].upper()
            threat_id = threat_record['threat_id']
            detected_count = len(threat_record['detected_items'])
            timestamp = threat_record['timestamp']
            src_ip = threat_record['metadata']['src_ip']
            action = threat_record['action_taken']
            
            title = f"🚨 CFW威胁检测告警 - {threat_level}"
            
            message = f"""
威胁ID: {threat_id}
时间: {timestamp}
威胁等级: {threat_level}
来源IP: {src_ip}
检测项目: {detected_count} 项敏感数据
处理动作: {action}

检测到的敏感数据类型:
"""
            
            for item in threat_record['detected_items']:
                data_type = item.get('type', 'unknown')
                message += f"• {data_type}\n"
            
            # 在主线程中显示弹窗
            def show_popup():
                root = tk.Tk()
                root.withdraw()  # 隐藏主窗口
                
                # 设置弹窗属性
                result = messagebox.showwarning(
                    title, 
                    message,
                    parent=root
                )
                
                root.destroy()
            
            # 在主线程中执行
            import threading
            if threading.current_thread() is threading.main_thread():
                show_popup()
            else:
                # 如果不在主线程，使用after方法
                root = tk.Tk()
                root.after(0, show_popup)
                root.mainloop()
                
        except Exception as e:
            self.logger.error(f"显示弹窗失败: {e}")
    
    def _log_threat(self, threat_record: Dict[str, Any]):
        """记录威胁到日志文件"""
        try:
            # 检查文件大小，必要时轮转
            self._rotate_log_if_needed()
            
            # 写入威胁记录
            with open(self.threat_log_path, 'a', encoding='utf-8') as f:
                json.dump(threat_record, f, ensure_ascii=False)
                f.write('\n')
            
            # 清理过期记录
            self._cleanup_old_logs()
            
        except Exception as e:
            self.logger.error(f"记录威胁日志失败: {e}")
    
    def _rotate_log_if_needed(self):
        """如果需要，轮转日志文件"""
        if not os.path.exists(self.threat_log_path):
            return
        
        if os.path.getsize(self.threat_log_path) > self.max_file_size:
            # 轮转日志文件
            for i in range(self.backup_count - 1, 0, -1):
                old_file = f"{self.threat_log_path}.{i}"
                new_file = f"{self.threat_log_path}.{i + 1}"
                if os.path.exists(old_file):
                    os.rename(old_file, new_file)
            
            # 重命名当前文件
            os.rename(self.threat_log_path, f"{self.threat_log_path}.1")
    
    def _cleanup_old_logs(self):
        """清理过期的日志记录"""
        # 这里可以实现按时间清理逻辑
        # 由于是JSON行格式，需要读取、过滤、重写
        pass
    
    def _parse_size(self, size_str: str) -> int:
        """解析大小字符串为字节数"""
        size_str = size_str.upper()
        if size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        else:
            return int(size_str)
    
    def _update_stats(self, threat_level: ThreatLevel, detected_items: List[Dict[str, Any]], action: str):
        """更新威胁统计信息"""
        self.threat_stats['total_threats'] += 1
        self.threat_stats['threats_by_level'][threat_level.value] += 1
        
        for item in detected_items:
            data_type = item.get('type', 'unknown')
            self.threat_stats['threats_by_type'][data_type] = \
                self.threat_stats['threats_by_type'].get(data_type, 0) + 1
        
        if action in self.threat_stats['actions_taken']:
            self.threat_stats['actions_taken'][action] += 1
    
    def get_threat_stats(self) -> Dict[str, Any]:
        """获取威胁统计信息"""
        return self.threat_stats.copy()
    
    def get_recent_threats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """获取最近的威胁记录"""
        threats = []
        if not os.path.exists(self.threat_log_path):
            return threats
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        try:
            with open(self.threat_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        record_time = datetime.fromisoformat(record['timestamp'])
                        if record_time >= cutoff_time:
                            threats.append(record)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except Exception as e:
            self.logger.error(f"读取威胁日志失败: {e}")
        
        return sorted(threats, key=lambda x: x['timestamp'], reverse=True)
    
    def export_threat_report(self, output_path: str, hours: int = 24) -> bool:
        """导出威胁报告"""
        try:
            threats = self.get_recent_threats(hours)
            stats = self.get_threat_stats()
            
            report = {
                'report_generated': datetime.now().isoformat(),
                'time_range_hours': hours,
                'statistics': stats,
                'threats': threats
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            
            return True
        except Exception as e:
            self.logger.error(f"导出威胁报告失败: {e}")
            return False
