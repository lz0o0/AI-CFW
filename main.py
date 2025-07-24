#!/usr/bin/env python3
"""
CFW高级防火墙系统 - 主入口文件

功能特性：
1. 流量拦截和处理 - 能够接管处理流经防火墙的流量
2. 双模式处理 - 支持直接处理和镜像处理两种模式
3. SSL/TLS解析 - 加密流量解析处理，包含证书部署
4. 深度包检测 - 基于LLM的智能流量分析
5. 透明代理 - 无感知的流量拦截和处理

作者: Leep
"""

import sys
import os
import json
import argparse
import logging
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from core.firewall_manager import FirewallManager
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"警告: 无法导入核心模块: {e}")
    CORE_AVAILABLE = False

try:
    from utils.install_dependencies import main as install_dependencies
    INSTALL_AVAILABLE = True
except ImportError:
    def install_dependencies():
        print("依赖安装功能不可用")
    INSTALL_AVAILABLE = False


def setup_logging(log_level="INFO"):
    """设置日志系统"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('firewall.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def check_dependencies():
    """检查并安装依赖"""
    try:
        import scapy
        import cryptography
        print("✓ 依赖检查通过")
        return True
    except ImportError as e:
        print(f"✗ 缺少依赖: {e}")
        print("正在安装依赖...")
        install_dependencies()
        return True


def _test_ai_models(config_file: str) -> dict:
    """测试AI模型连接"""
    results = {
        'openai': {'available': False, 'error': None},
        'claude': {'available': False, 'error': None},
        'local_llm': {'available': False, 'error': None}
    }
    
    try:
        # 加载配置
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            config = {}
        
        ai_config = config.get('ai_analysis', {})
        
        # 测试OpenAI
        openai_config = ai_config.get('openai', {})
        if openai_config.get('api_key'):
            try:
                from processors.llm_integration.openai_processor import OpenAIProcessor
                processor = OpenAIProcessor(openai_config)
                if processor.available:
                    results['openai']['available'] = True
                else:
                    results['openai']['error'] = "API key invalid or service unavailable"
            except Exception as e:
                results['openai']['error'] = str(e)
        else:
            results['openai']['error'] = "API key not configured"
        
        # 测试Claude
        claude_config = ai_config.get('claude', {})
        if claude_config.get('api_key'):
            try:
                from processors.llm_integration.claude_processor import ClaudeProcessor
                processor = ClaudeProcessor(claude_config)
                if processor.available:
                    results['claude']['available'] = True
                else:
                    results['claude']['error'] = "API key invalid or service unavailable"
            except Exception as e:
                results['claude']['error'] = str(e)
        else:
            results['claude']['error'] = "API key not configured"
        
        # 测试本地LLM
        local_config = ai_config.get('local_llm', {})
        try:
            from processors.llm_integration.local_llm_processor import LocalLLMProcessor
            processor = LocalLLMProcessor(local_config)
            if processor.available:
                results['local_llm']['available'] = True
                # 获取详细连接信息
                connection_info = processor.test_connection()
                results['local_llm']['details'] = connection_info
            else:
                results['local_llm']['error'] = f"Service not available at {local_config.get('api_endpoint', 'localhost:11434')}"
        except Exception as e:
            results['local_llm']['error'] = str(e)
            
    except Exception as e:
        print(f"测试过程出错: {e}")
    
    return results


def _display_ai_test_results(results: dict):
    """显示AI测试结果"""
    print("\n=== AI模型连接测试结果 ===")
    
    for model_name, result in results.items():
        status = "✓" if result['available'] else "✗"
        print(f"{status} {model_name.upper()}: {'可用' if result['available'] else '不可用'}")
        
        if result.get('error'):
            print(f"   错误: {result['error']}")
        
        if result.get('details'):
            details = result['details']
            if details.get('available_models'):
                print(f"   可用模型: {', '.join(details['available_models'])}")
    
    print()


def _check_configuration(config_file: str) -> dict:
    """检查配置文件"""
    issues = {
        'errors': [],
        'warnings': [],
        'recommendations': []
    }
    
    try:
        if not os.path.exists(config_file):
            issues['errors'].append(f"配置文件不存在: {config_file}")
            return issues
        
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # 检查必需的配置项
        required_sections = ['firewall', 'ssl', 'dpi']
        for section in required_sections:
            if section not in config:
                issues['warnings'].append(f"缺少配置节: {section}")
        
        # 检查SSL配置
        ssl_config = config.get('ssl', {})
        if ssl_config.get('enable_interception', False):
            ca_cert = ssl_config.get('ca_cert_path', './ssl_certs/ca.crt')
            ca_key = ssl_config.get('ca_key_path', './ssl_certs/ca.key')
            
            if not os.path.exists(ca_cert):
                issues['warnings'].append(f"CA证书文件不存在: {ca_cert}")
            if not os.path.exists(ca_key):
                issues['warnings'].append(f"CA私钥文件不存在: {ca_key}")
        
        # 检查AI配置
        ai_config = config.get('ai_analysis', {})
        enabled_models = ai_config.get('enabled_models', [])
        
        for model in enabled_models:
            model_config = ai_config.get(model, {})
            if model in ['openai', 'claude'] and not model_config.get('api_key'):
                issues['warnings'].append(f"{model.upper()} API密钥未配置")
        
        # 检查处理器配置
        processors = config.get('processors', {})
        enabled_processors = processors.get('enabled', [])
        
        if 'ai_content_analyzer' in enabled_processors and not ai_config:
            issues['warnings'].append("启用了AI内容分析器但未配置AI分析参数")
        
        # 生成建议
        if not enabled_models:
            issues['recommendations'].append("建议启用至少一个AI模型以获得最佳分析效果")
        
        if not ssl_config.get('enable_interception', False):
            issues['recommendations'].append("建议启用SSL拦截以分析加密流量")
        
        if not config.get('dpi', {}).get('enable', False):
            issues['recommendations'].append("建议启用DPI引擎以获得深度包检测功能")
        
    except json.JSONDecodeError as e:
        issues['errors'].append(f"配置文件JSON格式错误: {e}")
    except Exception as e:
        issues['errors'].append(f"配置检查出错: {e}")
    
    return issues


def _display_config_issues(issues: dict):
    """显示配置问题"""
    print("\n=== 配置文件检查结果 ===")
    
    if issues['errors']:
        print("❌ 错误:")
        for error in issues['errors']:
            print(f"   - {error}")
    
    if issues['warnings']:
        print("⚠️  警告:")
        for warning in issues['warnings']:
            print(f"   - {warning}")
    
    if issues['recommendations']:
        print("💡 建议:")
        for rec in issues['recommendations']:
            print(f"   - {rec}")
    
    if not any([issues['errors'], issues['warnings'], issues['recommendations']]):
        print("✅ 配置文件检查通过，未发现问题")
    
    print()


def main():
    """主入口函数"""
    parser = argparse.ArgumentParser(
        description="CFW高级防火墙系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s start                    # 启动防火墙
  %(prog)s start --mode direct      # 启动直接处理模式
  %(prog)s start --mode mirror      # 启动镜像处理模式
  %(prog)s ssl-setup               # 设置SSL拦截
  %(prog)s ssl-deploy              # 部署SSL证书
  %(prog)s status                  # 查看状态
  %(prog)s stop                    # 停止防火墙
  
高级功能:
  %(prog)s transparent-proxy       # 启动透明代理模式
  %(prog)s dpi-analyze            # 开启深度包检测分析
  %(prog)s llm-detection          # 启用LLM流量检测
  %(prog)s ai-analysis            # 启用AI智能内容分析
  %(prog)s crypto-analysis        # 启用加密和证书分析
  %(prog)s test-ai                # 测试AI模型连接
  %(prog)s config-check           # 检查配置文件
  %(prog)s threat-log             # 查看威胁日志
  %(prog)s threat-stats           # 查看威胁统计
  %(prog)s export-report          # 导出威胁报告
        """
    )
    
    parser.add_argument(
        'command',
        choices=['start', 'stop', 'status', 'ssl-setup', 'ssl-deploy', 
                'transparent-proxy', 'dpi-analyze', 'llm-detection', 'install-deps',
                'ai-analysis', 'crypto-analysis', 'test-ai', 'config-check',
                'threat-log', 'threat-stats', 'export-report'],
        help='执行的命令'
    )
    
    parser.add_argument(
        '--mode',
        choices=['direct', 'mirror'],
        default='direct',
        help='处理模式：direct(直接处理) 或 mirror(镜像处理)'
    )
    
    parser.add_argument(
        '--config',
        default='firewall_config.json',
        help='配置文件路径'
    )
    
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='查看最近多少小时的威胁日志（默认24小时）'
    )
    
    parser.add_argument(
        '--output',
        default='threat_report.json',
        help='威胁报告输出文件路径'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='日志级别'
    )
    
    args = parser.parse_args()
    
    # 设置日志
    setup_logging(args.log_level)
    
    # 检查核心模块可用性
    if not CORE_AVAILABLE and args.command != 'install-deps':
        print("错误: 核心模块不可用，请先运行 'python main.py install-deps'")
        return 1
    
    # 处理安装依赖命令
    if args.command == 'install-deps':
        print("开始安装依赖...")
        install_dependencies()
        return 0
    
    # 检查配置文件
    if not os.path.exists(args.config):
        print(f"警告: 配置文件不存在: {args.config}")
        print("使用默认配置")
    
    try:
        # 创建防火墙管理器
        firewall = FirewallManager(args.config)
        
        # 处理命令
        if args.command == 'start':
            print(f"启动防火墙，模式: {args.mode}")
            # 设置流量处理模式
            if args.mode == 'mirror':
                firewall.enable_traffic_interception('mirror')
            else:
                firewall.enable_traffic_interception('direct')
            
            if firewall.start():
                print("✓ 防火墙启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止防火墙...")
                    firewall.stop()
                    print("✓ 防火墙已停止")
            else:
                print("✗ 防火墙启动失败")
                return 1
        
        elif args.command == 'stop':
            print("停止防火墙...")
            if firewall.stop():
                print("✓ 防火墙已停止")
            else:
                print("✗ 防火墙停止失败")
                return 1
        
        elif args.command == 'status':
            status = firewall.status()
            print("=== 防火墙状态 ===")
            print(f"运行状态: {'运行中' if status.get('running', False) else '已停止'}")
            
            # 显示高级功能状态
            advanced_features = status.get('advanced_features', {})
            print(f"高级功能可用: {'是' if advanced_features.get('available', False) else '否'}")
            print(f"流量处理模式: {advanced_features.get('traffic_mode', '未知')}")
            print(f"SSL拦截: {'启用' if advanced_features.get('ssl_interception', False) else '禁用'}")
            print(f"DPI引擎: {'启用' if advanced_features.get('dpi_enabled', False) else '禁用'}")
            
            # 显示高级统计信息
            advanced_stats = status.get('advanced_stats', {})
            if advanced_stats:
                print("\n=== 组件状态 ===")
                for component, info in advanced_stats.items():
                    print(f"{component}: {info.get('status', '未知')}")
        
        elif args.command == 'ssl-setup':
            print("设置SSL拦截...")
            if firewall.enable_ssl_interception():
                print("✓ SSL拦截设置成功")
            else:
                print("✗ SSL拦截设置失败")
                return 1
        
        elif args.command == 'ssl-deploy':
            print("部署CA证书...")
            if firewall.deploy_ca_certificate():
                print("✓ CA证书部署成功")
            else:
                print("✗ CA证书部署失败")
                return 1
        
        elif args.command == 'transparent-proxy':
            print("启动透明代理模式...")
            # 设置配置为透明代理模式
            if hasattr(firewall, 'config'):
                firewall.config.setdefault('firewall', {})['mode'] = 'transparent_proxy'
            
            if firewall.start():
                print("✓ 透明代理启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止透明代理...")
                    firewall.stop()
                    print("✓ 透明代理已停止")
            else:
                print("✗ 透明代理启动失败")
                return 1
        
        elif args.command == 'dpi-analyze':
            print("开启深度包检测分析...")
            # 启用DPI功能
            firewall.enable_dpi()
            
            if firewall.start():
                print("✓ DPI分析启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止DPI分析...")
                    firewall.stop()
                    print("✓ DPI分析已停止")
            else:
                print("✗ DPI分析启动失败")
                return 1
        
        elif args.command == 'llm-detection':
            print("启用LLM流量检测...")
            # 启用DPI引擎（包含LLM检测）
            firewall.enable_dpi()
            
            if firewall.start():
                print("✓ LLM检测启动成功")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止LLM检测...")
                    firewall.stop()
                    print("✓ LLM检测已停止")
            else:
                print("✗ LLM检测启动失败")
                return 1
        
        elif args.command == 'ai-analysis':
            print("启用AI智能内容分析...")
            # 启用AI分析功能
            firewall.enable_ai_analysis()
            
            if firewall.start():
                print("✓ AI分析启动成功")
                print("支持的AI模型: OpenAI, Claude, 本地LLM")
                print("分析类型: 安全扫描, 威胁检测, 数据泄露检测, 行为分析")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止AI分析...")
                    firewall.stop()
                    print("✓ AI分析已停止")
            else:
                print("✗ AI分析启动失败")
                return 1
        
        elif args.command == 'crypto-analysis':
            print("启用加密和证书分析...")
            # 启用加密分析功能
            firewall.enable_crypto_analysis()
            
            if firewall.start():
                print("✓ 加密分析启动成功")
                print("功能包括: SSL/TLS分析, 证书验证, 加密算法评估")
                print("按 Ctrl+C 停止...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n正在停止加密分析...")
                    firewall.stop()
                    print("✓ 加密分析已停止")
            else:
                print("✗ 加密分析启动失败")
                return 1
        
        elif args.command == 'test-ai':
            print("测试AI模型连接...")
            test_results = _test_ai_models(args.config)
            _display_ai_test_results(test_results)
            return 0
        
        elif args.command == 'config-check':
            print("检查配置文件...")
            config_issues = _check_configuration(args.config)
            _display_config_issues(config_issues)
            return 0
        
        elif args.command == 'threat-log':
            print(f"查看最近 {args.hours} 小时的威胁日志...")
            _display_threat_log(args.config, args.hours)
            return 0
        
        elif args.command == 'threat-stats':
            print("查看威胁统计信息...")
            _display_threat_stats(args.config)
            return 0
        
        elif args.command == 'export-report':
            print(f"导出最近 {args.hours} 小时的威胁报告...")
            success = _export_threat_report(args.config, args.output, args.hours)
            if success:
                print(f"✓ 威胁报告已导出到: {args.output}")
            else:
                print("✗ 威胁报告导出失败")
                return 1
            return 0
    
    except Exception as e:
        print(f"错误: {e}")
        logging.exception("程序执行异常")
        return 1
    
    return 0


def _display_threat_log(config_path, hours):
    """显示威胁日志"""
    import json
    from datetime import datetime, timedelta
    
    try:
        # 读取配置获取威胁日志路径
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        threat_log_dir = config.get('threat_detection', {}).get('threat_log_dir', 'logs/threats')
        threat_log_file = f"{threat_log_dir}/threat_log.json"
        
        # 读取威胁日志
        try:
            with open(threat_log_file, 'r', encoding='utf-8') as f:
                threat_entries = [json.loads(line.strip()) for line in f if line.strip()]
        except FileNotFoundError:
            print("未找到威胁日志文件")
            return
        
        # 过滤指定时间范围内的记录
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_threats = []
        
        for entry in threat_entries:
            entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
            if entry_time >= cutoff_time:
                recent_threats.append(entry)
        
        if not recent_threats:
            print(f"最近 {hours} 小时内未发现威胁")
            return
        
        print(f"最近 {hours} 小时发现的威胁 ({len(recent_threats)} 条):")
        print("-" * 80)
        
        for entry in recent_threats[-20:]:  # 显示最近20条
            time_str = entry['timestamp'][:19].replace('T', ' ')
            print(f"🚨 [{time_str}] {entry['threat_type']}")
            print(f"   来源: {entry['source_ip']}:{entry['source_port']}")
            print(f"   目标: {entry['dest_ip']}:{entry['dest_port']}")
            print(f"   风险等级: {entry['risk_level']}")
            print(f"   处理策略: {entry['action_taken']}")
            if entry.get('details'):
                print(f"   详情: {entry['details'][:100]}...")
            print()
    
    except Exception as e:
        print(f"读取威胁日志时出错: {e}")


def _display_threat_stats(config_path):
    """显示威胁统计信息"""
    import json
    from datetime import datetime, timedelta
    from collections import defaultdict, Counter
    
    try:
        # 读取配置获取威胁日志路径
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        threat_log_dir = config.get('threat_detection', {}).get('threat_log_dir', 'logs/threats')
        threat_log_file = f"{threat_log_dir}/threat_log.json"
        
        # 读取威胁日志
        try:
            with open(threat_log_file, 'r', encoding='utf-8') as f:
                threat_entries = [json.loads(line.strip()) for line in f if line.strip()]
        except FileNotFoundError:
            print("未找到威胁日志文件")
            return
        
        if not threat_entries:
            print("暂无威胁记录")
            return
        
        # 统计信息
        threat_types = Counter()
        risk_levels = Counter()
        actions_taken = Counter()
        hourly_stats = defaultdict(int)
        daily_stats = defaultdict(int)
        
        for entry in threat_entries:
            threat_types[entry['threat_type']] += 1
            risk_levels[entry['risk_level']] += 1
            actions_taken[entry['action_taken']] += 1
            
            # 时间统计
            timestamp = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')
            day_key = timestamp.strftime('%Y-%m-%d')
            hourly_stats[hour_key] += 1
            daily_stats[day_key] += 1
        
        print("=== 威胁统计报告 ===")
        print(f"总威胁数量: {len(threat_entries)}")
        print()
        
        print("威胁类型分布:")
        for threat_type, count in threat_types.most_common():
            print(f"  {threat_type}: {count} 次")
        print()
        
        print("风险等级分布:")
        for risk_level, count in risk_levels.most_common():
            print(f"  {risk_level}: {count} 次")
        print()
        
        print("处理策略分布:")
        for action, count in actions_taken.most_common():
            print(f"  {action}: {count} 次")
        print()
        
        print("最近7天威胁趋势:")
        recent_days = sorted(daily_stats.keys())[-7:]
        for day in recent_days:
            print(f"  {day}: {daily_stats[day]} 次")
    
    except Exception as e:
        print(f"生成威胁统计时出错: {e}")


def _export_threat_report(config_path, output_path, hours):
    """导出威胁报告"""
    import json
    from datetime import datetime, timedelta
    
    try:
        # 读取配置获取威胁日志路径
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        threat_log_dir = config.get('threat_detection', {}).get('threat_log_dir', 'logs/threats')
        threat_log_file = f"{threat_log_dir}/threat_log.json"
        
        # 读取威胁日志
        try:
            with open(threat_log_file, 'r', encoding='utf-8') as f:
                threat_entries = [json.loads(line.strip()) for line in f if line.strip()]
        except FileNotFoundError:
            return False
        
        # 过滤指定时间范围内的记录
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_threats = []
        
        for entry in threat_entries:
            entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
            if entry_time >= cutoff_time:
                recent_threats.append(entry)
        
        # 生成报告
        report = {
            "report_generated": datetime.now().isoformat(),
            "time_range_hours": hours,
            "total_threats": len(recent_threats),
            "threats": recent_threats
        }
        
        # 导出到文件
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        return True
    
    except Exception as e:
        print(f"导出威胁报告时出错: {e}")
        return False


if __name__ == "__main__":
    sys.exit(main())
