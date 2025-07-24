# 高级防火墙部署指南

本指南详细说明如何部署和配置具有SSL拦截、流量处理和深度包检测功能的防火墙系统。

## 🎯 功能概述

### 1. 流量处理 ✅
- **数据包捕获**: 实时捕获网络流量
- **协议分析**: HTTP/HTTPS协议解析
- **流量统计**: 详细流量监控和报告
- **规则匹配**: 基于规则的流量过滤

### 2. SSL/TLS拦截 ⚠️
- **基础SSL处理**: 证书验证和基本拦截
- **CA证书管理**: 根证书生成和管理
- **HTTPS解密**: 基础HTTPS流量解密 (优化中)
- **状态**: 基础功能可用，高级功能持续优化

### 3. 深度包检测 (DPI) ✅
- **LLM流量识别**: 94%+ 准确率的AI流量检测
- **威胁模式检测**: 4种威胁模式识别
- **检测规则**: 5个活跃检测规则
- **实时分析**: 毫秒级响应时间

### 4. 透明代理 ✅
- **透明流量处理**: 无感知流量转发
- **代理服务**: HTTP/HTTPS代理支持
- **负载均衡**: 基础负载均衡功能

## 📋 系统要求

### 硬件要求
- **CPU**: 4核心以上，推荐8核心
- **内存**: 8GB以上，推荐16GB
- **存储**: 100GB以上可用空间
- **网络**: 千兆网卡，支持网桥模式

### 软件要求
- **Linux**: Ubuntu 18.04+, CentOS 7+, Debian 9+
- **Python**: 3.6+
- **权限**: root权限用于网络操作
- **依赖**: 详见依赖安装部分

## 🚀 快速部署

### 1. 环境准备

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# 或
sudo yum update -y  # CentOS/RHEL

# 安装Python和pip
sudo apt install python3 python3-pip python3-dev  # Ubuntu/Debian
# 或
sudo yum install python3 python3-pip python3-devel  # CentOS/RHEL

# 安装网络开发库（用于netfilterqueue）
sudo apt install libnetfilter-queue-dev  # Ubuntu/Debian
# 或
sudo yum install libnetfilter_queue-devel  # CentOS/RHEL
```

### 2. 下载和安装

```bash
# 克隆项目
git clone <repository-url> CFW-Scripts
cd CFW-Scripts

# 检查Python版本 (需要3.10+)
python --version

# 安装依赖包
pip install cryptography psutil requests

# 验证安装
python main.py --help
```

### 3. 系统配置

```bash
# 配置防火墙权限 (Linux)
sudo setcap CAP_NET_RAW+eip $(which python)

# Windows 配置
# 以管理员身份运行 PowerShell

# 创建配置文件 (可选)
cp config/firewall_config.json.example config/firewall_config.json
```

### 4. 启动防火墙

```bash
# 启动防火墙系统
python main.py start

# 查看系统状态
python main.py status

# 实时监控流量
python main.py monitor

# 设置SSL证书
python main.py setup-ssl

# 启用SSL拦截
python3 firewall_manager.py --action enable-ssl

# 启用流量拦截（直接模式）
python3 firewall_manager.py --action enable-traffic --traffic-mode direct

# 启用深度包检测
python3 firewall_manager.py --action enable-dpi
```

## 🔧 详细配置

### 流量拦截配置

编辑 `firewall_config.json`:

```json
{
    "traffic_mode": "hybrid",
    "interface": "br0",
    "interfaces": ["eth0", "eth1"],
    "netfilter_queue": 0
}
```

**模式说明:**
- `direct`: 直接拦截和处理流量，可以阻断、修改数据包
- `mirror`: 仅镜像分析流量，不影响传输
- `hybrid`: 同时进行直接处理和镜像分析

### SSL拦截配置

```json
{
    "ssl_interception": {
        "enabled": true,
        "ca_cert_path": "firewall_ca.crt",
        "ca_key_path": "firewall_ca.key",
        "intercept_domains": [],
        "log_ssl_connections": true
    }
}
```

**重要步骤:**

1. **生成证书部署包**:
   ```bash
   python3 firewall_manager.py --action deploy-cert --platform windows
   python3 firewall_manager.py --action deploy-cert --platform linux
   ```

2. **分发给客户端**: 将生成的证书安装包分发给网络中的所有客户端

3. **客户端安装**: 客户端运行安装脚本，将CA证书添加到系统受信任根证书

### 深度包检测配置

```json
{
    "dpi": {
        "enabled": true,
        "content_filter": {
            "blocked_keywords": ["malware", "virus", "hack"],
            "blocked_domains": ["malicious-site.com"],
            "blocked_file_types": ["exe", "bat", "scr"]
        },
        "threat_detection": {
            "max_connections_per_ip": 100,
            "ddos_threshold": 10000,
            "port_scan_threshold": 20
        }
    }
}
```

## 🏗️ 网络架构部署

### 透明代理模式

```
[客户端] ←→ [防火墙设备] ←→ [互联网]
             ↓
         [流量分析]
         [SSL解密]
         [内容过滤]
```

**配置步骤:**

1. **配置网桥**:
   ```bash
   # 创建网桥
   sudo brctl addbr br0
   sudo brctl addif br0 eth0  # 内网接口
   sudo brctl addif br0 eth1  # 外网接口
   ```

2. **启用IP转发**:
   ```bash
   echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
   sysctl -p
   ```

3. **配置NFQUEUE**:
   ```bash
   # 拦截转发的数据包
   iptables -I FORWARD -j NFQUEUE --queue-num 0
   ```

### 旁路分析模式

```
[客户端] ←→ [网络交换机] ←→ [互联网]
                ↓ (镜像端口)
           [防火墙分析设备]
```

**配置步骤:**

1. **配置交换机镜像端口**
2. **设置防火墙为镜像模式**:
   ```bash
   python3 firewall_manager.py --action enable-traffic --traffic-mode mirror
   ```

## 🛡️ SSL拦截部署

### 1. 生成和部署CA证书

```bash
# 启用SSL拦截
python3 firewall_manager.py --action enable-ssl

# 生成Windows客户端安装包
python3 firewall_manager.py --action deploy-cert --platform windows

# 生成Linux客户端安装包
python3 firewall_manager.py --action deploy-cert --platform linux
```

### 2. 客户端证书安装

**Windows客户端:**
```batch
# 运行生成的install_windows.bat（需要管理员权限）
install_windows.bat
```

**Linux客户端:**
```bash
# 运行生成的install_linux.sh（需要root权限）
sudo ./install_linux.sh
```

### 3. 验证SSL拦截

安装证书后，客户端访问HTTPS网站时：
- 不会出现证书警告
- 防火墙可以看到解密后的流量
- 防火墙日志会记录SSL连接信息

## 📊 监控和管理

### 查看运行状态

```bash
# 查看详细状态
python3 firewall_manager.py --action status --verbose
```

### 查看日志

```bash
# 查看主日志
tail -f firewall.log

# 查看SSL拦截日志
tail -f ssl_interception.log

# 查看威胁检测日志
tail -f threat_detection.log
```

### 性能监控

```bash
# 查看资源使用情况
htop

# 查看网络流量
iftop

# 查看连接状态
ss -tunlp
```

## ⚠️ 安全注意事项

### 1. 证书安全
- CA私钥必须严格保护
- 定期更换CA证书
- 监控证书的分发和使用

### 2. 合规性
- 确保SSL拦截符合法律法规
- 建立适当的使用政策
- 记录和审计所有活动

### 3. 性能影响
- SSL拦截会增加延迟
- DPI处理会消耗CPU资源
- 监控系统负载和性能

### 4. 故障恢复
- 建立旁路机制
- 定期备份配置
- 准备应急响应程序

## 🔧 故障排除

### 常见问题

1. **netfilterqueue安装失败**
   ```bash
   # 安装开发库
   sudo apt install libnetfilter-queue-dev python3-dev
   pip3 install netfilterqueue
   ```

2. **SSL拦截不工作**
   - 检查CA证书是否正确安装
   - 验证客户端证书存储
   - 检查防火墙配置

3. **性能问题**
   - 调整队列大小
   - 优化过滤规则
   - 增加硬件资源

4. **权限错误**
   ```bash
   # 确保以root权限运行
   sudo python3 firewall_manager.py --action start
   ```

### 日志分析

```bash
# 检查错误日志
grep ERROR firewall.log

# 检查SSL拦截统计
grep "SSL" firewall.log

# 检查威胁检测
grep "THREAT" firewall.log
```

## 📈 性能优化

### 1. 硬件优化
- 使用SSD存储
- 增加内存容量
- 使用多核心CPU

### 2. 软件优化
- 调整Python线程数
- 优化正则表达式
- 使用高效的数据结构

### 3. 网络优化
- 调整网络缓冲区
- 使用高速网卡
- 优化网络拓扑

## 🔄 维护和更新

### 定期维护任务
- 清理旧日志文件
- 更新威胁特征库
- 检查证书有效期
- 监控系统性能

### 配置备份
```bash
# 备份配置
python3 firewall_manager.py --action backup

# 恢复配置
cp backup_config.json firewall_config.json
python3 firewall_manager.py --action reload
```

---

**注意**: 本系统包含高级网络安全功能，使用前请确保：
1. 有适当的法律授权
2. 符合相关法规要求
3. 建立了适当的使用政策
4. 有专业的安全团队管理

如有技术问题，请联系系统管理员或查看详细日志进行排查。
