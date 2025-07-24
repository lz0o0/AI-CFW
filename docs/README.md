# 防火墙管理脚本

这是一个可以部署在防火墙设备上运行的管理脚本，提供了完整的防火墙规则管理、监控和配置功能。

## 功能特性

- ✅ **跨平台支持**: 支持Linux和Windows系统
- ✅ **规则管理**: 添加、删除、列出防火墙规则
- ✅ **配置管理**: JSON格式的配置文件，支持热重载
- ✅ **日志记录**: 详细的操作日志和监控日志
- ✅ **服务化部署**: 支持systemd服务(Linux)和Windows服务
- ✅ **备份恢复**: 自动配置备份和恢复功能
- ✅ **状态监控**: 实时监控防火墙状态和资源使用
- ✅ **命令行接口**: 完整的CLI工具支持

## 系统要求

### Linux系统
- Python 3.6+
- iptables
- systemd (可选，用于服务化部署)
- root权限 (安装时需要)

### Windows系统
- Python 3.6+
- Windows防火墙API支持
- 管理员权限 (安装时需要)
- NSSM (可选，用于创建Windows服务)

## 快速开始

### Linux系统安装

1. **克隆或下载项目文件**
   ```bash
   # 确保所有文件都在同一目录中
   ls -la
   # 应该看到: firewall_manager.py, firewall_config.json, install.sh
   ```

2. **运行安装脚本**
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```

3. **启动服务**
   ```bash
   sudo systemctl start firewall-manager
   sudo systemctl status firewall-manager
   ```

### Windows系统安装

1. **以管理员身份运行PowerShell**

2. **执行安装脚本**
   ```powershell
   # 允许执行脚本（如果需要）
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   
   # 运行安装脚本
   .\install.ps1
   ```

3. **检查安装状态**
   ```powershell
   # 检查服务状态
   Get-Service FirewallManager
   ```

### 手动运行

如果不想安装为服务，也可以直接运行：

```bash
# Linux
python3 firewall_manager.py --action status

# Windows
python firewall_manager.py --action status
```

## 使用方法

### 命令行工具

```bash
# 查看帮助
firewall-manager --help

# 查看防火墙状态
firewall-manager --action status

# 启动防火墙服务
firewall-manager --action start

# 停止防火墙服务
firewall-manager --action stop

# 重新加载配置
firewall-manager --action reload

# 使用自定义配置文件
firewall-manager --config /path/to/config.json --action status
```

### 配置文件

配置文件位置：
- Linux: `/etc/firewall/firewall_config.json`
- Windows: `%ProgramData%\FirewallManager\firewall_config.json`

配置文件示例：
```json
{
    "log_level": "INFO",
    "log_file": "firewall.log",
    "interface": "eth0",
    "rules": [
        {
            "id": "allow_ssh",
            "name": "允许SSH",
            "action": "ALLOW",
            "protocol": "TCP",
            "source": "0.0.0.0/0",
            "destination": "0.0.0.0/0",
            "port": 22,
            "enabled": true,
            "priority": 100,
            "description": "允许SSH连接"
        }
    ],
    "whitelist": ["127.0.0.1", "::1"],
    "blacklist": [],
    "monitoring": {
        "enabled": true,
        "log_connections": true,
        "alert_threshold": 100,
        "check_interval": 60
    }
}
```

### 服务管理

#### Linux (systemd)
```bash
# 启动服务
sudo systemctl start firewall-manager

# 停止服务
sudo systemctl stop firewall-manager

# 重启服务
sudo systemctl restart firewall-manager

# 查看服务状态
sudo systemctl status firewall-manager

# 查看服务日志
sudo journalctl -u firewall-manager -f

# 开机自启
sudo systemctl enable firewall-manager

# 禁用开机自启
sudo systemctl disable firewall-manager
```

#### Windows
```powershell
# 启动服务
Start-Service FirewallManager

# 停止服务
Stop-Service FirewallManager

# 查看服务状态
Get-Service FirewallManager

# 设置自动启动
Set-Service FirewallManager -StartupType Automatic

# 设置手动启动
Set-Service FirewallManager -StartupType Manual
```

## 项目结构

```
CFW-Scripts/
├── firewall_manager.py      # 主程序文件
├── firewall_config.json     # 默认配置文件
├── install.sh              # Linux安装脚本
├── install.ps1             # Windows安装脚本
└── README.md               # 项目文档
```

## 日志文件

### Linux
- 服务日志: `journalctl -u firewall-manager`
- 应用日志: `/var/log/firewall/firewall.log`

### Windows
- 服务日志: Windows事件查看器
- 应用日志: `%ProgramData%\FirewallManager\Logs\firewall.log`

## 开发和自定义

### 添加新功能

1. 在 `FirewallManager` 类中添加新方法
2. 在 `main()` 函数中添加对应的命令行选项
3. 更新配置文件格式（如果需要）
4. 添加相应的测试用例

### 扩展防火墙规则

当前规则格式支持以下字段：
- `id`: 规则唯一标识符
- `name`: 规则名称
- `action`: 动作 (ALLOW/DENY)
- `protocol`: 协议 (TCP/UDP/ICMP/ALL)
- `source`: 源地址
- `destination`: 目标地址
- `port`: 端口号
- `enabled`: 是否启用
- `priority`: 优先级
- `description`: 描述

### TODO 功能扩展

以下功能留空，可以根据具体需求实现：

1. **实际防火墙规则操作**
   - iptables规则管理 (Linux)
   - Windows防火墙API调用 (Windows)

2. **网络监控**
   - 实时连接监控
   - 流量统计
   - 异常检测

3. **Web管理界面**
   - 基于Flask/FastAPI的Web UI
   - 实时状态显示
   - 规则可视化管理

4. **API接口**
   - RESTful API
   - WebSocket实时通知
   - 第三方系统集成

5. **高级功能**
   - 地理位置过滤
   - DDoS防护
   - 应用层防火墙

## 卸载

### Linux
```bash
# 停止服务
sudo systemctl stop firewall-manager
sudo systemctl disable firewall-manager

# 删除服务文件
sudo rm /etc/systemd/system/firewall-manager.service
sudo systemctl daemon-reload

# 删除程序文件
sudo rm -rf /opt/firewall
sudo rm -rf /etc/firewall
sudo rm /usr/local/bin/firewall-manager

# 删除服务用户
sudo userdel firewall
```

### Windows
```powershell
# 运行卸载脚本
.\install.ps1 -Uninstall
```

## 故障排除

### 常见问题

1. **权限不足**
   - 确保以管理员/root权限运行
   - 检查文件和目录权限

2. **Python依赖问题**
   - 确保Python 3.6+已安装
   - 检查Python路径配置

3. **服务启动失败**
   - 查看服务日志
   - 检查配置文件格式
   - 确认网络接口名称

4. **防火墙规则不生效**
   - 检查规则语法
   - 确认规则优先级
   - 验证系统防火墙状态

### 获取帮助

如果遇到问题，请提供以下信息：
- 操作系统版本
- Python版本
- 错误日志
- 配置文件内容
- 重现步骤

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

---

**注意**: 这是一个基础框架，具体的防火墙操作功能需要根据实际需求和环境进行实现。
