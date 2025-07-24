#!/bin/bash

# 防火墙部署脚本 - Linux系统
# 用于在Linux防火墙设备上部署和配置防火墙脚本

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置变量
INSTALL_DIR="/opt/cfw-scripts"
SERVICE_NAME="cfw-firewall"
USER="cfw-user"
CONFIG_DIR="/etc/cfw-scripts"
LOG_DIR="/var/log/cfw-scripts"

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_blue() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 检查操作系统
check_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "无法检测操作系统版本"
        exit 1
    fi
    
    . /etc/os-release
    log_info "检测到操作系统: $NAME $VERSION"
    
    case $ID in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel|fedora)
            PACKAGE_MANAGER="yum"
            ;;
        *)
            log_warn "未完全测试的操作系统: $ID"
            ;;
    esac
}

# 安装系统依赖
install_system_deps() {
    log_info "安装系统依赖包..."
    
    case $PACKAGE_MANAGER in
        apt)
            apt update
            apt install -y python3 python3-pip python3-dev gcc \
                          libnetfilterqueue-dev iptables-dev libpcap-dev \
                          systemd git curl wget
            ;;
        yum)
            yum update -y
            yum install -y python3 python3-pip python3-devel gcc \
                          libnetfilter_queue-devel iptables-devel libpcap-devel \
                          systemd git curl wget
            ;;
        *)
            log_error "不支持的包管理器: $PACKAGE_MANAGER"
            exit 1
            ;;
    esac
    
    log_info "系统依赖包安装完成"
}

# 创建用户和目录
create_user_and_dirs() {
    log_info "创建用户和目录..."
    
    # 创建用户
    if ! id "$USER" &>/dev/null; then
        useradd -r -s /bin/false -d $INSTALL_DIR $USER
        log_info "创建用户: $USER"
    else
        log_info "用户已存在: $USER"
    fi
    
    # 创建目录
    mkdir -p $INSTALL_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $LOG_DIR
    mkdir -p $INSTALL_DIR/ssl_certs
    mkdir -p $INSTALL_DIR/data
    
    log_info "目录创建完成"
}

# 复制应用文件
copy_application() {
    log_info "复制应用文件..."
    
    # 复制主要文件
    cp -r core/ $INSTALL_DIR/
    cp -r processors/ $INSTALL_DIR/
    cp -r utils/ $INSTALL_DIR/
    cp -r tests/ $INSTALL_DIR/
    cp main.py $INSTALL_DIR/
    cp requirements.txt $INSTALL_DIR/
    cp README.md $INSTALL_DIR/
    
    # 复制配置文件
    if [ -f config/firewall_config.json ]; then
        cp config/firewall_config.json $CONFIG_DIR/
    fi
    
    log_info "应用文件复制完成"
}

# 安装Python依赖
install_python_deps() {
    log_info "安装Python依赖..."
    
    cd $INSTALL_DIR
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
    
    log_info "Python依赖安装完成"
}

# 设置权限
set_permissions() {
    log_info "设置文件权限..."
    
    chown -R $USER:$USER $INSTALL_DIR
    chown -R $USER:$USER $CONFIG_DIR
    chown -R $USER:$USER $LOG_DIR
    
    # 设置执行权限
    chmod +x $INSTALL_DIR/main.py
    chmod +x $INSTALL_DIR/utils/*.py
    
    # 设置配置文件权限
    chmod 640 $CONFIG_DIR/*.json 2>/dev/null || true
    
    log_info "权限设置完成"
}

# 创建systemd服务
create_systemd_service() {
    log_info "创建systemd服务..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=CFW Firewall Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/main.py start --daemon
ExecStop=/usr/bin/python3 $INSTALL_DIR/main.py stop
ExecReload=/usr/bin/python3 $INSTALL_DIR/main.py reload
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $INSTALL_DIR/ssl_certs $INSTALL_DIR/data

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    log_info "systemd服务创建完成"
}

# 配置iptables规则
configure_iptables() {
    log_info "配置iptables规则..."
    
    # 备份现有规则
    iptables-save > /etc/iptables.rules.backup.$(date +%Y%m%d_%H%M%S)
    
    # 创建自定义链
    iptables -t mangle -N CFW_QUEUE 2>/dev/null || true
    
    # 添加流量重定向规则（示例）
    # 注意：这些规则需要根据实际网络环境调整
    iptables -t mangle -A FORWARD -j CFW_QUEUE
    iptables -t mangle -A CFW_QUEUE -j NFQUEUE --queue-num 0
    
    # 保存规则
    case $PACKAGE_MANAGER in
        apt)
            iptables-save > /etc/iptables/rules.v4
            ;;
        yum)
            service iptables save
            ;;
    esac
    
    log_warn "iptables规则已配置，请根据实际网络环境调整"
}

# 生成SSL证书
generate_ssl_certs() {
    log_info "生成SSL证书..."
    
    cd $INSTALL_DIR
    python3 -c "
from core.ssl_interceptor import SSLInterceptor
import json

config = {
    'ssl': {
        'ca_cert_path': './ssl_certs/ca.crt',
        'ca_key_path': './ssl_certs/ca.key',
        'cert_duration_days': 365
    }
}

interceptor = SSLInterceptor(config)
interceptor.start()
print('SSL证书生成完成')
"
    
    log_info "SSL证书生成完成"
}

# 创建管理脚本
create_management_scripts() {
    log_info "创建管理脚本..."
    
    # 创建管理脚本
    cat > /usr/local/bin/cfw-firewall << 'EOF'
#!/bin/bash

SERVICE_NAME="cfw-firewall"
INSTALL_DIR="/opt/cfw-scripts"

case "$1" in
    start)
        systemctl start $SERVICE_NAME
        ;;
    stop)
        systemctl stop $SERVICE_NAME
        ;;
    restart)
        systemctl restart $SERVICE_NAME
        ;;
    status)
        systemctl status $SERVICE_NAME
        ;;
    logs)
        journalctl -u $SERVICE_NAME -f
        ;;
    config)
        vim /etc/cfw-scripts/firewall_config.json
        ;;
    test)
        cd $INSTALL_DIR && python3 -m tests.comprehensive_test
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status|logs|config|test}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/cfw-firewall
    
    log_info "管理脚本创建完成"
}

# 运行测试
run_tests() {
    log_info "运行系统测试..."
    
    cd $INSTALL_DIR
    
    # 测试基本功能
    log_blue "测试模块导入..."
    python3 -c "
try:
    from core import FirewallManager
    from processors import BaseProcessor
    print('✓ 核心模块导入成功')
except Exception as e:
    print(f'✗ 模块导入失败: {e}')
    exit(1)
"
    
    # 运行配置测试
    log_blue "测试配置文件..."
    python3 main.py --test-config
    
    log_info "系统测试完成"
}

# 显示部署后信息
show_post_deploy_info() {
    log_info "部署完成！"
    
    echo
    echo "======================================================"
    echo "              CFW 防火墙系统部署完成"
    echo "======================================================"
    echo
    echo "安装目录: $INSTALL_DIR"
    echo "配置目录: $CONFIG_DIR"
    echo "日志目录: $LOG_DIR"
    echo "服务名称: $SERVICE_NAME"
    echo
    echo "常用命令:"
    echo "  启动服务: cfw-firewall start"
    echo "  停止服务: cfw-firewall stop"
    echo "  查看状态: cfw-firewall status"
    echo "  查看日志: cfw-firewall logs"
    echo "  编辑配置: cfw-firewall config"
    echo "  运行测试: cfw-firewall test"
    echo
    echo "或使用systemctl:"
    echo "  systemctl start $SERVICE_NAME"
    echo "  systemctl status $SERVICE_NAME"
    echo "  systemctl logs -u $SERVICE_NAME"
    echo
    echo "配置文件:"
    echo "  $CONFIG_DIR/firewall_config.json"
    echo
    echo "CA证书位置:"
    echo "  $INSTALL_DIR/ssl_certs/ca.crt"
    echo
    echo "注意事项:"
    echo "  1. 请根据网络环境调整iptables规则"
    echo "  2. SSL拦截需要客户端安装CA证书"
    echo "  3. 某些功能需要管理员权限"
    echo "  4. 建议在测试环境中先验证功能"
    echo
    echo "======================================================"
}

# 主函数
main() {
    echo "======================================================"
    echo "           CFW 防火墙系统自动部署脚本"
    echo "======================================================"
    echo
    
    check_root
    check_os
    
    log_info "开始部署CFW防火墙系统..."
    
    install_system_deps
    create_user_and_dirs
    copy_application
    install_python_deps
    set_permissions
    create_systemd_service
    
    # 询问是否配置iptables
    echo
    read -p "是否配置iptables规则? (y/N): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        configure_iptables
    else
        log_warn "跳过iptables配置，请手动配置网络规则"
    fi
    
    generate_ssl_certs
    create_management_scripts
    run_tests
    
    show_post_deploy_info
    
    log_info "部署完成！请使用 'cfw-firewall start' 启动服务"
}

# 执行主函数
main "$@"
