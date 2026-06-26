#!/bin/bash

# rsyslog 日志服务器部署脚本
# 用途：部署集中日志服务器，接收多台主机的日志
# 日期：2026-06-26

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认配置
DEFAULT_PORT="514"
DEFAULT_PROTOCOL="tcp"  # tcp 或 udp
DEFAULT_LOG_DIR="/var/log/remote"

# ============================================================================
# 显示帮助
# ============================================================================
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  server    - 部署日志服务器（接收端）"
    echo "  client    - 配置当前主机为日志客户端（发送端）"
    echo "  status    - 检查 rsyslog 服务状态"
    echo "  test      - 发送测试日志"
    echo "  help      - 显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  sudo $0 server      # 在日志服务器上执行"
    echo "  sudo $0 client      # 在需要发送日志的主机上执行"
}

# ============================================================================
# 检查 root 权限
# ============================================================================
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[错误]${NC} 请以 root 权限运行本脚本"
        exit 1
    fi
}

# ============================================================================
# 检测系统类型
# ============================================================================
detect_os() {
    if [ -f /etc/redhat-release ]; then
        OS="centos"
        PKG_MANAGER="yum"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        PKG_MANAGER="apt"
    else
        OS="unknown"
        PKG_MANAGER="unknown"
    fi
    echo -e "${BLUE}[信息]${NC} 检测到系统类型: $OS"
}

# ============================================================================
# 安装 rsyslog
# ============================================================================
install_rsyslog() {
    echo -e "${BLUE}[信息]${NC} 检查 rsyslog 安装状态..."

    if command -v rsyslogd &>/dev/null; then
        echo -e "${GREEN}[已安装]${NC} rsyslog 已存在"
        return 0
    fi

    echo -e "${YELLOW}[安装]${NC} 正在安装 rsyslog..."

    case $PKG_MANAGER in
        yum)
            yum install -y rsyslog
            ;;
        apt)
            apt-get update && apt-get install -y rsyslog
            ;;
        *)
            echo -e "${RED}[错误]${NC} 不支持的系统类型，请手动安装 rsyslog"
            exit 1
            ;;
    esac

    if command -v rsyslogd &>/dev/null; then
        echo -e "${GREEN}[成功]${NC} rsyslog 安装成功"
    else
        echo -e "${RED}[失败]${NC} rsyslog 安装失败"
        exit 1
    fi
}

# ============================================================================
# 配置日志服务器（接收端）
# ============================================================================
setup_server() {
    echo ""
    echo "================================================================================"
    echo "                    配置日志服务器（接收端）"
    echo "================================================================================"
    echo ""

    # 获取配置参数
    read -r -p "请输入监听端口 [默认: $DEFAULT_PORT]: " PORT
    PORT=${PORT:-$DEFAULT_PORT}

    echo "请选择协议:"
    echo "  1) TCP（推荐，可靠传输）"
    echo "  2) UDP（简单，可能丢包）"
    read -r -p "请选择 [默认: 1]: " PROTO_CHOICE

    case $PROTO_CHOICE in
        2)
            PROTOCOL="udp"
            ;;
        *)
            PROTOCOL="tcp"
            ;;
    esac

    read -r -p "请输入日志存储目录 [默认: $DEFAULT_LOG_DIR]: " LOG_DIR
    LOG_DIR=${LOG_DIR:-$DEFAULT_LOG_DIR}

    echo ""
    echo -e "${BLUE}[配置]${NC} 监听端口: $PORT"
    echo -e "${BLUE}[配置]${NC} 协议类型: $PROTOCOL"
    echo -e "${BLUE}[配置]${NC} 存储目录: $LOG_DIR"
    echo ""

    read -r -p "确认配置？(y/n): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo -e "${YELLOW}[取消]${NC} 操作已取消"
        exit 0
    fi

    # 备份原配置
    echo -e "${BLUE}[备份]${NC} 备份原配置文件..."
    cp /etc/rsyslog.conf /etc/rsyslog.conf.bak.$(date +%Y%m%d_%H%M%S)

    # 创建日志存储目录
    echo -e "${BLUE}[创建]${NC} 创建日志存储目录..."
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"

    # 配置 rsyslog
    echo -e "${BLUE}[配置]${NC} 配置 rsyslog 服务..."

    cat > /etc/rsyslog.d/remote-server.conf << EOF
# ======================================================
# 远程日志服务器配置
# 生成时间：$(date '+%Y-%m-%d %H:%M:%S')
# ======================================================

# 模块加载
EOF

    if [ "$PROTOCOL" = "tcp" ]; then
        cat >> /etc/rsyslog.d/remote-server.conf << EOF
\$ModLoad imtcp
\$InputTCPServerRun $PORT
EOF
    else
        cat >> /etc/rsyslog.d/remote-server.conf << EOF
\$ModLoad imudp
\$UDPServerRun $PORT
EOF
    fi

    cat >> /etc/rsyslog.d/remote-server.conf << EOF

# 日志存储模板
\$template RemoteHost,"${LOG_DIR}/%HOSTNAME%/%PROGRAMNAME%.log"
\$template RemoteDaily,"${LOG_DIR}/%HOSTNAME%/%\$YEAR%-%\$MONTH%-%\$DAY%.log"

# 按主机名分类存储
*.* ?RemoteHost

# 也可以按日期存储（取消注释启用）
# *.* ?RemoteDaily

# 停止处理（防止重复记录）
& stop
EOF

    # 配置防火墙
    echo -e "${BLUE}[防火墙]${NC} 配置防火墙规则..."
    configure_firewall "$PORT" "$PROTOCOL"

    # 重启服务
    echo -e "${BLUE}[重启]${NC} 重启 rsyslog 服务..."
    systemctl restart rsyslog
    systemctl enable rsyslog

    # 检查状态
    if systemctl is-active rsyslog &>/dev/null; then
        echo ""
        echo -e "${GREEN}[成功]${NC} 日志服务器配置完成！"
        echo ""
        echo "================================================================================"
        echo "  服务器信息"
        echo "================================================================================"
        echo "  监听地址: 0.0.0.0:$PORT"
        echo "  协议类型: $PROTOCOL"
        echo "  日志目录: $LOG_DIR"
        echo ""
        echo "  客户端配置示例（在客户端执行）："
        echo "  sudo $0 client"
        echo "================================================================================"
    else
        echo -e "${RED}[错误]${NC} rsyslog 服务启动失败，请检查配置"
        journalctl -u rsyslog --no-pager -n 20
    fi
}

# ============================================================================
# 配置防火墙
# ============================================================================
configure_firewall() {
    local port="$1"
    local protocol="$2"

    if command -v firewall-cmd &>/dev/null; then
        # firewalld
        firewall-cmd --permanent --add-port="${port}/${protocol}" 2>/dev/null
        firewall-cmd --reload 2>/dev/null
        echo -e "${GREEN}[防火墙]${NC} 已放行端口 ${port}/${protocol}"
    elif command -v ufw &>/dev/null; then
        # ufw
        ufw allow "${port}/${protocol}" 2>/dev/null
        echo -e "${GREEN}[防火墙]${NC} 已放行端口 ${port}/${protocol}"
    elif command -v iptables &>/dev/null; then
        # iptables
        iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT 2>/dev/null
        echo -e "${GREEN}[防火墙]${NC} 已放行端口 ${port}/${protocol}"
        echo -e "${YELLOW}[提示]${NC} iptables 规则重启后失效，建议保存: iptables-save > /etc/sysconfig/iptables"
    else
        echo -e "${YELLOW}[警告]${NC} 未检测到防火墙工具，请手动放行端口 ${port}/${protocol}"
    fi
}

# ============================================================================
# 配置日志客户端（发送端）
# ============================================================================
setup_client() {
    echo ""
    echo "================================================================================"
    echo "                    配置日志客户端（发送端）"
    echo "================================================================================"
    echo ""

    # 获取服务器地址
    read -r -p "请输入日志服务器地址（IP或域名）: " SERVER_IP
    if [ -z "$SERVER_IP" ]; then
        echo -e "${RED}[错误]${NC} 服务器地址不能为空"
        exit 1
    fi

    read -r -p "请输入日志服务器端口 [默认: $DEFAULT_PORT]: " PORT
    PORT=${PORT:-$DEFAULT_PORT}

    echo "请选择协议:"
    echo "  1) TCP（推荐）"
    echo "  2) UDP"
    read -r -p "请选择 [默认: 1]: " PROTO_CHOICE

    case $PROTO_CHOICE in
        2)
            PROTOCOL="udp"
            PREFIX="@"
            ;;
        *)
            PROTOCOL="tcp"
            PREFIX="@@"
            ;;
    esac

    echo ""
    echo -e "${BLUE}[配置]${NC} 服务器地址: $SERVER_IP"
    echo -e "${BLUE}[配置]${NC} 服务器端口: $PORT"
    echo -e "${BLUE}[配置]${NC} 协议类型: $PROTOCOL"
    echo ""

    read -r -p "确认配置？(y/n): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo -e "${YELLOW}[取消]${NC} 操作已取消"
        exit 0
    fi

    # 备份原配置
    echo -e "${BLUE}[备份]${NC} 备份原配置文件..."
    cp /etc/rsyslog.conf /etc/rsyslog.conf.bak.$(date +%Y%m%d_%H%M%S)

    # 检查是否已有远程日志配置
    if grep -q "^*.*@@\|^*.*@@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
        echo -e "${YELLOW}[警告]${NC} 检测到已有远程日志配置："
        grep "^*.*@@\|^*.*@@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null
        echo ""
        read -r -p "是否覆盖？(y/n): " overwrite
        if [ "$overwrite" != "y" ] && [ "$overwrite" != "Y" ]; then
            echo -e "${YELLOW}[取消]${NC} 操作已取消"
            exit 0
        fi
        # 删除旧配置
        sed -i '/^*.*@@/d; /^*.*@@/d' /etc/rsyslog.conf 2>/dev/null
        rm -f /etc/rsyslog.d/remote-client.conf 2>/dev/null
    fi

    # 配置客户端
    echo -e "${BLUE}[配置]${NC} 配置客户端发送日志..."

    cat > /etc/rsyslog.d/remote-client.conf << EOF
# ======================================================
# 远程日志客户端配置
# 生成时间：$(date '+%Y-%m-%d %H:%M:%S')
# 服务器：${SERVER_IP}:${PORT}
# 协议：${PROTOCOL}
# ======================================================

# 发送所有日志到远程服务器
*.* ${PREFIX}${SERVER_IP}:${PORT}

# 停止处理（如果只需要远程日志，取消注释下一行）
# & stop
EOF

    # 重启服务
    echo -e "${BLUE}[重启]${NC} 重启 rsyslog 服务..."
    systemctl restart rsyslog

    if systemctl is-active rsyslog &>/dev/null; then
        echo ""
        echo -e "${GREEN}[成功]${NC} 客户端配置完成！"
        echo ""
        echo "================================================================================"
        echo "  配置信息"
        echo "================================================================================"
        echo "  日志服务器: ${SERVER_IP}:${PORT}"
        echo "  协议类型: ${PROTOCOL}"
        echo "  配置文件: /etc/rsyslog.d/remote-client.conf"
        echo ""
        echo "  发送测试日志："
        echo "  logger -p local0.info '测试日志消息'"
        echo "================================================================================"
    else
        echo -e "${RED}[错误]${NC} rsyslog 服务启动失败，请检查配置"
        journalctl -u rsyslog --no-pager -n 20
    fi
}

# ============================================================================
# 检查服务状态
# ============================================================================
check_status() {
    echo ""
    echo "================================================================================"
    echo "                    rsyslog 服务状态"
    echo "================================================================================"
    echo ""

    # 服务状态
    echo -e "${BLUE}[服务状态]${NC}"
    systemctl status rsyslog --no-pager | head -5
    echo ""

    # 监听端口
    echo -e "${BLUE}[监听端口]${NC}"
    ss -tlnp | grep rsyslog || echo "  未检测到监听端口"
    ss -ulnp | grep rsyslog || echo "  未检测到 UDP 监听"
    echo ""

    # 配置文件
    echo -e "${BLUE}[远程日志配置]${NC}"
    if [ -f /etc/rsyslog.d/remote-server.conf ]; then
        echo "  服务器配置: /etc/rsyslog.d/remote-server.conf"
        grep -v "^#\|^$" /etc/rsyslog.d/remote-server.conf | head -10
    fi
    if [ -f /etc/rsyslog.d/remote-client.conf ]; then
        echo "  客户端配置: /etc/rsyslog.d/remote-client.conf"
        grep -v "^#\|^$" /etc/rsyslog.d/remote-client.conf | head -10
    fi
    echo ""

    # 日志目录
    echo -e "${BLUE}[远程日志目录]${NC}"
    if [ -d /var/log/remote ]; then
        ls -la /var/log/remote/ | head -10
        echo ""
        echo "  磁盘使用: $(du -sh /var/log/remote/ 2>/dev/null | awk '{print $1}')"
    else
        echo "  目录不存在: /var/log/remote"
    fi
    echo ""
}

# ============================================================================
# 发送测试日志
# ============================================================================
test_log() {
    echo ""
    echo "================================================================================"
    echo "                    发送测试日志"
    echo "================================================================================"
    echo ""

    # 读取客户端配置
    local server_ip=""
    local port=""

    if [ -f /etc/rsyslog.d/remote-client.conf ]; then
        server_ip=$(grep "^*.*@\|@@\|@@" /etc/rsyslog.d/remote-client.conf | awk -F'[@:]' '{print $(NF-1)}' | head -1)
        port=$(grep "^*.*@\|@@\|@@" /etc/rsyslog.d/remote-client.conf | awk -F'[@:]' '{print $NF}' | head -1)
    fi

    if [ -z "$server_ip" ]; then
        echo -e "${YELLOW}[警告]${NC} 未检测到客户端配置"
        read -r -p "请输入日志服务器地址: " server_ip
        read -r -p "请输入端口 [默认: 514]: " port
        port=${port:-514}
    fi

    echo -e "${BLUE}[目标]${NC} ${server_ip}:${port}"
    echo ""

    # 发送测试日志
    logger -p local0.info "=== 测试日志消息 $(date) ==="
    logger -p local0.info "主机名: $(hostname)"
    logger -p local0.info "IP地址: $(hostname -I | awk '{print $1}')"

    echo -e "${GREEN}[已发送]${NC} 测试日志已发送"
    echo ""
    echo "请在日志服务器上检查："
    echo "  tail -f /var/log/remote/$(hostname)/*.log"
    echo ""
    echo "或使用以下命令测试连接："
    if [ "$port" = "514" ]; then
        echo "  nc -zv $server_ip 514"
    else
        echo "  nc -zv $server_ip $port"
    fi
}

# ============================================================================
# 主程序
# ============================================================================
main() {
    check_root
    detect_os
    install_rsyslog

    case "${1:-help}" in
        server)
            setup_server
            ;;
        client)
            setup_client
            ;;
        status)
            check_status
            ;;
        test)
            test_log
            ;;
        help|*)
            show_help
            ;;
    esac
}

main "$@"
