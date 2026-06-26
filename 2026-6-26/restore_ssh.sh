#!/bin/bash

# SSH 配置恢复脚本
# 用途：恢复 SSH 允许 root 登录并重启服务
# 日期：2026-06-26

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[错误]${NC} 请以 root 权限运行本脚本"
    exit 1
fi

echo "================================================================================"
echo "                    SSH 配置恢复脚本"
echo "================================================================================"
echo ""

# 1. 备份当前配置
echo -e "${YELLOW}[1/4]${NC} 备份当前 SSH 配置..."
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)
    echo -e "${GREEN}[成功]${NC} 已备份到 /etc/ssh/sshd_config.bak.*"
else
    echo -e "${RED}[错误]${NC} /etc/ssh/sshd_config 不存在"
    exit 1
fi

# 2. 恢复 PermitRootLogin 为 yes
echo -e "${YELLOW}[2/4]${NC} 设置 PermitRootLogin 为 yes..."
if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
else
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
fi
echo -e "${GREEN}[成功]${NC} PermitRootLogin 已设置为 yes"

# 3. 检查配置语法
echo -e "${YELLOW}[3/4]${NC} 检查 SSH 配置语法..."
if sshd -t 2>/dev/null; then
    echo -e "${GREEN}[成功]${NC} 配置语法正确"
else
    echo -e "${RED}[错误]${NC} 配置语法错误，正在恢复备份..."
    latest_bak=$(ls -t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -1)
    if [ -n "$latest_bak" ]; then
        cp "$latest_bak" /etc/ssh/sshd_config
        echo -e "${YELLOW}[已恢复]${NC} 从备份恢复配置"
    fi
    exit 1
fi

# 4. 重启 SSH 服务
echo -e "${YELLOW}[4/4]${NC} 重启 SSH 服务..."
systemctl restart sshd
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[成功]${NC} SSH 服务已重启"
else
    echo -e "${RED}[错误]${NC} SSH 服务重启失败"
    exit 1
fi

# 获取服务器IP
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "================================================================================"
echo -e "${GREEN}  SSH 配置恢复完成！${NC}"
echo "================================================================================"
echo ""
echo "  服务器IP: ${SERVER_IP}"
echo "  SSH 端口: 22"
echo "  root 登录: 已启用"
echo ""
echo "  请尝试 SSH 登录:"
echo "  ssh root@${SERVER_IP}"
echo ""
echo "================================================================================"
