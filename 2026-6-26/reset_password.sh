#!/bin/bash

# 紧急密码重置脚本
# 用途：重置 root 密码并修复认证配置
# 日期：2026-06-26

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 密码长度
PASSWORD_LENGTH=12

# 生成符合要求的随机密码
generate_password() {
    local lower="abcdefghijklmnopqrstuvwxyz"
    local upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local digits="0123456789"
    local special='`~!@#$%^&*()-_=+\|[{]};:'"'"'",<.>/?'

    # 确保每种字符至少一个
    local password=""
    password+="${lower:RANDOM%${#lower}:1}"
    password+="${upper:RANDOM%${#upper}:1}"
    password+="${digits:RANDOM%${#digits}:1}"
    password+="${special:RANDOM%${#special}:1}"

    # 填充剩余长度
    local all_chars="${lower}${upper}${digits}${special}"
    for i in $(seq 1 $((PASSWORD_LENGTH - 4))); do
        password+="${all_chars:RANDOM%${#all_chars}:1}"
    done

    # 打乱密码顺序
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[错误]${NC} 请以 root 权限运行本脚本"
    exit 1
fi

echo "================================================================================"
echo "                    紧急密码重置脚本"
echo "================================================================================"
echo ""

# 生成随机密码
NEW_PASSWORD=$(generate_password)

# 1. 重置密码
echo -e "${YELLOW}[1/6]${NC} 重置 root 密码..."
echo "root:${NEW_PASSWORD}" | chpasswd
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[成功]${NC} 密码已重置"
else
    echo -e "${RED}[失败]${NC} 密码重置失败"
    exit 1
fi

# 2. 禁用 faillock
echo -e "${YELLOW}[2/6]${NC} 禁用登录锁定..."
cat > /etc/security/faillock.conf << 'EOF'
# 禁用登录失败锁定
deny = 0
EOF
echo -e "${GREEN}[成功]${NC} faillock 已禁用"

# 3. 清除 PAM 中的 faillock
echo -e "${YELLOW}[3/6]${NC} 清除 PAM 配置中的 faillock..."
sed -i '/pam_faillock.so/d' /etc/pam.d/system-auth
sed -i '/pam_faillock.so/d' /etc/pam.d/password-auth
echo -e "${GREEN}[成功]${NC} PAM 配置已修复"

# 4. 恢复 SSH 允许 root 登录
echo -e "${YELLOW}[4/6]${NC} 恢复 SSH root 登录..."
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    # 确保有这行配置
    grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    echo -e "${GREEN}[成功]${NC} SSH 已允许 root 登录"
else
    echo -e "${YELLOW}[警告]${NC} sshd_config 文件不存在"
fi

# 5. 重置密码策略
echo -e "${YELLOW}[5/6]${NC} 重置密码策略..."
chage --maxdays 99999 root
chage --mindays 0 root
echo -e "${GREEN}[成功]${NC} 密码策略已重置"

# 6. 重启 sshd
echo -e "${YELLOW}[6/6]${NC} 重启 SSH 服务..."
systemctl restart sshd
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[成功]${NC} SSH 服务已重启"
else
    echo -e "${RED}[失败]${NC} SSH 服务重启失败"
fi

echo ""
echo "================================================================================"
echo -e "${GREEN}  修复完成！${NC}"
echo "================================================================================"
echo ""

# 获取服务器IP
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "  服务器IP: ${SERVER_IP}"
echo "  root 密码: ${NEW_PASSWORD}"
echo ""
echo "  请尝试 SSH 登录:"
echo "  ssh root@${SERVER_IP}"
echo ""
echo "================================================================================"
