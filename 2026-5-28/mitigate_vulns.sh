#!/bin/sh

# 漏洞临时缓解脚本
# 适用漏洞：Copy Fail (CVE-2026-31431)、Dirty Frag
# 注意：执行前请评估业务影响，禁用模块可能影响 IPsec 等正常功能

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }
pass()  { printf "${GREEN}[PASS]${NC} %s\n" "$1"; }
fail()  { printf "${RED}[FAIL]${NC} %s\n" "$1"; }

print_kv() {
    key="$1"
    value="$2"
    printf '%s: %s\n' "$key" "$value"
}

confirm() {
    printf "%s [y/N]: " "$1"
    read -r answer </dev/tty
    case "$answer" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "此脚本需要 root 权限运行"
        exit 1
    fi
}

get_primary_ip() {
    primary_ip=""
    if command -v ip >/dev/null 2>&1; then
        primary_ip=$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1 {print $4}' | cut -d/ -f1)
        if [ -n "$primary_ip" ]; then
            printf '%s\n' "$primary_ip"
            return
        fi
    fi
    if command -v hostname >/dev/null 2>&1; then
        primary_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        if [ -n "$primary_ip" ]; then
            printf '%s\n' "$primary_ip"
            return
        fi
    fi
    printf 'unknown'
}

sanitize_for_filename() {
    printf '%s\n' "$1" | sed 's/[:\/ ]/_/g'
}

mitigate_copy_fail() {
    echo "=== 缓解 Copy Fail / CVE-2026-31431 ==="

    algif_loaded="$(lsmod 2>/dev/null | grep -w algif_aead || true)"
    af_alg_usage="$(lsof 2>/dev/null | grep AF_ALG || true)"

    if [ -n "$af_alg_usage" ]; then
        warn "检测到进程正在使用 AF_ALG："
        echo "$af_alg_usage"
        if ! confirm "继续禁用 algif_aead 可能影响上述进程，是否继续？"; then
            info "跳过 algif_aead 禁用"
            return
        fi
    fi

    info "写入 modprobe 禁用配置..."
    echo "install algif_aead /bin/false" >> /etc/modprobe.d/disable-vuln-modules.conf

    if [ -n "$algif_loaded" ]; then
        info "卸载 algif_aead 模块..."
        rmmod algif_aead 2>/dev/null || warn "模块卸载失败，可能正在使用中"
    fi

    info "清理页缓存..."
    sync && echo 3 > /proc/sys/vm/drop_caches

    info "Copy Fail 缓解完成"
}

mitigate_dirty_frag() {
    echo "=== 缓解 Dirty Frag ==="

    esp4_loaded="$(lsmod 2>/dev/null | grep -w esp4 || true)"
    esp6_loaded="$(lsmod 2>/dev/null | grep -w esp6 || true)"
    rxrpc_loaded="$(lsmod 2>/dev/null | grep -w rxrpc || true)"
    xfrm_policy="$(ip xfrm policy list 2>/dev/null || true)"
    xfrm_state="$(ip xfrm state list 2>/dev/null || true)"

    if [ -n "$xfrm_policy" ] || [ -n "$xfrm_state" ]; then
        warn "检测到系统正在使用 IPsec（xfrm policy/state 存在）"
        warn "禁用 esp4/esp6 可能导致 IPsec 连接中断"
        if ! confirm "是否继续禁用 esp4、esp6、rxrpc？"; then
            info "跳过 Dirty Frag 缓解"
            return
        fi
    fi

    info "写入 modprobe 禁用配置..."
    cat >> /etc/modprobe.d/disable-vuln-modules.conf <<'EOF'
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF

    for mod in esp4 esp6 rxrpc; do
        loaded="$(lsmod 2>/dev/null | grep -w "$mod" || true)"
        if [ -n "$loaded" ]; then
            info "卸载 $mod 模块..."
            rmmod "$mod" 2>/dev/null || warn "$mod 卸载失败，可能正在使用中"
        fi
    done

    info "Dirty Frag 缓解完成"
}

verify_mitigation() {
    echo ""
    echo "=== 验证缓解措施 ==="

    all_pass=true

    # 1. 验证配置文件存在
    conf_file="/etc/modprobe.d/disable-vuln-modules.conf"
    if [ -f "$conf_file" ]; then
        pass "配置文件已写入: $conf_file"
        echo "--- 配置文件内容 ---"
        cat "$conf_file"
        echo "--- 配置文件结束 ---"
    else
        fail "配置文件不存在: $conf_file"
        all_pass=false
    fi

    # 2. 卸载残留模块
    for mod in algif_aead esp4 esp6 rxrpc; do
        loaded="$(lsmod 2>/dev/null | grep -w "$mod" || true)"
        if [ -n "$loaded" ]; then
            warn "模块 $mod 仍已加载，尝试卸载..."
            rmmod "$mod" 2>/dev/null && info "$mod 卸载成功" || warn "$mod 卸载失败"
        fi
    done

    # 3. 尝试加载模块，应该失败
    echo ""
    info "尝试加载已禁用的模块（预期失败）..."
    for mod in algif_aead esp4 esp6 rxrpc; do
        if modprobe "$mod" 2>/dev/null; then
            fail "模块 $mod 仍可加载，禁用未生效"
            all_pass=false
        else
            pass "模块 $mod 已被封锁，无法加载"
        fi
    done

    # 4. 最终结论
    echo ""
    if [ "$all_pass" = true ]; then
        pass "所有模块已封锁完毕，缓解措施生效"
    else
        fail "部分模块封锁未生效，请检查配置"
    fi
}

rollback() {
    echo "=== 回滚所有缓解措施 ==="
    conf_file="/etc/modprobe.d/disable-vuln-modules.conf"
    if [ -f "$conf_file" ]; then
        rm -f "$conf_file"
        info "已删除 $conf_file"
    else
        info "未发现缓解配置，无需回滚"
    fi
}

show_usage() {
    echo "用法: $0 <action>"
    echo ""
    echo "Action:"
    echo "  mitigate-all    缓解所有漏洞并验证"
    echo "  verify          仅验证缓解措施是否生效"
    echo "  rollback        回滚所有缓解"
    echo ""
    echo "示例:"
    echo "  $0 mitigate-all   # 缓解 + 验证"
    echo "  $0 verify         # 仅验证"
    echo "  $0 rollback       # 回滚"
}

# 初始化
PRIMARY_IP="$(get_primary_ip)"
SAFE_IP="$(sanitize_for_filename "$PRIMARY_IP")"
TIME_TAG="$(date '+%Y%m%d_%H%M%S' 2>/dev/null)"
[ -n "$TIME_TAG" ] || TIME_TAG="unknown_time"
LOG_FILE="./漏洞修复_${SAFE_IP}_${TIME_TAG}.log"

check_root

# 所有输出同时写入 stdout 和日志文件
{
    echo "漏洞修复报告"
    echo "generated_at: $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    print_kv host_name "$(hostname 2>/dev/null)"
    print_kv primary_ip "$PRIMARY_IP"
    print_kv log_file "$LOG_FILE"
    echo

    case "${1:-}" in
        mitigate-all)
            mitigate_copy_fail
            echo
            mitigate_dirty_frag
            verify_mitigation
            ;;
        verify)
            verify_mitigation
            ;;
        rollback)
            rollback
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac

    echo ""
    info "日志已保存到: $LOG_FILE"
} 2>&1 | tee "$LOG_FILE"
