#!/bin/sh

# 漏洞临时缓解脚本
# 适用漏洞：Copy Fail (CVE-2026-31431)、Dirty Frag
# 注意：执行前请评估业务影响，禁用模块可能影响 IPsec 等正常功能

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }

confirm() {
    printf "%s [y/N]: " "$1"
    read -r answer
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
    echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif-aead.conf

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
    cat > /etc/modprobe.d/dirtyfrag.conf <<'EOF'
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

rollback_copy_fail() {
    echo "=== 回滚 Copy Fail 缓解 ==="
    if [ -f /etc/modprobe.d/disable-algif-aead.conf ]; then
        rm -f /etc/modprobe.d/disable-algif-aead.conf
        info "已删除 /etc/modprobe.d/disable-algif-aead.conf"
    else
        info "未发现 Copy Fail 缓解配置，无需回滚"
    fi
}

rollback_dirty_frag() {
    echo "=== 回滚 Dirty Frag 缓解 ==="
    if [ -f /etc/modprobe.d/dirtyfrag.conf ]; then
        rm -f /etc/modprobe.d/dirtyfrag.conf
        info "已删除 /etc/modprobe.d/dirtyfrag.conf"
    else
        info "未发现 Dirty Frag 缓解配置，无需回滚"
    fi
}

show_usage() {
    echo "用法: $0 <action>"
    echo ""
    echo "Action:"
    echo "  mitigate-copy-fail    缓解 Copy Fail (CVE-2026-31431)"
    echo "  mitigate-dirty-frag   缓解 Dirty Frag"
    echo "  mitigate-all          缓解所有漏洞"
    echo "  rollback-copy-fail    回滚 Copy Fail 缓解"
    echo "  rollback-dirty-frag   回滚 Dirty Frag 缓解"
    echo "  rollback-all          回滚所有缓解"
    echo ""
    echo "示例:"
    echo "  $0 mitigate-all       # 缓解所有漏洞"
    echo "  $0 rollback-all       # 回滚所有缓解"
}

check_root

case "${1:-}" in
    mitigate-copy-fail)  mitigate_copy_fail ;;
    mitigate-dirty-frag) mitigate_dirty_frag ;;
    mitigate-all)
        mitigate_copy_fail
        echo
        mitigate_dirty_frag
        ;;
    rollback-copy-fail)  rollback_copy_fail ;;
    rollback-dirty-frag) rollback_dirty_frag ;;
    rollback-all)
        rollback_copy_fail
        echo
        rollback_dirty_frag
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
