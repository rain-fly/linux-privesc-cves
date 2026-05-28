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

# 幂等写入 modprobe 配置（避免重复追加）
append_modprobe_conf() {
    entry="$1"
    conf="/etc/modprobe.d/disable-vuln-modules.conf"
    if grep -qxF "$entry" "$conf" 2>/dev/null; then
        info "modprobe 规则已存在，跳过写入: $entry"
    else
        echo "$entry" >> "$conf"
        info "已写入 modprobe 规则: $entry"
    fi
}

# 检查模块是否为 builtin
is_builtin() {
    mod="$1"
    grep -q "${mod}" /lib/modules/$(uname -r)/modules.builtin 2>/dev/null
}

# 应用 initcall_blacklist（支持 grubby / BLS / 传统 grub2-mkconfig）
# 返回值：0=已生效  2=已写入需重启  3=写入失败
apply_initcall_blacklist() {
    target_arg="initcall_blacklist=algif_aead_init"

    # 已在当前内核生效
    if grep -q "$target_arg" /proc/cmdline 2>/dev/null; then
        pass "initcall_blacklist 已在内核参数中生效"
        return 0
    fi

    # 优先使用 grubby（Anolis/RHEL/CentOS BLS 模式推荐）
    if command -v grubby >/dev/null 2>&1; then
        if grubby --info=DEFAULT 2>/dev/null | grep -q "$target_arg"; then
            warn "grubby 参数已写入，尚未重启生效"
            return 2
        fi
        info "通过 grubby 写入 initcall_blacklist 到默认内核..."
        if grubby --update-kernel=DEFAULT --args="$target_arg"; then
            info "grubby 写入成功，验证："
            grubby --info=DEFAULT 2>/dev/null | grep "^args"
            warn "需要重启后生效"
            return 2
        else
            warn "grubby 写入失败，尝试降级方案..."
        fi
    fi

    # 降级：检查当前内核 BLS .conf 是否使用 $kernelopts 变量
    kernel_ver="$(uname -r)"
    bls_conf="$(ls /boot/loader/entries/*${kernel_ver}*.conf 2>/dev/null | head -1)"
    if [ -n "$bls_conf" ]; then
        if grep -q '\$kernelopts' "$bls_conf"; then
            # 走 kernelopts 变量，grub2-mkconfig 有效
            info "检测到 BLS kernelopts 模式，写入 /etc/default/grub..."
            if ! grep -q "$target_arg" /etc/default/grub 2>/dev/null; then
                sed -i "s|\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"|\1 ${target_arg}\"|" /etc/default/grub
            fi
            grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null \
                || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null \
                || { warn "grub 配置更新失败，请手动执行 grub2-mkconfig"; return 3; }
            warn "需要重启后生效"
            return 2
        else
            # 硬编码 options，grubby 不可用时无法自动修改
            warn "当前内核 BLS 条目使用硬编码 options 且 grubby 不可用"
            warn "请手动编辑: $bls_conf"
            warn "在 options 行末尾追加: $target_arg"
            warn "然后重启系统"
            return 3
        fi
    fi

    # 最后降级：传统 grub2-mkconfig
    if [ -f /etc/default/grub ]; then
        info "写入 /etc/default/grub（传统模式）..."
        if ! grep -q "$target_arg" /etc/default/grub; then
            sed -i "s|\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"|\1 ${target_arg}\"|" /etc/default/grub
        fi
        grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null \
            || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null \
            || { warn "grub 配置更新失败，请手动执行"; return 3; }
        warn "需要重启后生效"
        return 2
    fi

    warn "未找到可用的引导配置方式，请手动添加内核参数: $target_arg"
    return 3
}

mitigate_copy_fail() {
    echo "=== 缓解 Copy Fail / CVE-2026-31431 ==="

    af_alg_usage="$(lsof 2>/dev/null | grep AF_ALG || true)"
    if [ -n "$af_alg_usage" ]; then
        warn "检测到进程正在使用 AF_ALG："
        echo "$af_alg_usage"
        if ! confirm "继续禁用 algif_aead 可能影响上述进程，是否继续？"; then
            info "跳过 algif_aead 禁用"
            return
        fi
    fi

    if is_builtin algif_aead; then
        warn "algif_aead 是内核 builtin 模块，modprobe install 规则无法封锁"
        warn "需通过 initcall_blacklist 内核参数 + 重启来彻底缓解"
        apply_initcall_blacklist
        bl_ret=$?

        # 无论能否重启，立即清理页缓存作为临时措施
        info "临时清理页缓存（使已篡改缓存失效）..."
        sync && echo 3 > /proc/sys/vm/drop_caches

        if [ "$bl_ret" -eq 0 ]; then
            info "Copy Fail 缓解完成（initcall_blacklist 已生效）"
        elif [ "$bl_ret" -eq 2 ]; then
            warn "Copy Fail 缓解：引导参数已写入，重启后完全生效"
        else
            warn "Copy Fail 缓解：引导参数写入失败，请手动处理后重启"
        fi
        return "$bl_ret"
    fi

    # 非 builtin：modprobe 封锁
    info "写入 modprobe 禁用配置..."
    append_modprobe_conf "install algif_aead /bin/false"

    algif_loaded="$(lsmod 2>/dev/null | grep -w algif_aead || true)"
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

    info "写入 modprobe 禁用配置（幂等）..."
    for entry in \
        "install esp4 /bin/false" \
        "install esp6 /bin/false" \
        "install rxrpc /bin/false"; do
        append_modprobe_conf "$entry"
    done

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
    need_reboot=false

    # 1. 验证 modprobe 配置文件（仅当存在非 builtin 模块时必须）
    conf_file="/etc/modprobe.d/disable-vuln-modules.conf"
    has_non_builtin=false
    for mod in algif_aead esp4 esp6 rxrpc; do
        is_builtin "$mod" || has_non_builtin=true
    done

    if [ "$has_non_builtin" = true ]; then
        if [ -f "$conf_file" ]; then
            pass "modprobe 配置文件已写入: $conf_file"
            echo "--- 配置文件内容 ---"
            cat "$conf_file"
            echo "--- 配置文件结束 ---"
        else
            fail "modprobe 配置文件不存在: $conf_file"
            all_pass=false
        fi
    fi

    # 2. 逐模块验证
    echo ""
    info "逐模块验证封锁状态..."
    for mod in algif_aead esp4 esp6 rxrpc; do
        if is_builtin "$mod"; then
            # builtin 模块：验证 initcall_blacklist
            init_func="${mod}_init"
            if grep -q "initcall_blacklist=${init_func}" /proc/cmdline 2>/dev/null; then
                pass "模块 $mod（builtin）：已通过 initcall_blacklist 封锁，当前生效"
            else
                # 检查是否已写入引导配置（待重启）
                grubby_has=""
                if command -v grubby >/dev/null 2>&1; then
                    grubby_has="$(grubby --info=DEFAULT 2>/dev/null | grep "initcall_blacklist=${init_func}" || true)"
                fi
                grub_has="$(grep "initcall_blacklist=${init_func}" /etc/default/grub 2>/dev/null || true)"
                bls_has=""
                kernel_ver="$(uname -r)"
                bls_conf="$(ls /boot/loader/entries/*${kernel_ver}*.conf 2>/dev/null | head -1)"
                [ -n "$bls_conf" ] && bls_has="$(grep "initcall_blacklist=${init_func}" "$bls_conf" 2>/dev/null || true)"

                if [ -n "$grubby_has" ] || [ -n "$grub_has" ] || [ -n "$bls_has" ]; then
                    warn "模块 $mod（builtin）：initcall_blacklist 已写入引导配置，重启后生效"
                    need_reboot=true
                else
                    fail "模块 $mod（builtin）：未找到 initcall_blacklist 配置，封锁未完成"
                    all_pass=false
                fi
            fi
            continue
        fi

        # 非 builtin 模块：先尝试卸载残留，再测试加载
        loaded="$(lsmod 2>/dev/null | grep -w "$mod" || true)"
        if [ -n "$loaded" ]; then
            warn "模块 $mod 仍已加载，尝试卸载..."
            rmmod "$mod" 2>/dev/null && info "$mod 卸载成功" || warn "$mod 卸载失败，仍在使用中"
        fi

        if modprobe "$mod" 2>/dev/null; then
            fail "模块 $mod：仍可加载，modprobe 封锁未生效"
            all_pass=false
        else
            pass "模块 $mod：已被 modprobe 封锁，无法加载"
        fi
    done

    # 3. 最终结论
    echo ""
    if [ "$all_pass" = true ] && [ "$need_reboot" = false ]; then
        pass "所有模块已封锁完毕，缓解措施完全生效"
    elif [ "$all_pass" = true ] && [ "$need_reboot" = true ]; then
        warn "modprobe 封锁已生效；builtin 模块封锁参数已写入，重启后完全生效"
    else
        fail "部分模块封锁未生效，请检查上方输出"
    fi
}

rollback() {
    echo "=== 回滚所有缓解措施 ==="

    # 回滚 modprobe 配置
    conf_file="/etc/modprobe.d/disable-vuln-modules.conf"
    if [ -f "$conf_file" ]; then
        rm -f "$conf_file"
        info "已删除 modprobe 配置: $conf_file"
    else
        info "未发现 modprobe 缓解配置，无需回滚"
    fi

    # 回滚 initcall_blacklist（grubby 优先）
    target_arg="initcall_blacklist=algif_aead_init"
    rolled_grub=false

    if command -v grubby >/dev/null 2>&1; then
        if grubby --info=DEFAULT 2>/dev/null | grep -q "$target_arg"; then
            info "通过 grubby 移除 initcall_blacklist..."
            grubby --update-kernel=DEFAULT --remove-args="$target_arg" \
                && info "grubby 回滚成功，重启后生效" \
                || warn "grubby 回滚失败，请手动执行"
            rolled_grub=true
        fi
    fi

    if [ "$rolled_grub" = false ]; then
        # 回滚 /etc/default/grub
        if [ -f /etc/default/grub ] && grep -q "$target_arg" /etc/default/grub; then
            sed -i "s| ${target_arg}||g" /etc/default/grub
            grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null \
                || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null \
                || warn "grub 配置更新失败，请手动执行"
            info "已从 /etc/default/grub 移除 initcall_blacklist，重启后生效"
            rolled_grub=true
        fi

        # 回滚 BLS .conf 文件
        kernel_ver="$(uname -r)"
        bls_conf="$(ls /boot/loader/entries/*${kernel_ver}*.conf 2>/dev/null | head -1)"
        if [ -n "$bls_conf" ] && grep -q "$target_arg" "$bls_conf"; then
            sed -i "s| ${target_arg}||g" "$bls_conf"
            info "已从 BLS 条目移除 initcall_blacklist: $bls_conf，重启后生效"
            rolled_grub=true
        fi
    fi

    if [ "$rolled_grub" = false ]; then
        info "未发现 initcall_blacklist 配置，无需回滚"
    fi

    info "回滚完成"
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
    print_kv kernel "$(uname -r)"
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