#!/bin/sh

print_kv() {
    key="$1"
    value="$2"
    printf '%s: %s\n' "$key" "$value"
}

print_multiline_kv() {
    key="$1"
    value="$2"
    if [ -n "$value" ]; then
        printf '%s:\n%s\n' "$key" "$value"
    else
        printf '%s: %s\n' "$key" "none"
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

get_os_pretty_name() {
    if [ -r /etc/os-release ]; then
        os_name=$(grep '^PRETTY_NAME=' /etc/os-release | head -n 1 | cut -d= -f2- | tr -d '"')
        if [ -n "$os_name" ]; then
            printf '%s\n' "$os_name"
            return
        fi
    fi
    uname -s 2>/dev/null
}

get_system_type() {
    if command_exists systemd-detect-virt; then
        virt_type=$(systemd-detect-virt 2>/dev/null)
        if [ -n "$virt_type" ] && [ "$virt_type" != "none" ]; then
            printf 'virtualized (%s)\n' "$virt_type"
            return
        fi
    fi

    if [ -r /proc/1/cgroup ] && grep -Eq '(docker|kubepods|containerd|lxc)' /proc/1/cgroup 2>/dev/null; then
        printf 'container-like environment\n'
        return
    fi

    printf 'physical or unknown\n'
}

get_ip_info() {
    if command_exists ip; then
        ip -o -4 addr show scope global 2>/dev/null | awk '{print $2" "$4}'
        ip -o -6 addr show scope global 2>/dev/null | awk '{print $2" "$4}'
        return
    fi

    if command_exists hostname; then
        hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d'
    fi
}

get_primary_ip() {
    primary_ip=""

    if command_exists ip; then
        primary_ip=$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1 {print $4}' | cut -d/ -f1)
        if [ -n "$primary_ip" ]; then
            printf '%s\n' "$primary_ip"
            return
        fi

        primary_ip=$(ip -o -6 addr show scope global 2>/dev/null | awk 'NR==1 {print $4}' | cut -d/ -f1)
        if [ -n "$primary_ip" ]; then
            printf '%s\n' "$primary_ip"
            return
        fi
    fi

    if command_exists hostname; then
        primary_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        if [ -n "$primary_ip" ]; then
            printf '%s\n' "$primary_ip"
            return
        fi
    fi

    printf 'unknown\n'
}

sanitize_for_filename() {
    printf '%s\n' "$1" | sed 's/[:\/ ]/_/g'
}

version_ge() {
    [ "$1" = "$2" ] && return 0
    first=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)
    [ "$first" = "$2" ]
}

extract_kernel_base() {
    printf '%s\n' "$1" | sed 's/-.*$//'
}

check_copy_fail() {
    echo "=== Copy Fail / CVE-2026-31431 ==="
    kernel="$(uname -r 2>/dev/null)"
    kernel_base="$(extract_kernel_base "$kernel")"
    algif_loaded="$(lsmod 2>/dev/null | grep -w algif_aead)"
    algif_block="$(ls /etc/modprobe.d/*algif* 2>/dev/null)"
    af_alg_usage="$(lsof 2>/dev/null | grep AF_ALG)"
    module_disable_guidance=""

    vulnerable="未知"
    reason="无法自动精确判断，请结合发行版补丁确认"
    basis=""
    upstream_version_judgement="未知"
    patch_state_judgement="待确认"
    final_judgement="待确认"

    case "$kernel_base" in
        7.*)
            vulnerable="否"
            reason="内核主线版本看起来不低于 7.x"
            basis="文档中标明主线内核 >= 7.0 不受影响"
            upstream_version_judgement="不受影响"
            patch_state_judgement="无需额外确认"
            final_judgement="不受影响"
            ;;
        6.19.*)
            if version_ge "$kernel_base" "6.19.12"; then
                vulnerable="否"
                reason="内核版本看起来不低于 6.19.12"
                basis="文档中标明 6.19.12 及以上版本不受影响"
                upstream_version_judgement="不受影响"
                patch_state_judgement="无需额外确认"
                final_judgement="不受影响"
            else
                vulnerable="可能"
                reason="6.19 分支版本低于 6.19.12"
                basis="文档中标明 6.19.12 以下可能受影响"
                upstream_version_judgement="受影响"
                patch_state_judgement="待确认"
                final_judgement="高概率受影响"
            fi
            ;;
        6.18.*)
            if version_ge "$kernel_base" "6.18.22"; then
                vulnerable="否"
                reason="6.18 分支版本看起来不低于 6.18.22"
                basis="文档中标明 6.18.22 及以上版本不受影响"
                upstream_version_judgement="不受影响"
                patch_state_judgement="无需额外确认"
                final_judgement="不受影响"
            else
                vulnerable="可能"
                reason="6.18 分支版本低于 6.18.22"
                basis="文档中标明 6.18.22 以下可能受影响"
                upstream_version_judgement="受影响"
                patch_state_judgement="待确认"
                final_judgement="高概率受影响"
            fi
            ;;
        6.12.*|6.6.*|6.1.*|5.15.*|5.10.*)
            vulnerable="可能"
            reason="内核版本命中公开列出的长期支持受影响分支"
            basis="文档明确列出 6.12、6.6、6.1、5.15、5.10 所有版本受影响"
            upstream_version_judgement="受影响"
            patch_state_judgement="待确认"
            final_judgement="高概率受影响"
            ;;
        *)
            vulnerable="可能"
            reason="内核版本位于公开受影响时间范围内或缺乏明确修复映射"
            basis="文档说明从 2017 年引入到 2026 年修复之间的版本普遍存在风险，发行版 backport 情况需单独确认"
            upstream_version_judgement="受影响"
            patch_state_judgement="待确认"
            final_judgement="高概率受影响"
            ;;
    esac

    if [ -n "$af_alg_usage" ]; then
        module_disable_guidance="检测到进程正在使用 AF_ALG，直接禁用 algif_aead 可能影响现有业务，建议先确认进程归属和维护窗口，再决定是否禁用"
    elif [ -n "$algif_loaded" ]; then
        module_disable_guidance="当前未发现 AF_ALG 使用进程，但模块已加载，通常可以评估后禁用 algif_aead 并观察业务影响"
    else
        module_disable_guidance="当前未发现 AF_ALG 使用进程，且 algif_aead 未加载，如无强依赖业务，通常可以禁用以降低暴露面"
    fi

    print_kv kernel "$kernel"
    print_kv kernel_base "$kernel_base"
    print_kv upstream_version_judgement "$upstream_version_judgement"
    print_kv patch_state_judgement "$patch_state_judgement"
    print_kv final_judgement "$final_judgement"
    print_kv vulnerable "$vulnerable"
    print_kv reason "$reason"
    print_kv basis "$basis"
    if [ -n "$algif_loaded" ]; then
        print_kv algif_aead_loaded "yes"
        print_multiline_kv algif_aead_module "$algif_loaded"
    else
        print_kv algif_aead_loaded "no"
    fi
    if [ -n "$af_alg_usage" ]; then
        print_kv af_alg_in_use "yes"
        print_multiline_kv af_alg_usage_details "$af_alg_usage"
    else
        print_kv af_alg_in_use "no"
    fi
    if [ -n "$algif_block" ]; then
        print_multiline_kv algif_aead_block_files "$algif_block"
    else
        print_kv algif_aead_block_files "none"
    fi
    print_kv module_disable_guidance "$module_disable_guidance"
    echo
}

check_dirty_frag() {
    echo "=== Dirty Frag ==="
    kernel="$(uname -r 2>/dev/null)"
    kernel_base="$(extract_kernel_base "$kernel")"
    esp4_loaded="$(lsmod 2>/dev/null | grep -w esp4)"
    esp6_loaded="$(lsmod 2>/dev/null | grep -w esp6)"
    rxrpc_loaded="$(lsmod 2>/dev/null | grep -w rxrpc)"
    mitigation="$(grep -R 'install esp4 /bin/false\|install esp6 /bin/false\|install rxrpc /bin/false' /etc/modprobe.d/ 2>/dev/null)"
    xfrm_policy="$(ip xfrm policy list 2>/dev/null)"
    xfrm_state="$(ip xfrm state list 2>/dev/null)"
    upstream_commit_reference="f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4"
    patch_state_judgement="待确认"
    final_judgement="待确认"
    module_disable_guidance=""

    if [ -n "$esp4_loaded$esp6_loaded$rxrpc_loaded" ]; then
        module_reason="检测到可能相关模块已加载，攻击面更直接"
        if [ -n "$mitigation" ]; then
            final_judgement="中风险，需核查补丁状态"
        else
            final_judgement="高风险，需优先核查补丁状态"
        fi
    else
        module_reason="未检测到 esp4、esp6、rxrpc 已加载，但仍需结合内核补丁状态判断"
        if [ -n "$mitigation" ]; then
            final_judgement="低到中风险，仍需核查补丁状态"
        else
            final_judgement="中风险，需核查补丁状态"
        fi
    fi

    if [ -n "$mitigation" ]; then
        patch_state_judgement="已检测到临时缓解配置，但不能替代补丁确认"
    fi

    if [ -n "$xfrm_policy" ] || [ -n "$xfrm_state" ]; then
        module_disable_guidance="检测到 xfrm policy/state 输出，说明系统正在使用 IPsec 相关能力，不建议直接禁用 esp4 或 esp6；应先评估业务影响并安排维护窗口。rxrpc 是否可禁用需结合业务确认。"
        if [ -n "$rxrpc_loaded" ]; then
            final_judgement="高风险，且存在 IPsec/相关模块使用，优先升级补丁并谨慎处理模块禁用"
        else
            final_judgement="中到高风险，检测到 IPsec 使用，优先升级补丁，不建议直接禁用 esp4/esp6"
        fi
    elif [ -n "$esp4_loaded$esp6_loaded$rxrpc_loaded" ]; then
        module_disable_guidance="未发现 xfrm policy/state 使用痕迹，但相关模块已加载，通常可以在确认业务后评估禁用 esp4、esp6、rxrpc。"
    else
        module_disable_guidance="未发现 xfrm policy/state 使用痕迹，且相关模块未加载，通常可以禁用 esp4、esp6、rxrpc 以降低暴露面。"
    fi

    print_kv kernel "$kernel"
    print_kv kernel_base "$kernel_base"
    print_kv upstream_commit_reference "$upstream_commit_reference"
    print_kv patch_state_judgement "$patch_state_judgement"
    print_kv final_judgement "$final_judgement"
    print_kv vulnerable "可能"
    print_kv reason "需结合发行版是否 backport 修复判断"
    print_kv basis "文档仅给出主线修复 commit f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4，未给出完整发行版安全版本映射"
    print_kv module_reason "$module_reason"
    if [ -n "$xfrm_policy" ]; then
        print_kv ipsec_in_use "yes"
        print_multiline_kv xfrm_policy_details "$xfrm_policy"
    else
        print_kv ipsec_in_use "no"
    fi
    if [ -n "$xfrm_state" ]; then
        print_kv xfrm_state_present "yes"
        print_multiline_kv xfrm_state_details "$xfrm_state"
    else
        print_kv xfrm_state_present "no"
    fi

    if [ -n "$esp4_loaded" ]; then
        print_kv esp4_loaded "yes"
        print_multiline_kv esp4_module "$esp4_loaded"
    else
        print_kv esp4_loaded "no"
    fi
    if [ -n "$esp6_loaded" ]; then
        print_kv esp6_loaded "yes"
        print_multiline_kv esp6_module "$esp6_loaded"
    else
        print_kv esp6_loaded "no"
    fi
    if [ -n "$rxrpc_loaded" ]; then
        print_kv rxrpc_loaded "yes"
        print_multiline_kv rxrpc_module "$rxrpc_loaded"
    else
        print_kv rxrpc_loaded "no"
    fi
    if [ -n "$mitigation" ]; then
        print_kv mitigation_config "present"
        print_multiline_kv mitigation_details "$mitigation"
    else
        print_kv mitigation_config "absent"
    fi
    print_kv module_disable_guidance "$module_disable_guidance"
    echo
}

check_cpanel() {
    echo "=== cPanel Auth Bypass / CVE-2026-41940 ==="
    version_file="/usr/local/cpanel/version"
    version_branch="unknown"
    fixed_version_reference="11.86.0.41 / 11.110.0.97 / 11.118.0.63 / 11.126.0.54 / 11.130.0.18 / 11.132.0.29 / 11.134.0.20 / 11.136.0.5 / WP Squared 11.136.1.7"
    final_judgement="待确认"

    if [ -f "$version_file" ]; then
        version="$(cat "$version_file" 2>/dev/null)"
        version_branch="$(printf '%s\n' "$version" | awk -F. '{print $1 "." $2 "." $3}')"
        print_kv installed "yes"
        print_kv version "$version"
        print_kv version_branch "$version_branch"
        print_kv fixed_version_reference "$fixed_version_reference"
        print_kv vulnerable "可能"
        print_kv reason "请将版本号与官方修复版本逐项比对"
        print_kv basis "文档列出的受影响版本范围覆盖多个 11.x 分支，需按对应分支安全版本精确判断"
        final_judgement="发现 cPanel，需立即核对当前版本是否低于对应分支修复版本"
    else
        print_kv installed "no"
        print_kv version_branch "$version_branch"
        print_kv fixed_version_reference "$fixed_version_reference"
        print_kv vulnerable "否"
        print_kv reason "未发现 cPanel 安装路径"
        print_kv basis "未检测到 /usr/local/cpanel/version 或相关安装目录"
        final_judgement="未安装 cPanel，当前主机不受该漏洞直接影响"
    fi

    ports="$(ss -lntp 2>/dev/null | grep -E ':(2082|2083|2086|2087)\b')"
    if [ -n "$ports" ]; then
        print_kv mgmt_ports_exposed "yes"
        print_multiline_kv mgmt_port_details "$ports"
        if [ -f "$version_file" ]; then
            final_judgement="发现 cPanel 且管理端口暴露，需优先核对版本并限制访问来源"
        fi
    else
        print_kv mgmt_ports_exposed "no"
    fi

    print_kv final_judgement "$final_judgement"
    echo
}

PRIMARY_IP="$(get_primary_ip)"
SAFE_IP="$(sanitize_for_filename "$PRIMARY_IP")"
TIME_TAG="$(date '+%Y%m%d_%H%M%S' 2>/dev/null)"
[ -n "$TIME_TAG" ] || TIME_TAG="unknown_time"
LOG_FILE="./漏洞扫描_${SAFE_IP}_${TIME_TAG}.log"

{
    echo "漏洞本地检测报告"
    echo "generated_at: $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    print_kv host_name "$(hostname 2>/dev/null)"
    print_kv os_name "$(get_os_pretty_name)"
    print_kv system_type "$(get_system_type)"
    print_kv primary_ip "$PRIMARY_IP"
    print_multiline_kv ip_addresses "$(get_ip_info)"
    print_kv log_file "$LOG_FILE"
    echo
    check_copy_fail
    check_dirty_frag
    check_cpanel
} | tee "$LOG_FILE"
