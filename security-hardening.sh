#!/bin/bash

# 脚本执行选项：
# set -e: 命令失败时立即退出
# set -u: 尝试使用未设置的变量时退出
# set -o pipefail: 管道中的命令失败时，将整个管道的退出状态设置为该命令的退出状态
set -e -u -o pipefail

#region //全局配置和版本信息
# VPS安全加固与代理搭建一体化脚本
# 版本：2.0.0
# 支持系统：Ubuntu/Debian/CentOS
# 参考项目：YujuToolBox, xrayREALITY

version="2.1.1"
script_name="security-hardening"

# 颜色定义
red='\033[31m'
green='\033[0;32m'
yellow='\033[33m'
blue='\033[0;34m'
pink='\033[38;5;218m'
cyan='\033[96m'
white='\033[0m'
grey='\e[37m'

# 全局变量
user_authorization="false"
log_file="/var/log/security-hardening.log"
config_dir="/etc/security-hardening"
backup_dir="/etc/security-hardening/backup"
#endregion

#region //工具函数库
# 复制脚本到系统路径
copy_script_to_system() {
    cp "$0" /usr/local/bin/security-hardening > /dev/null 2>&1
    chmod +x /usr/local/bin/security-hardening > /dev/null 2>&1
}

# 日志记录函数
log_operation() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$log_file"
}

# 错误处理函数
error_exit() {
    local message="$1"
    echo -e "${red}错误: ${message}${white}" >&2
    log_operation "ERROR: $message"
    exit 1
}

# 成功提示函数
success_msg() {
    local message="$1"
    echo -e "${green}✓ ${message}${white}"
    log_operation "SUCCESS: $message"
}

# 警告提示函数
warn_msg() {
    local message="$1"
    echo -e "${yellow}⚠ ${message}${white}"
    log_operation "WARNING: $message"
}

# 信息提示函数
info_msg() {
    local message="$1"
    echo -e "${blue}ℹ ${message}${white}"
    log_operation "INFO: $message"
}

# 操作完成提示
break_end() {
    echo -e "${green}执行完成${white}"
    echo -e "${green}按任意键返回菜单...${white}"
    read -n 1 -s -r -p ""
    echo ""
    clear
}

# 确认操作函数
confirm_operation() {
    local operation="$1"
    echo -e "${yellow}⚠️  即将执行：${operation}${white}"
    read -p "确认继续？(y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return 1
}

# 安全地向文件追加内容（如果内容不存在）
append_if_not_exists() {
    local line="$1"
    local file="$2"
    if ! grep -qF -- "$line" "$file"; then
        echo "$line" >> "$file"
    fi
}

#endregion

#region //输入验证函数库
# 通用输入提示函数
# $1: 提示信息
# $2: 用于存储结果的变量名
# $3: 验证函数的名称
# $4...: 验证函数需要的额外参数
prompt_for_input() {
    local prompt_msg="$1"
    local -n result_var="$2"
    local validation_func="$3"
    shift 3

    while true; do
        read -p "$prompt_msg" user_input
        if "$validation_func" "$user_input" "$@"; then
            result_var="$user_input"
            break
        else
            error_msg "输入无效，请重试。"
        fi
    done
}

# 验证端口号
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

# 验证文件是否存在
validate_file_exists() {
    local file_path="$1"
    [[ -f "$file_path" ]]
}

# 验证数字范围
# $1: 要验证的输入
# $2: 允许的最小值
# $3: 允许的最大值
validate_numeric_range() {
    local input="$1"
    local min="$2"
    local max="$3"
    
    # 检查是否为纯数字
    if ! [[ "$input" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # 检查是否在范围内
    if [ "$input" -ge "$min" ] && [ "$input" -le "$max" ]; then
        return 0
    else
        return 1
    fi
}

# 验证输入是指定范围内的数字或是 'q'
# $1: 要验证的输入
# $2: 允许的最小值
# $3: 允许的最大值
validate_numeric_range_or_q() {
    local input="$1"
    local min="$2"
    local max="$3"

    if [[ "$input" =~ ^[qQ]$ ]]; then
        return 0
    fi

    validate_numeric_range "$input" "$min" "$max"
}
#endregion

#region //工具函数库 (continued)
# 进度显示函数
show_progress() {
    local current=$1
    local total=$2
    local desc="$3"
    
    echo -e "${green}[${current}/${total}]${white} ${desc}"
    local progress=$((current*30/total))
    printf "${pink}"
    for ((i=0; i<progress; i++)); do printf "="; done
    printf ">"
    for ((i=progress; i<30; i++)); do printf " "; done
    printf "${white}\n"
}

#region //授权和用户协议
# 初始化授权状态检查
authorization_check() {
    if grep -q '^user_authorization="true"' /usr/local/bin/security-hardening > /dev/null 2>&1; then
        user_authorization="true"
    fi
}

# 用户协议提示
user_agreement() {
    clear
    echo -e "${pink}欢迎使用VPS安全加固与代理搭建工具 v${version}${white}"
    echo "此脚本集成了系统安全加固和VLESS-HTTP2-REALITY代理部署功能"
    echo -e "${red}请仔细阅读以下重要提示：${white}"
    echo "1. 此脚本会修改系统配置，包括SSH、防火墙等关键设置"
    echo "2. 建议在测试环境中先行验证"
    echo "3. 请确保您有足够的系统管理权限"
    echo "4. 脚本执行过程中请勿中断"
    echo -e "${pink}============================${white}"
    read -r -p "是否同意并继续？(y/n): " user_input
    
    if [[ "$user_input" =~ ^[Yy]$ ]]; then
        echo "已同意用户协议"
        sed -i 's/^user_authorization="false"/user_authorization="true"/' /usr/local/bin/security-hardening 2>/dev/null
        user_authorization="true"
        # 安装基础依赖
        install_basic_dependencies
    else
        echo "已拒绝用户协议"
        exit 1
    fi
}

# 检查授权状态
authorization_false() {
    if [[ "$user_authorization" == "false" ]]; then
        user_agreement
    fi
}

# 安装基础依赖
install_basic_dependencies() {
    info_msg "正在安装基础依赖..."
    if command -v apt-get > /dev/null; then
        apt-get update -y > /dev/null 2>&1
        apt-get install -y curl wget sudo systemd > /dev/null 2>&1
    elif command -v yum > /dev/null; then
        yum update -y > /dev/null 2>&1
        yum install -y curl wget sudo systemd > /dev/null 2>&1
    elif command -v dnf > /dev/null; then
        dnf update -y > /dev/null 2>&1
        dnf install -y curl wget sudo systemd > /dev/null 2>&1
    fi
    success_msg "基础依赖安装完成"
}
#endregion

#region //权限和环境检查
# Root权限检测
root_check() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "此脚本需要root权限运行，请使用 sudo 或切换到root用户"
    fi
}

# 系统兼容性检查
check_system_compatibility() {
    # 检查是否为支持的系统
    if [[ ! -f /etc/os-release ]]; then
        error_exit "无法检测系统版本，请确保运行在支持的Linux发行版上"
    fi
    
    # 检查是否为OpenVZ（不支持某些功能）
    if [[ -d "/proc/vz" ]]; then
        warn_msg "检测到OpenVZ虚拟化环境，某些功能可能受限"
    fi
    
    # 检查systemd支持
    if ! command -v systemctl > /dev/null; then
        error_exit "系统不支持systemd，无法继续"
    fi
    
    success_msg "系统兼容性检查通过"
}

# 网络环境检查
check_network_environment() {
    info_msg "检查网络连接..."
    
    # 检查基本网络连接
    if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        error_exit "网络连接失败，请检查网络设置"
    fi
    
    # 检查DNS解析
    if ! nslookup google.com > /dev/null 2>&1; then
        warn_msg "DNS解析可能存在问题"
    fi
    
    success_msg "网络环境检查完成"
}

# 快捷指令设置
setup_shortcut() {
    copy_script_to_system
    if ! grep -q "alias security-hardening" ~/.bashrc 2>/dev/null; then
        echo "alias security-hardening='/usr/local/bin/security-hardening'" >> ~/.bashrc
    fi
}

# 包管理器操作封装
install_package() {
    local package="$1"
    local quiet="${2:-false}"

    info_msg "安装软件包: $package"

    local install_status=1
    case $PKG_MANAGER in
        apt)
            if [[ "$quiet" == "true" ]]; then
                (apt-get update -y > /dev/null 2>&1 && apt-get install -y "$package" > /dev/null 2>&1)
            else
                (apt-get update -y && apt-get install -y "$package")
            fi
            install_status=$?
            ;;
        yum)
            if [[ "$quiet" == "true" ]]; then
                yum install -y "$package" > /dev/null 2>&1
            else
                yum install -y "$package"
            fi
            install_status=$?
            ;;
        dnf)
            if [[ "$quiet" == "true" ]]; then
                dnf install -y "$package" > /dev/null 2>&1
            else
                dnf install -y "$package"
            fi
            install_status=$?
            ;;
        *)
            error_exit "不支持的包管理器: $PKG_MANAGER"
            ;;
    esac

    if [[ $install_status -eq 0 ]]; then
        success_msg "软件包 $package 安装成功"
    else
        error_exit "软件包 $package 安装失败"
    fi
}

# 服务管理封装
manage_service() {
    local action="$1"
    local service="$2"
    local status=0

    info_msg "执行操作: $action, 服务: $service"

    case $action in
        start|stop|restart|enable|disable)
            if systemctl "$action" "$service"; then
                success_msg "服务 $service $action 操作成功"
            else
                status=$?
                # 对于 enable/disable，即使失败也只警告不退出
                if [[ "$action" == "enable" || "$action" == "disable" ]]; then
                    warn_msg "服务 $service $action 操作可能失败 (退出码: $status)"
                    return 0 # 避免脚本因非关键错误退出
                else
                    error_exit "服务 $service $action 操作失败 (退出码: $status)"
                fi
            fi
            ;;
        status)
            # status 命令本身不会因为 set -e 退出，因为它在 case 语句中
            # 并且我们希望它的原始退出码用于逻辑判断
            systemctl status "$service"
            return $?
            ;;
        *)
            error_exit "无效的服务操作: $action"
            ;;
    esac
    return $status
}

# 备份文件
backup_file() {
    local file="$1"
    local backup_name="${2:-$(basename "$file").backup.$(date +%Y%m%d_%H%M%S)}"

    if [[ -f "$file" ]]; then
        cp "$file" "$backup_dir/$backup_name"
        success_msg "文件已备份: $file -> $backup_dir/$backup_name"
    else
        warn_msg "文件不存在，无法备份: $file"
    fi
}

# 检查端口是否被占用
check_port() {
    local port="$1"
    if ss -tuln | grep -q ":$port "; then
        return 0  # 端口被占用
    else
        return 1  # 端口空闲
    fi
}

# 生成随机字符串
generate_random_string() {
    local length="${1:-16}"
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length"
}

# 检查命令是否存在
command_exists() {
    command -v "$1" > /dev/null 2>&1
}
#endregion

#region //SSH安全配置模块 (重构)
# 默认SSH端口
SSH_DEFAULT_PORT="55520"

# 新的SSH安全配置主函数 (优化版)
configure_ssh_securely() {
    clear
    echo -e "${pink}SSH安全加固配置${white}"
    echo "================================"
    echo "参考: https://linux.do/t/topic/267502"
    echo "参考: https://101.lug.ustc.edu.cn/"
    echo ""

    info_msg "开始执行SSH安全加固流程..."
    echo ""
    echo "配置特点:"
    echo "• 使用 sshd_config.d 目录避免主配置冲突"
    echo "• 检查并处理云服务商配置覆盖"
    echo "• 根据用户偏好优化连接参数"
    echo "• 使用 'sshd -T' 验证最终生效配置"
    echo ""

    # --- 步骤 1: 环境扫描与冲突处理 ---
    echo -e "${cyan}步骤 1/6: 环境扫描与冲突处理${white}"
    handle_ssh_conflict_configs
    echo ""

    # --- 步骤 2: 获取用户输入 ---
    echo -e "${cyan}步骤 2/6: 配置参数设置${white}"
    local new_ssh_port
    prompt_for_input "请输入新的SSH端口 (1024-65535) [默认: $SSH_DEFAULT_PORT]: " new_ssh_port validate_port_or_empty "$SSH_DEFAULT_PORT"
    if [[ -z "$new_ssh_port" ]]; then
        new_ssh_port="$SSH_DEFAULT_PORT"
    fi

    # Root登录方式选择
    echo ""
    echo -e "${cyan}Root用户登录方式选择:${white}"
    echo "1. prohibit-password - 仅允许密钥登录 (推荐)"
    echo "2. no - 完全禁止Root登录"
    echo ""
    local root_choice
    prompt_for_input "请选择Root登录方式 [1-2, 默认: 1]: " root_choice validate_numeric_range_or_empty 1 2 "1"

    local permit_root_login
    case "${root_choice:-1}" in
        1) permit_root_login="prohibit-password" ;;
        2) permit_root_login="no" ;;
        *) permit_root_login="prohibit-password" ;;
    esac

    echo ""
    echo -e "${yellow}配置摘要:${white}"
    echo "  SSH端口: $new_ssh_port"
    echo "  Root登录: $permit_root_login"
    echo "  密码认证: 禁用"
    echo "  公钥认证: 启用"
    echo "  X11转发: 启用"
    echo "  DNS查找: 禁用 (加快登录)"
    echo "  连接保活: 60秒间隔, 最多3次"
    echo ""

    if ! confirm_operation "应用SSH安全配置"; then
        warn_msg "用户取消了SSH配置操作。"
        return
    fi

    # --- 步骤 3: 应用安全配置 ---
    echo ""
    echo -e "${cyan}步骤 3/6: 应用安全配置${white}"
    apply_ssh_secure_config "$new_ssh_port" "$permit_root_login"

    # --- 步骤 4: 配置验证 ---
    echo ""
    echo -e "${cyan}步骤 4/6: 配置验证${white}"
    verify_ssh_config "$new_ssh_port" "$permit_root_login"

    # --- 步骤 5: 生成SSH密钥 ---
    echo ""
    echo -e "${cyan}步骤 5/6: SSH密钥配置${white}"
    setup_ssh_keys

    # --- 步骤 6: 安全地重启服务 ---
    echo ""
    echo -e "${cyan}步骤 6/6: 重启SSH服务${white}"
    info_msg "准备重启SSH服务以应用配置..."

    # 最后一次验证
    if ! sshd -t; then
        error_exit "配置文件验证失败，取消重启以避免锁定"
    fi

    manage_service "restart" "sshd"

    echo ""
    success_msg "SSH安全配置完成！"
    echo ""
    echo -e "${green}重要提醒:${white}"
    echo "• 当前会话不会中断"
    echo "• 新连接请使用端口 $new_ssh_port"
    echo "• 仅支持密钥认证登录"
    echo "• 使用 'sudo sshd -T' 可查看完整配置"
    echo ""

    # 保存配置信息
    save_ssh_config_info "$new_ssh_port" "$permit_root_login"
}

# 检查常见云服务商SSH配置文件
check_common_cloud_configs() {
    local cloud_configs=(
        "/etc/ssh/sshd_config.d/50-cloud-init.conf"     # CloudCone, DigitalOcean
        "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"  # Ubuntu Cloud Images
        "/etc/ssh/sshd_config.d/99-cloudimg-settings.conf"  # Ubuntu Cloud Images (newer)
        "/etc/ssh/sshd_config.d/50-cloudimg-settings.conf"  # Ubuntu Cloud Images (older)
        "/etc/ssh/sshd_config.d/01-permitrootlogin.conf"    # Some VPS providers
        "/etc/ssh/sshd_config.d/00-cloud-init.conf"         # Generic cloud-init
    )

    local found_configs=()
    for config in "${cloud_configs[@]}"; do
        if [[ -f "$config" ]]; then
            found_configs+=("$config")
        fi
    done

    if [[ ${#found_configs[@]} -gt 0 ]]; then
        return 0  # 找到云服务商配置
    else
        return 1  # 未找到
    fi
}

# 检查并处理云服务商SSH配置
check_cloud_ssh_configs() {
    info_msg "检查云服务商SSH配置文件..."
    echo "参考: https://linux.do/t/topic/267502"
    echo "参考: https://unix.stackexchange.com/questions/727492/"
    echo ""

    local cloud_configs=()
    local sshd_config_dir="/etc/ssh/sshd_config.d"

    # 检查是否存在 sshd_config.d 目录
    if [[ ! -d "$sshd_config_dir" ]]; then
        warn_msg "sshd_config.d 目录不存在，将创建它"
        mkdir -p "$sshd_config_dir"
        chmod 755 "$sshd_config_dir"
    fi

    # 扫描所有 .conf 文件
    if [[ -d "$sshd_config_dir" ]]; then
        while IFS= read -r -d '' file; do
            cloud_configs+=("$file")
        done < <(find "$sshd_config_dir" -name "*.conf" -print0 2>/dev/null)
    fi

    if [[ ${#cloud_configs[@]} -gt 0 ]]; then
        warn_msg "发现以下SSH配置文件，可能会覆盖安全设置:"
        for file in "${cloud_configs[@]}"; do
            echo -e "${yellow}  - $file${white}"
            # 显示文件内容摘要
            if [[ -r "$file" ]]; then
                echo -e "${cyan}    内容摘要:${white}"
                grep -E "^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" "$file" 2>/dev/null | sed 's/^/      /' || echo "      (无关键配置项)"
            fi
        done
        echo ""

        echo -e "${yellow}建议操作:${white}"
        echo "1. 重命名为 .bak 文件以禁用 (推荐)"
        echo "2. 保留文件但可能导致配置冲突"
        echo ""

        if confirm_operation "将这些配置文件重命名为 .bak 以避免冲突"; then
            for file in "${cloud_configs[@]}"; do
                if [[ -f "$file" ]]; then
                    mv "$file" "${file}.bak"
                    success_msg "已禁用: $(basename "$file") -> $(basename "$file").bak"
                fi
            done
            info_msg "云服务商配置文件已禁用，自定义配置将正常生效"
        else
            warn_msg "保留云服务商配置文件。请注意可能的配置冲突。"
            warn_msg "建议使用 'sudo sshd -T' 检查最终生效的配置"
        fi
    else
        success_msg "未发现冲突的云服务商SSH配置文件"
    fi
}

# 步骤 1: 处理潜在的SSH配置冲突 (改进版)
handle_ssh_conflict_configs() {
    info_msg "扫描潜在的SSH配置冲突..."
    echo "参考最佳实践: https://linux.do/t/topic/267502"
    echo ""

    # 使用新的云服务商配置检查函数
    check_cloud_ssh_configs
}

# 步骤 2 的辅助验证函数
validate_port_or_empty() {
    local input="$1"
    # 如果输入为空，则返回成功，以接受默认值
    [[ -z "$input" ]] && return 0
    # 否则，使用现有的端口验证函数
    validate_port "$input"
}

# 步骤 3: 将安全配置写入专用文件 (优化版)
apply_ssh_secure_config() {
    local new_port="$1"
    local permit_root="${2:-prohibit-password}"  # 默认使用 prohibit-password
    local config_file="/etc/ssh/sshd_config.d/99-security-hardening.conf"

    info_msg "将安全配置写入 $config_file"
    echo "参考: https://linux.do/t/topic/267502"
    echo "使用 sshd_config.d 目录避免主配置文件冲突"

    # 确保目录存在
    mkdir -p "$(dirname "$config_file")"

    # 备份现有配置文件
    if [[ -f "$config_file" ]]; then
        backup_file "$config_file"
    fi

    # 备份主配置文件以防万一
    backup_file "/etc/ssh/sshd_config"

    # 使用Here Document原子化写入配置
    cat << EOF > "$config_file"
# VPS安全加固工具 - SSH安全配置
# 自动生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 参考: https://linux.do/t/topic/267502
# 参考: https://101.lug.ustc.edu.cn/
#
# 此文件位于 sshd_config.d 目录中，优先级高于主配置文件
# 使用 'sudo sshd -T' 可查看最终生效的配置

# === 连接设置 ===
Port $new_port
Protocol 2

# === 认证配置 ===
# 启用公钥认证，禁用密码认证
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Root用户登录策略
# prohibit-password: 仅允许密钥登录
# no: 完全禁止Root登录
PermitRootLogin $permit_root

# === 安全增强 ===
# 认证尝试限制
MaxAuthTries 3
LoginGraceTime 2m

# 连接保活设置 (根据用户偏好优化)
ClientAliveInterval 60
ClientAliveCountMax 3

# 基础安全设置
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes

# === 功能设置 ===
# X11转发 (根据用户偏好启用)
X11Forwarding yes
X11DisplayOffset 10
X11UseLocalhost yes

# DNS查找 (根据用户偏好禁用以加快登录)
UseDNS no

# === 会话限制 ===
MaxStartups 10:30:60
MaxSessions 10

# === 日志设置 ===
LogLevel INFO
SyslogFacility AUTHPRIV
EOF

    # 设置正确的文件权限
    chmod 644 "$config_file"

    success_msg "SSH安全配置已写入 $config_file"
    info_msg "配置特点:"
    echo "  - 使用 sshd_config.d 目录，避免主配置文件冲突"
    echo "  - 根据用户偏好优化连接保活参数"
    echo "  - 启用X11转发，禁用DNS查找以加快登录"
    echo "  - 使用 prohibit-password 允许Root密钥登录"
}

# 步骤 4: 验证最终生效的SSH配置 (增强版)
verify_ssh_config() {
    local expected_port="$1"
    local expected_root_login="${2:-prohibit-password}"

    info_msg "验证最终生效的SSH配置..."
    echo "参考: https://linux.do/t/topic/267502"
    echo "使用 'sshd -T' 检查最终生效配置"
    echo ""

    # 1. 检查配置文件语法
    echo -e "${cyan}1. 配置文件语法检查${white}"
    if ! sshd -t 2>/dev/null; then
        echo -e "${red}✗ SSH配置文件语法错误${white}"
        echo "错误详情:"
        sshd -t 2>&1 | sed 's/^/  /'
        error_exit "请修复配置文件语法错误后重试"
    else
        echo -e "${green}✓ SSH配置文件语法正确${white}"
    fi

    # 2. 使用 sshd -T 获取最终生效配置
    echo ""
    echo -e "${cyan}2. 最终生效配置验证${white}"
    local effective_config
    if ! effective_config=$(sshd -T 2>/dev/null); then
        error_exit "无法获取SSH有效配置，请检查配置文件"
    fi

    # 3. 验证关键安全设置
    local effective_port=$(echo "$effective_config" | grep -i '^port ' | awk '{print $2}')
    local effective_root_login=$(echo "$effective_config" | grep -i '^permitrootlogin ' | awk '{print $2}')
    local effective_password_auth=$(echo "$effective_config" | grep -i '^passwordauthentication ' | awk '{print $2}')
    local effective_pubkey_auth=$(echo "$effective_config" | grep -i '^pubkeyauthentication ' | awk '{print $2}')
    local effective_x11_forward=$(echo "$effective_config" | grep -i '^x11forwarding ' | awk '{print $2}')
    local effective_use_dns=$(echo "$effective_config" | grep -i '^usedns ' | awk '{print $2}')
    local effective_client_alive=$(echo "$effective_config" | grep -i '^clientaliveinterval ' | awk '{print $2}')

    # 4. 显示关键配置项
    echo "关键配置项验证:"
    printf "  %-20s: %s\n" "Port" "$effective_port"
    printf "  %-20s: %s\n" "PermitRootLogin" "$effective_root_login"
    printf "  %-20s: %s\n" "PasswordAuth" "$effective_password_auth"
    printf "  %-20s: %s\n" "PubkeyAuth" "$effective_pubkey_auth"
    printf "  %-20s: %s\n" "X11Forwarding" "$effective_x11_forward"
    printf "  %-20s: %s\n" "UseDNS" "$effective_use_dns"
    printf "  %-20s: %s\n" "ClientAliveInterval" "$effective_client_alive"

    # 5. 验证配置是否符合预期
    echo ""
    echo -e "${cyan}3. 安全配置验证${white}"
    local validation_passed=true
    local warnings=0

    # 端口验证
    if [[ "$effective_port" != "$expected_port" ]]; then
        echo -e "${red}✗ 端口配置异常: 期望 $expected_port, 实际 $effective_port${white}"
        validation_passed=false
    else
        echo -e "${green}✓ SSH端口: $effective_port${white}"
    fi

    # Root登录验证
    if [[ "$effective_root_login" != "$expected_root_login" ]]; then
        if [[ "$effective_root_login" == "no" && "$expected_root_login" == "prohibit-password" ]]; then
            echo -e "${yellow}⚠ Root登录: $effective_root_login (比预期更严格)${white}"
            ((warnings++))
        else
            echo -e "${red}✗ Root登录配置异常: 期望 $expected_root_login, 实际 $effective_root_login${white}"
            validation_passed=false
        fi
    else
        echo -e "${green}✓ Root登录: $effective_root_login${white}"
    fi

    # 密码认证验证
    if [[ "$effective_password_auth" != "no" ]]; then
        echo -e "${red}✗ 密码认证未禁用: $effective_password_auth${white}"
        validation_passed=false
    else
        echo -e "${green}✓ 密码认证: 已禁用${white}"
    fi

    # 公钥认证验证
    if [[ "$effective_pubkey_auth" != "yes" ]]; then
        echo -e "${red}✗ 公钥认证未启用: $effective_pubkey_auth${white}"
        validation_passed=false
    else
        echo -e "${green}✓ 公钥认证: 已启用${white}"
    fi

    # 显示验证结果
    echo ""
    if [[ "$validation_passed" == "true" ]]; then
        success_msg "SSH配置验证通过！"
        if [[ $warnings -gt 0 ]]; then
            warn_msg "有 $warnings 个警告，但不影响安全性"
        fi
    else
        error_exit "SSH配置验证失败！请检查配置文件或云服务商覆盖设置"
    fi

    # 6. 提供故障排除建议
    echo ""
    echo -e "${cyan}故障排除提示:${white}"
    echo "- 查看完整配置: sudo sshd -T"
    echo "- 检查配置文件: ls -la /etc/ssh/sshd_config.d/"
    echo "- 测试连接: ssh -p $effective_port user@server"
    echo "- 查看日志: sudo journalctl -u sshd -f"
}

# setup_ssh_keys 函数保持不变，因为它处理的是用户密钥，与sshd服务配置解耦
setup_ssh_keys() {
    info_msg "配置SSH密钥认证..."

    # 检查是否已存在SSH密钥
    if [[ -f ~/.ssh/id_rsa ]]; then
        warn_msg "SSH密钥已存在"
        read -p "是否重新生成？(y/N): " regenerate
        if [[ ! "$regenerate" =~ ^[Yy]$ ]]; then
            return
        fi
    fi

    # 创建SSH目录
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh

    # 生成SSH密钥对
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -q -N ""

    # 设置authorized_keys
    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/id_rsa
    chmod 644 ~/.ssh/id_rsa.pub

    success_msg "SSH密钥已生成并配置"

    echo -e "${yellow}重要：SSH私钥已保存至 ~/.ssh/id_rsa 文件中。${white}"
    echo -e "${red}此文件包含敏感信息，请妥善保管，不要泄露。${white}"
}

# 创建自定义SSH配置文件
create_custom_ssh_config() {
    local ssh_port="$1"
    local permit_root="$2"
    local custom_config="/etc/ssh/sshd_config.d/99-security-hardening.conf"

    info_msg "创建自定义SSH配置文件..."

    # 备份现有的自定义配置
    if [[ -f "$custom_config" ]]; then
        backup_file "$custom_config"
    fi

    # 创建新的配置文件
    cat > "$custom_config" << EOF
# VPS安全加固工具自定义SSH配置
# 创建时间: $(date '+%Y-%m-%d %H:%M:%S')
# 优先级: 99 (最高优先级，覆盖其他配置)
#
# 参考资料:
# - https://linux.do/t/topic/267502
# - https://101.lug.ustc.edu.cn/
# - https://unix.stackexchange.com/questions/727492/
#
# 说明: 在 /etc/ssh/sshd_config.d/ 创建配置文件而不是直接编辑
# /etc/ssh/sshd_config，防止 OpenSSH 更新后配置冲突

# 端口配置
Port $ssh_port

# Root用户登录配置
PermitRootLogin $permit_root

# 认证配置
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# 安全配置
MaxAuthTries 3
LoginGraceTime 60
MaxStartups 10:30:60
MaxSessions 10

# 网络配置
X11Forwarding yes
UseDNS no
ClientAliveInterval 60
ClientAliveCountMax 3

# 协议配置
Protocol 2

# 禁用不安全的认证方式
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no

# 用户限制（可选，根据需要启用）
# AllowUsers user1 user2
# DenyUsers baduser
# AllowGroups ssh-users
EOF

    chmod 644 "$custom_config"
    success_msg "自定义SSH配置已创建: $custom_config"
}

# 验证SSH配置
verify_ssh_config() {
    info_msg "验证SSH配置..."

    # 测试配置文件语法
    echo -e "${cyan}1. 检查配置文件语法...${white}"
    if ! sshd -t 2>/dev/null; then
        echo -e "${red}✗ SSH配置文件语法错误${white}"
        echo "错误详情:"
        sshd -t 2>&1 | sed 's/^/  /'
        error_exit "请修复配置文件语法错误后重试"
    else
        echo -e "${green}✓ SSH配置文件语法正确${white}"
    fi

    echo ""
    echo -e "${cyan}2. 使用 'sshd -T' 验证生效配置...${white}"
    echo "参考: https://linux.do/t/topic/267502"
    echo "================================"

    # 显示关键配置项
    local key_configs=(
        "Port"
        "PermitRootLogin"
        "PasswordAuthentication"
        "PubkeyAuthentication"
        "X11Forwarding"
        "UseDNS"
        "ClientAliveInterval"
        "ClientAliveCountMax"
        "MaxAuthTries"
        "LoginGraceTime"
        "MaxStartups"
        "MaxSessions"
    )

    for config in "${key_configs[@]}"; do
        local value=$(sshd -T | grep -i "^$config " | awk '{print $2}' 2>/dev/null || echo "未设置")
        printf "  %-20s: %s\n" "$config" "$value"
    done

    echo "================================"

    # 安全配置验证
    echo -e "${cyan}3. 安全配置验证...${white}"

    # 检查PermitRootLogin
    local permit_root=$(sshd -T | grep -i "^PermitRootLogin " | awk '{print $2}')
    if [[ "$permit_root" == "without-password" || "$permit_root" == "prohibit-password" ]]; then
        echo -e "${green}✓ Root用户仅允许密钥登录${white}"
    elif [[ "$permit_root" == "no" ]]; then
        echo -e "${yellow}⚠ Root用户完全禁止登录${white}"
    elif [[ "$permit_root" == "yes" ]]; then
        echo -e "${red}✗ Root用户允许密码登录（不安全）${white}"
    fi

    # 检查密码认证
    local password_auth=$(sshd -T | grep -i "^PasswordAuthentication " | awk '{print $2}')
    if [[ "$password_auth" == "no" ]]; then
        echo -e "${green}✓ 密码认证已禁用${white}"
    else
        echo -e "${red}✗ 密码认证仍然启用（不安全）${white}"
    fi

    # 检查端口
    local current_port=$(sshd -T | grep -i "^Port " | awk '{print $2}')
    if [[ "$current_port" != "22" ]]; then
        echo -e "${green}✓ SSH端口已修改为非默认端口: $current_port${white}"
    else
        echo -e "${yellow}⚠ 仍使用默认端口22${white}"
    fi

    # 检查X11转发（根据用户偏好应该启用）
    local x11_forward=$(sshd -T | grep -i "^X11Forwarding " | awk '{print $2}')
    if [[ "$x11_forward" == "yes" ]]; then
        echo -e "${green}✓ X11转发已启用${white}"
    else
        echo -e "${yellow}⚠ X11转发未启用${white}"
    fi

    success_msg "SSH配置验证完成"
}

# 显示SSH配置完成后的说明
show_ssh_config_summary() {
    local ssh_port="$1"
    local permit_root="$2"

    echo ""
    echo -e "${pink}SSH配置完成总结${white}"
    echo "================================"

    echo -e "${cyan}配置文件位置:${white}"
    echo "  主配置: /etc/ssh/sshd_config"
    echo "  自定义: /etc/ssh/sshd_config.d/99-security-hardening.conf"
    echo ""

    echo -e "${cyan}关键配置项:${white}"
    echo "  SSH端口: $ssh_port"
    echo "  Root登录: $permit_root"
    echo "  密码认证: 禁用"
    echo "  密钥认证: 启用"
    echo "  X11转发: 启用"
    echo "  DNS查找: 禁用"
    echo ""

    echo -e "${yellow}重要提醒:${white}"
    echo "1. 配置已使用 sshd_config.d 目录，符合最佳实践"
    echo "2. 使用 'sudo sshd -T' 可查看当前生效的完整配置"
    echo "3. 重启SSH服务: sudo systemctl restart sshd"
    echo "4. 测试新配置: ssh -p $ssh_port user@server"
    echo ""

    echo -e "${red}安全注意事项:${white}"
    echo "1. 确保已正确配置SSH密钥，否则可能无法登录"
    echo "2. 建议先在新终端测试连接，确认无误后再断开当前连接"
    echo "3. 如果使用防火墙，请确保新端口已开放"
    echo ""

    echo -e "${cyan}参考资料:${white}"
    echo "- https://linux.do/t/topic/267502"
    echo "- https://101.lug.ustc.edu.cn/"
    echo "- https://unix.stackexchange.com/questions/727492/"
}

# 配置SSH安全设置（新版本）
configure_ssh_security_settings() {
    info_msg "配置SSH安全设置..."

    # 获取SSH端口
    local ssh_port
    prompt_for_input "请输入SSH端口 (1-65535): " ssh_port validate_port

    # 验证端口范围
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || [[ $ssh_port -lt 1024 ]] || [[ $ssh_port -gt 65535 ]]; then
        warn_msg "端口范围无效，使用默认端口 55520"
        ssh_port=55520
    fi

    # Root用户登录方式选择
    echo ""
    echo -e "${cyan}Root用户登录方式:${white}"
    echo "1. 禁止Root登录 (推荐)"
    echo "2. 仅允许密钥登录"
    echo "3. 允许密码登录 (不推荐)"
    echo ""

    local permit_choice
    read -p "请选择 [1-3] (默认: 2): " permit_choice
    permit_choice=${permit_choice:-2}

    local permit_root
    case $permit_choice in
        1) permit_root="no" ;;
        2) permit_root="prohibit-password" ;;
        3) permit_root="yes" ;;
        *) permit_root="prohibit-password" ;;
    esac

    echo ""
    echo -e "${yellow}配置摘要:${white}"
    echo "  SSH端口: $ssh_port"
    echo "  Root登录: $permit_root"
    echo ""

    if ! confirm_operation "应用SSH安全配置"; then
        info_msg "操作已取消"
        return
    fi

    # 执行配置步骤
    show_progress 1 5 "检查云服务商配置"
    check_cloud_ssh_configs

    show_progress 2 5 "创建自定义配置"
    create_custom_ssh_config "$ssh_port" "$permit_root"

    show_progress 3 5 "验证配置"
    verify_ssh_config

    show_progress 4 5 "生成SSH密钥"
    generate_ssh_keys

    show_progress 5 5 "配置完成"

    success_msg "SSH安全设置配置完成！"

    # 保存配置信息
    save_ssh_config_info "$ssh_port" "$permit_root"

    # 显示配置总结
    show_ssh_config_summary "$ssh_port" "$permit_root"
}

# 保存SSH配置信息
save_ssh_config_info() {
    local ssh_port="$1"
    local permit_root="$2"

    # 保存到配置文件
    cat >> "$config_dir/ssh_config.conf" << EOF
# SSH配置信息
SSH_PORT=$ssh_port
PERMIT_ROOT_LOGIN=$permit_root
CONFIG_DATE=$(date '+%Y-%m-%d %H:%M:%S')
CUSTOM_CONFIG_FILE=/etc/ssh/sshd_config.d/99-security-hardening.conf
EOF
}

# SSH配置诊断和修复 (增强版)
ssh_config_diagnosis() {
    clear
    echo -e "${pink}SSH配置深度诊断${white}"
    echo "================================"
    echo "参考: https://linux.do/t/topic/267502"
    echo "参考: https://unix.stackexchange.com/questions/727492/"
    echo ""

    info_msg "正在执行SSH配置深度诊断..."
    echo ""

    local issues=0
    local warnings=0
    local recommendations=()

    # 1. 云服务商配置检查
    echo -e "${cyan}1. 云服务商配置冲突检查${white}"
    local cloud_configs=()
    local sshd_config_dir="/etc/ssh/sshd_config.d"

    if [[ -d "$sshd_config_dir" ]]; then
        while IFS= read -r -d '' file; do
            cloud_configs+=("$file")
        done < <(find "$sshd_config_dir" -name "*.conf" -print0 2>/dev/null)
    fi

    if [[ ${#cloud_configs[@]} -gt 0 ]]; then
        echo "  发现配置文件:"
        for file in "${cloud_configs[@]}"; do
            local basename_file=$(basename "$file")
            if [[ "$basename_file" == "99-security-hardening.conf" ]]; then
                echo -e "    ${green}✓ $file (安全配置)${white}"
            elif [[ "$basename_file" =~ (cloud-init|cloudimg) ]]; then
                echo -e "    ${yellow}⚠ $file (云服务商配置)${white}"
                ((warnings++))
                recommendations+=("建议禁用云服务商配置: mv $file $file.bak")
            else
                echo -e "    ${cyan}? $file (未知配置)${white}"
                ((warnings++))
            fi
        done
    else
        echo "  ✓ 未发现配置文件冲突"
    fi

    # 2. sshd_config.d 目录检查
    echo ""
    echo -e "${cyan}2. sshd_config.d 目录结构检查${white}"
    if [[ -d "$sshd_config_dir" ]]; then
        echo "  ✓ sshd_config.d 目录存在"
        local config_count=$(find "$sshd_config_dir" -name "*.conf" 2>/dev/null | wc -l)
        echo "  配置文件总数: $config_count"

        if [[ -f "$sshd_config_dir/99-security-hardening.conf" ]]; then
            echo "  ✓ 安全配置文件存在"
            local config_size=$(stat -f%z "$sshd_config_dir/99-security-hardening.conf" 2>/dev/null || stat -c%s "$sshd_config_dir/99-security-hardening.conf" 2>/dev/null)
            echo "  配置文件大小: ${config_size:-未知} 字节"
        else
            echo "  ⚠ 未找到安全配置文件"
            ((warnings++))
            recommendations+=("运行SSH安全配置: 选择菜单中的SSH配置选项")
        fi
    else
        echo "  ✗ sshd_config.d 目录不存在"
        ((issues++))
        recommendations+=("创建目录: sudo mkdir -p /etc/ssh/sshd_config.d")
    fi

    # 3. 配置文件语法检查
    echo ""
    echo -e "${cyan}3. 配置文件语法验证${white}"
    if sshd -t 2>/dev/null; then
        echo "  ✓ SSH配置文件语法正确"
    else
        echo "  ✗ SSH配置文件语法错误"
        echo "    错误详情:"
        sshd -t 2>&1 | sed 's/^/    /'
        ((issues++))
        recommendations+=("修复语法错误后重新验证配置")
    fi

    # 4. 使用 sshd -T 检查最终生效配置
    echo ""
    echo -e "${cyan}4. 最终生效配置分析 (sshd -T)${white}"
    if command -v sshd >/dev/null 2>&1; then
        local effective_config
        if effective_config=$(sshd -T 2>/dev/null); then
            echo "  ✓ 成功获取有效配置"

            # 分析关键安全配置
            local port=$(echo "$effective_config" | grep -i '^port ' | awk '{print $2}')
            local root_login=$(echo "$effective_config" | grep -i '^permitrootlogin ' | awk '{print $2}')
            local password_auth=$(echo "$effective_config" | grep -i '^passwordauthentication ' | awk '{print $2}')
            local pubkey_auth=$(echo "$effective_config" | grep -i '^pubkeyauthentication ' | awk '{print $2}')
            local x11_forward=$(echo "$effective_config" | grep -i '^x11forwarding ' | awk '{print $2}')
            local use_dns=$(echo "$effective_config" | grep -i '^usedns ' | awk '{print $2}')

            echo "    关键配置项:"
            printf "      %-20s: %s\n" "Port" "${port:-默认}"
            printf "      %-20s: %s\n" "PermitRootLogin" "${root_login:-默认}"
            printf "      %-20s: %s\n" "PasswordAuth" "${password_auth:-默认}"
            printf "      %-20s: %s\n" "PubkeyAuth" "${pubkey_auth:-默认}"
            printf "      %-20s: %s\n" "X11Forwarding" "${x11_forward:-默认}"
            printf "      %-20s: %s\n" "UseDNS" "${use_dns:-默认}"

            # 安全性评估
            echo ""
            echo "    安全性评估:"
            if [[ "$password_auth" == "no" ]]; then
                echo "      ✓ 密码认证已禁用"
            else
                echo "      ✗ 密码认证未禁用 (安全风险)"
                ((issues++))
                recommendations+=("禁用密码认证: PasswordAuthentication no")
            fi

            if [[ "$pubkey_auth" == "yes" ]]; then
                echo "      ✓ 公钥认证已启用"
            else
                echo "      ⚠ 公钥认证未启用"
                ((warnings++))
                recommendations+=("启用公钥认证: PubkeyAuthentication yes")
            fi

            if [[ "$root_login" == "prohibit-password" ]]; then
                echo "      ✓ Root仅允许密钥登录"
            elif [[ "$root_login" == "no" ]]; then
                echo "      ✓ Root登录已完全禁用"
            else
                echo "      ✗ Root登录配置不安全: $root_login"
                ((issues++))
                recommendations+=("限制Root登录: PermitRootLogin prohibit-password")
            fi

        else
            echo "  ✗ 无法获取有效配置"
            ((issues++))
        fi
    else
        echo "  ✗ sshd 命令不可用"
        ((issues++))
    fi

    # 5. SSH服务状态检查
    echo ""
    echo -e "${cyan}5. SSH服务状态检查${white}"
    if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
        echo "  ✓ SSH服务正在运行"
        local ssh_port=$(ss -tlnp | grep -E ':22[[:space:]]|:'"$port"'[[:space:]]' | head -1)
        if [[ -n "$ssh_port" ]]; then
            echo "  ✓ SSH端口监听正常"
        else
            echo "  ⚠ SSH端口监听异常"
            ((warnings++))
        fi
    else
        echo "  ✗ SSH服务未运行"
        ((issues++))
        recommendations+=("启动SSH服务: sudo systemctl start sshd")
    fi

    # 6. SSH密钥检查
    echo ""
    echo -e "${cyan}6. SSH密钥配置检查${white}"
    local key_count=0
    for user_home in /root /home/*; do
        if [[ -d "$user_home/.ssh" ]]; then
            local username=$(basename "$user_home")
            if [[ "$user_home" == "/root" ]]; then
                username="root"
            fi

            if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
                local keys=$(wc -l < "$user_home/.ssh/authorized_keys" 2>/dev/null || echo "0")
                if [[ $keys -gt 0 ]]; then
                    echo "  ✓ 用户 $username: $keys 个授权密钥"
                    ((key_count++))
                else
                    echo "  ⚠ 用户 $username: 无授权密钥"
                    ((warnings++))
                fi
            else
                echo "  ⚠ 用户 $username: 未配置授权密钥"
                ((warnings++))
            fi
        fi
    done

    if [[ $key_count -eq 0 ]]; then
        echo "  ✗ 系统中未找到任何SSH密钥"
        ((issues++))
        recommendations+=("配置SSH密钥: 使用菜单中的密钥生成功能")
    fi

    # 7. 诊断总结
    echo ""
    echo "================================"
    echo -e "${cyan}诊断总结${white}"
    echo "问题数量: $issues"
    echo "警告数量: $warnings"
    echo ""

    if [[ $issues -eq 0 && $warnings -eq 0 ]]; then
        echo -e "${green}✓ SSH配置完全正常，无需修复${white}"
    elif [[ $issues -eq 0 ]]; then
        echo -e "${yellow}⚠ SSH配置基本正常，有 $warnings 个建议优化项${white}"
    else
        echo -e "${red}✗ 发现 $issues 个问题需要修复${white}"
    fi

    # 8. 修复建议
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        echo ""
        echo -e "${cyan}修复建议:${white}"
        for i in "${!recommendations[@]}"; do
            echo "$((i+1)). ${recommendations[i]}"
        done
        echo ""

        if [[ $issues -gt 0 ]]; then
            if confirm_operation "自动修复SSH配置问题"; then
                fix_ssh_issues
            fi
        fi
    fi

    echo ""
    echo -e "${cyan}有用的命令:${white}"
    echo "• 查看完整配置: sudo sshd -T"
    echo "• 测试配置语法: sudo sshd -t"
    echo "• 查看SSH日志: sudo journalctl -u sshd -f"
    echo "• 重启SSH服务: sudo systemctl restart sshd"
    echo "• 检查端口监听: sudo ss -tlnp | grep ssh"

    break_end

    if [[ "$x11_forward" == "yes" ]]; then
        echo "  ✓ X11转发已启用（符合用户偏好）"
    else
        echo "  ⚠ X11转发未启用"
        ((warnings++))
    fi

    # 检查配置文件结构
    echo -e "${cyan}9. 配置文件结构检查${white}"
    local sshd_config_dir="/etc/ssh/sshd_config.d"
    if [[ -d "$sshd_config_dir" ]]; then
        local config_files=($(find "$sshd_config_dir" -name "*.conf" 2>/dev/null))
        if [[ ${#config_files[@]} -gt 0 ]]; then
            echo "  发现配置文件:"
            for config in "${config_files[@]}"; do
                echo "    - $(basename "$config")"
                # 检查是否有冲突配置
                if grep -q "PasswordAuthentication yes" "$config" 2>/dev/null; then
                    echo "      ⚠ 此文件启用了密码认证"
                    ((warnings++))
                fi
            done
        else
            echo "  ✓ 无额外配置文件"
        fi
    fi

    # 检查SSH服务状态
    echo -e "${cyan}7. SSH服务状态检查${white}"
    if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
        echo "  ✓ SSH服务运行正常"
    else
        echo "  ✗ SSH服务未运行"
        ((issues++))
    fi

    echo ""
    echo "================================"

    # 显示诊断结果
    if [[ $issues -eq 0 && $warnings -eq 0 ]]; then
        echo -e "${green}✓ SSH配置完全正常！${white}"
    elif [[ $issues -eq 0 ]]; then
        echo -e "${yellow}⚠ SSH配置基本正常，但有 $warnings 个建议优化项${white}"
    else
        echo -e "${red}✗ 发现 $issues 个严重问题和 $warnings 个警告项${white}"
        echo ""
        if confirm_operation "是否自动修复发现的问题"; then
            fix_ssh_issues
        fi
    fi

    break_end
}

# 修复SSH配置问题
fix_ssh_issues() {
    info_msg "正在修复SSH配置问题..."

    # 检查并修复Root登录配置
    local permit_root=$(sshd -T | grep -i "^permitrootlogin " | awk '{print $2}')
    if [[ "$permit_root" == "yes" ]]; then
        echo "修复Root登录配置..."
        echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config.d/99-security-hardening.conf
    fi

    # 检查并修复密钥认证
    local pubkey_auth=$(sshd -T | grep -i "^pubkeyauthentication " | awk '{print $2}')
    if [[ "$pubkey_auth" != "yes" ]]; then
        echo "启用密钥认证..."
        echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/99-security-hardening.conf
    fi

    # 重新验证配置
    if sshd -t 2>/dev/null; then
        success_msg "SSH配置修复完成"
        echo "建议重启SSH服务: systemctl restart sshd"
    else
        error_exit "配置修复失败，请手动检查"
    fi
}

# 重启SSH服务
restart_ssh_service() {
    info_msg "重启SSH服务..."

    # 测试配置文件语法
    if ! sshd -t; then
        error_exit "SSH配置文件语法错误，请检查配置"
    fi

    # 重启SSH服务
    manage_service restart sshd || manage_service restart ssh

    success_msg "SSH服务已重启"
}

# SSH配置管理菜单 (新增)
ssh_config_management() {
    while true; do
        clear
        echo -e "${pink}SSH配置管理${white}"
        echo "================================"
        echo "参考: https://linux.do/t/topic/267502"
        echo "参考: https://101.lug.ustc.edu.cn/"
        echo ""

        # 显示当前SSH状态
        echo -e "${cyan}当前SSH状态:${white}"
        if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
            echo "  服务状态: 运行中"
            local current_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' || echo "未知")
            local root_login=$(sshd -T 2>/dev/null | grep -i '^permitrootlogin ' | awk '{print $2}' || echo "未知")
            local password_auth=$(sshd -T 2>/dev/null | grep -i '^passwordauthentication ' | awk '{print $2}' || echo "未知")
            echo "  当前端口: $current_port"
            echo "  Root登录: $root_login"
            echo "  密码认证: $password_auth"
        else
            echo "  服务状态: 未运行"
        fi
        echo ""

        echo "请选择操作："
        echo "1. 完整SSH安全配置 (推荐新用户)"
        echo "2. SSH配置深度诊断"
        echo "3. 仅修改SSH端口"
        echo "4. 仅配置Root登录方式"
        echo "5. SSH密钥管理"
        echo "6. 查看当前SSH配置 (sshd -T)"
        echo "7. 处理云服务商配置冲突"
        echo "8. SSH服务管理"
        echo "0. 返回主菜单"
        echo ""

        local choice
        prompt_for_input "请选择 [0-8]: " choice validate_numeric_range 0 8

        case $choice in
            1)
                configure_ssh_securely
                ;;
            2)
                ssh_config_diagnosis
                ;;
            3)
                change_ssh_port_only
                ;;
            4)
                configure_root_login_only
                ;;
            5)
                ssh_key_management_menu
                ;;
            6)
                show_current_ssh_config
                ;;
            7)
                handle_cloud_config_conflicts
                ;;
            8)
                ssh_service_management
                ;;
            0)
                break
                ;;
        esac
    done
}

# 仅修改SSH端口
change_ssh_port_only() {
    clear
    echo -e "${pink}修改SSH端口${white}"
    echo "================================"

    local current_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' || echo "22")
    echo "当前SSH端口: $current_port"
    echo ""

    local new_port
    prompt_for_input "请输入新的SSH端口 (1024-65535): " new_port validate_port

    if [[ "$new_port" == "$current_port" ]]; then
        warn_msg "新端口与当前端口相同，无需修改"
        break_end
        return
    fi

    echo ""
    echo -e "${yellow}端口修改摘要:${white}"
    echo "  当前端口: $current_port"
    echo "  新端口: $new_port"
    echo ""

    if ! confirm_operation "修改SSH端口"; then
        info_msg "操作已取消"
        return
    fi

    # 创建或更新配置文件
    local config_file="/etc/ssh/sshd_config.d/99-security-hardening.conf"

    if [[ -f "$config_file" ]]; then
        # 更新现有配置文件中的端口
        backup_file "$config_file"
        sed -i "s/^Port .*/Port $new_port/" "$config_file"
        success_msg "已更新配置文件中的端口设置"
    else
        # 创建新的配置文件
        mkdir -p "$(dirname "$config_file")"
        echo "# SSH端口配置" > "$config_file"
        echo "Port $new_port" >> "$config_file"
        success_msg "已创建新的端口配置文件"
    fi

    # 验证配置
    if sshd -t; then
        success_msg "配置文件语法正确"

        if confirm_operation "重启SSH服务以应用新端口"; then
            manage_service restart sshd
            success_msg "SSH端口已修改为 $new_port"
            warn_msg "请使用新端口连接: ssh -p $new_port user@server"
        else
            info_msg "配置已保存，请手动重启SSH服务"
        fi
    else
        error_exit "配置文件语法错误，请检查"
    fi

    break_end
}

# 仅配置Root登录方式
configure_root_login_only() {
    clear
    echo -e "${pink}配置Root登录方式${white}"
    echo "================================"

    local current_root=$(sshd -T 2>/dev/null | grep -i '^permitrootlogin ' | awk '{print $2}' || echo "未知")
    echo "当前Root登录配置: $current_root"
    echo ""

    echo "Root登录方式选择:"
    echo "1. prohibit-password - 仅允许密钥登录 (推荐)"
    echo "2. no - 完全禁止Root登录"
    echo "3. yes - 允许密码登录 (不推荐)"
    echo ""

    local choice
    prompt_for_input "请选择 [1-3]: " choice validate_numeric_range 1 3

    local new_root_login
    case $choice in
        1) new_root_login="prohibit-password" ;;
        2) new_root_login="no" ;;
        3)
            warn_msg "允许Root密码登录存在安全风险"
            if ! confirm_operation "确认允许Root密码登录"; then
                info_msg "操作已取消"
                return
            fi
            new_root_login="yes"
            ;;
    esac

    if [[ "$new_root_login" == "$current_root" ]]; then
        warn_msg "新配置与当前配置相同，无需修改"
        break_end
        return
    fi

    echo ""
    echo -e "${yellow}Root登录配置摘要:${white}"
    echo "  当前配置: $current_root"
    echo "  新配置: $new_root_login"
    echo ""

    if ! confirm_operation "修改Root登录配置"; then
        info_msg "操作已取消"
        return
    fi

    # 更新配置文件
    local config_file="/etc/ssh/sshd_config.d/99-security-hardening.conf"

    if [[ -f "$config_file" ]]; then
        backup_file "$config_file"
        if grep -q "^PermitRootLogin" "$config_file"; then
            sed -i "s/^PermitRootLogin .*/PermitRootLogin $new_root_login/" "$config_file"
        else
            echo "PermitRootLogin $new_root_login" >> "$config_file"
        fi
    else
        mkdir -p "$(dirname "$config_file")"
        echo "# Root登录配置" > "$config_file"
        echo "PermitRootLogin $new_root_login" >> "$config_file"
    fi

    # 验证并重启
    if sshd -t; then
        success_msg "配置文件语法正确"

        if confirm_operation "重启SSH服务以应用新配置"; then
            manage_service restart sshd
            success_msg "Root登录配置已修改为: $new_root_login"
        else
            info_msg "配置已保存，请手动重启SSH服务"
        fi
    else
        error_exit "配置文件语法错误，请检查"
    fi

    break_end
}

# 显示当前SSH配置
show_current_ssh_config() {
    clear
    echo -e "${pink}当前SSH配置 (sshd -T)${white}"
    echo "================================"
    echo "参考: https://linux.do/t/topic/267502"
    echo ""

    if ! command -v sshd >/dev/null 2>&1; then
        error_exit "sshd 命令不可用"
    fi

    echo -e "${cyan}正在获取SSH有效配置...${white}"
    echo ""

    # 获取并显示关键配置项
    local effective_config
    if effective_config=$(sshd -T 2>/dev/null); then
        echo -e "${cyan}关键安全配置项:${white}"
        echo "================================"

        local key_configs=(
            "Port"
            "PermitRootLogin"
            "PasswordAuthentication"
            "PubkeyAuthentication"
            "X11Forwarding"
            "UseDNS"
            "ClientAliveInterval"
            "ClientAliveCountMax"
            "MaxAuthTries"
            "LoginGraceTime"
            "MaxStartups"
            "MaxSessions"
            "LogLevel"
            "SyslogFacility"
        )

        for config in "${key_configs[@]}"; do
            local value=$(echo "$effective_config" | grep -i "^$config " | awk '{print $2}' 2>/dev/null || echo "未设置")
            printf "  %-20s: %s\n" "$config" "$value"
        done

        echo ""
        echo -e "${cyan}配置文件来源:${white}"
        echo "================================"
        echo "主配置文件: /etc/ssh/sshd_config"
        if [[ -d "/etc/ssh/sshd_config.d" ]]; then
            echo "自定义配置目录: /etc/ssh/sshd_config.d/"
            find /etc/ssh/sshd_config.d -name "*.conf" 2>/dev/null | while read -r file; do
                echo "  - $(basename "$file")"
            done
        fi

        echo ""
        echo -e "${yellow}提示:${white}"
        echo "• 配置优先级: sshd_config.d/*.conf > sshd_config"
        echo "• 验证语法: sudo sshd -t"
        echo "• 重启服务: sudo systemctl restart sshd"

    else
        error_exit "无法获取SSH配置，请检查sshd服务状态"
    fi

    break_end
}

# 处理云服务商配置冲突
handle_cloud_config_conflicts() {
    clear
    echo -e "${pink}处理云服务商配置冲突${white}"
    echo "================================"
    echo "参考: https://linux.do/t/topic/267502"
    echo "参考: https://unix.stackexchange.com/questions/727492/"
    echo ""

    check_cloud_ssh_configs

    break_end
}

# SSH服务管理
ssh_service_management() {
    clear
    echo -e "${pink}SSH服务管理${white}"
    echo "================================"

    # 显示服务状态
    echo -e "${cyan}SSH服务状态:${white}"
    if systemctl is-active sshd >/dev/null 2>&1; then
        echo "  sshd: 运行中"
    elif systemctl is-active ssh >/dev/null 2>&1; then
        echo "  ssh: 运行中"
    else
        echo "  SSH服务: 未运行"
    fi

    echo ""
    echo "服务管理选项:"
    echo "1. 启动SSH服务"
    echo "2. 停止SSH服务"
    echo "3. 重启SSH服务"
    echo "4. 查看SSH服务状态"
    echo "5. 查看SSH日志"
    echo "0. 返回"
    echo ""

    local choice
    prompt_for_input "请选择 [0-5]: " choice validate_numeric_range 0 5

    case $choice in
        1)
            info_msg "启动SSH服务..."
            if manage_service start sshd || manage_service start ssh; then
                success_msg "SSH服务启动成功"
            else
                error_msg "SSH服务启动失败"
            fi
            ;;
        2)
            warn_msg "停止SSH服务将断开所有SSH连接"
            if confirm_operation "停止SSH服务"; then
                manage_service stop sshd || manage_service stop ssh
                warn_msg "SSH服务已停止"
            fi
            ;;
        3)
            info_msg "重启SSH服务..."
            if sshd -t; then
                if manage_service restart sshd || manage_service restart ssh; then
                    success_msg "SSH服务重启成功"
                else
                    error_msg "SSH服务重启失败"
                fi
            else
                error_msg "配置文件有语法错误，取消重启"
            fi
            ;;
        4)
            echo ""
            echo -e "${cyan}SSH服务详细状态:${white}"
            systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null || echo "SSH服务状态未知"
            ;;
        5)
            echo ""
            echo -e "${cyan}SSH服务日志 (最近20行):${white}"
            journalctl -u sshd -n 20 --no-pager 2>/dev/null || journalctl -u ssh -n 20 --no-pager 2>/dev/null || echo "无法获取SSH日志"
            ;;
        0)
            return
            ;;
    esac

    break_end
}

# 完整的SSH安全配置 (保持兼容性)
configure_ssh_security() {
    configure_ssh_securely
}
#endregion

#region //防火墙配置模块
# 检测防火墙类型
detect_firewall_type() {
    if command_exists ufw; then
        echo "ufw"
    elif command_exists iptables; then
        echo "iptables"
    else
        echo "none"
    fi
}

# 安装防火墙工具
install_firewall() {
    local fw_type="$1"

    case $fw_type in
        ufw)
            install_package ufw true
            ;;
        iptables)
            case $PKG_MANAGER in
                apt)
                    install_package iptables-persistent true
                    ;;
                yum|dnf)
                    install_package iptables-services true
                    ;;
            esac
            ;;
    esac
}

# UFW防火墙配置
configure_ufw() {
    info_msg "配置UFW防火墙..."

    # 重置UFW规则
    ufw --force reset > /dev/null 2>&1

    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing

    # 获取SSH端口
    local ssh_port=$(sshd -T | grep -i "^port " | awk '{print $2}' 2>/dev/null || echo "22")

    # 允许SSH
    ufw allow "$ssh_port"/tcp comment 'SSH'

    # 允许HTTP/HTTPS
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'

    # 允许常用代理端口
    ufw allow 8080/tcp comment 'Proxy'
    ufw allow 8443/tcp comment 'Proxy HTTPS'

    # IPv6支持
    if [[ "$IPV6_ADDRESS" != "不支持" && "$IPV6_ADDRESS" != "" ]]; then
        sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
    fi

    # 启用UFW
    ufw --force enable

    success_msg "UFW防火墙配置完成"
}

# iptables防火墙配置
configure_iptables() {
    info_msg "配置iptables防火墙..."

    # 清空现有规则
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    # 设置默认策略
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # 允许本地回环
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # 允许已建立的连接
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # 获取SSH端口
    local ssh_port=$(sshd -T | grep -i "^port " | awk '{print $2}' 2>/dev/null || echo "22")

    # 允许SSH
    iptables -A INPUT -p tcp --dport "$ssh_port" -j ACCEPT

    # 允许HTTP/HTTPS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # 允许代理端口
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

    # DDoS防护规则
    iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

    # 防止SYN洪水攻击
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP

    # 防止端口扫描
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A INPUT -m recent --name portscan --remove
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
    iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

    # IPv6规则（如果支持）
    if [[ "$IPV6_ADDRESS" != "不支持" && "$IPV6_ADDRESS" != "" ]] && command_exists ip6tables; then
        ip6tables -F
        ip6tables -P INPUT DROP
        ip6tables -P FORWARD DROP
        ip6tables -P OUTPUT ACCEPT

        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        ip6tables -A INPUT -p tcp --dport "$ssh_port" -j ACCEPT
        ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
        ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
    fi

    # 保存规则
    case $PKG_MANAGER in
        apt)
            iptables-save > /etc/iptables/rules.v4
            if command_exists ip6tables; then
                ip6tables-save > /etc/iptables/rules.v6
            fi
            ;;
        yum|dnf)
            service iptables save
            if command_exists ip6tables; then
                service ip6tables save
            fi
            ;;
    esac

    success_msg "iptables防火墙配置完成"
}

# 显示防火墙状态
show_firewall_status() {
    local fw_type=$(detect_firewall_type)

    echo -e "${cyan}防火墙状态:${white}"

    case $fw_type in
        ufw)
            ufw status verbose
            ;;
        iptables)
            iptables -L -n --line-numbers
            ;;
        none)
            echo "未检测到防火墙"
            ;;
    esac
}

# 完整的防火墙配置
configure_firewall() {
    clear
    echo -e "${pink}防火墙配置${white}"
    echo "================================"

    local fw_type=$(detect_firewall_type)

    echo "检测到的防火墙类型: $fw_type"
    echo ""

    if [[ "$fw_type" == "none" ]]; then
        echo "未检测到防火墙，将安装UFW"
        fw_type="ufw"
        install_firewall ufw
    fi

    echo "将配置以下防火墙规则："
    echo "1. 默认拒绝所有入站连接"
    echo "2. 允许SSH端口 ($(grep -E "^Port " "$SSH_CONFIG" | awk '{print $2}' 2>/dev/null || echo "22"))"
    echo "3. 允许HTTP (80) 和HTTPS (443)"
    echo "4. 允许代理端口 (8080, 8443)"
    echo "5. 配置DDoS防护规则"
    if [[ "$IPV6_ADDRESS" != "不支持" && "$IPV6_ADDRESS" != "" ]]; then
        echo "6. 启用IPv6支持"
    fi
    echo ""

    if ! confirm_operation "防火墙配置"; then
        info_msg "操作已取消"
        return
    fi

    # 执行配置
    case $fw_type in
        ufw)
            show_progress 1 3 "配置UFW防火墙"
            configure_ufw
            ;;
        iptables)
            show_progress 1 3 "配置iptables防火墙"
            configure_iptables
            ;;
    esac

    show_progress 2 3 "启用防火墙服务"
    case $fw_type in
        ufw)
            manage_service enable ufw
            ;;
        iptables)
            manage_service enable iptables
            if command_exists ip6tables; then
                manage_service enable ip6tables
            fi
            ;;
    esac

    show_progress 3 3 "配置完成"

    echo ""
    success_msg "防火墙配置完成！"
    echo ""
    show_firewall_status
    echo ""

    break_end
}
#endregion

#region //系统优化模块
# 检查当前内核版本
check_kernel_version() {
    local kernel_version=$(uname -r)
    local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)

    echo "当前内核版本: $kernel_version"

    # 检查是否支持BBR
    if [[ $kernel_major -gt 4 ]] || [[ $kernel_major -eq 4 && $kernel_minor -ge 9 ]]; then
        echo "内核版本支持BBR"
        return 0
    else
        echo "内核版本过低，不支持BBR"
        return 1
    fi
}

# 启用BBR拥塞控制
enable_bbr() {
    info_msg "启用BBR拥塞控制算法..."

    # 检查当前拥塞控制算法
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    echo "当前拥塞控制算法: $current_cc"

    if [[ "$current_cc" == "bbr" ]]; then
        success_msg "BBR已经启用"
        return
    fi

    # 检查内核是否支持BBR
    if ! check_kernel_version; then
        warn_msg "内核版本不支持BBR，跳过配置"
        return
    fi

    # 备份当前配置
    backup_file /etc/sysctl.conf

    # 配置BBR
    # 使用辅助函数安全地追加配置
    append_if_not_exists "net.core.default_qdisc = fq" /etc/sysctl.conf
    append_if_not_exists "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf

    # 应用配置
    sysctl -p > /dev/null 2>&1

    # 验证配置
    local new_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ "$new_cc" == "bbr" ]]; then
        success_msg "BBR拥塞控制算法已启用"
    else
        warn_msg "BBR启用可能需要重启系统后生效"
    fi
}

# 优化网络参数
optimize_network_parameters() {
    info_msg "优化网络参数..."

    # 备份配置
    backup_file /etc/sysctl.conf

    # 网络优化参数
    # 使用辅助函数安全地追加网络优化参数
    append_if_not_exists "# 网络性能优化参数" /etc/sysctl.conf
    append_if_not_exists "# TCP接收缓冲区" /etc/sysctl.conf
    append_if_not_exists "net.core.rmem_default = 262144" /etc/sysctl.conf
    append_if_not_exists "net.core.rmem_max = 16777216" /etc/sysctl.conf
    append_if_not_exists "net.core.netdev_max_backlog = 5000" /etc/sysctl.conf

    cat >> /etc/sysctl.conf << EOF

# TCP发送缓冲区
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

# TCP缓冲区自动调整
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP连接优化
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000

# TCP窗口缩放
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# 防止SYN攻击
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# 文件描述符限制
fs.file-max = 1000000
EOF

    # 应用配置
    sysctl -p > /dev/null 2>&1

    success_msg "网络参数优化完成"
}

# 优化文件描述符限制
optimize_file_limits() {
    info_msg "优化文件描述符限制..."

    # 备份配置
    backup_file /etc/security/limits.conf

    # 设置文件描述符限制
    cat >> /etc/security/limits.conf << EOF

# 文件描述符限制优化
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
root soft nofile 1000000
root hard nofile 1000000
root soft nproc 1000000
root hard nproc 1000000
EOF

    # 设置systemd服务限制
    if [[ -d /etc/systemd/system.conf.d ]]; then
        mkdir -p /etc/systemd/system.conf.d
    fi

    cat > /etc/systemd/system.conf.d/limits.conf << EOF
[Manager]
DefaultLimitNOFILE=1000000
DefaultLimitNPROC=1000000
EOF

    success_msg "文件描述符限制优化完成"
}

# 配置SWAP
configure_swap() {
    info_msg "配置SWAP虚拟内存..."

    # 检查是否为OpenVZ
    if [[ -d "/proc/vz" ]]; then
        warn_msg "OpenVZ环境不支持SWAP配置"
        return
    fi

    # 获取物理内存大小(MB)
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local swap_size=$((mem_total * 2))  # 设置为内存的2倍

    # 检查现有SWAP
    local current_swap=$(free -m | awk '/^Swap:/{print $2}')

    if [[ $current_swap -gt 0 ]]; then
        echo "当前SWAP大小: ${current_swap}MB"
        read -p "是否重新配置SWAP？(y/N): " reconfigure
        if [[ ! "$reconfigure" =~ ^[Yy]$ ]]; then
            return
        fi

        # 关闭现有SWAP
        swapoff -a
        sed -i '/swapfile/d' /etc/fstab
        rm -f /swapfile
    fi

    echo "将创建 ${swap_size}MB 的SWAP文件"

    # 创建SWAP文件
    fallocate -l ${swap_size}M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    # 添加到fstab
    echo '/swapfile none swap defaults 0 0' >> /etc/fstab

    # 优化SWAP使用策略
    echo 'vm.swappiness=10' >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1

    success_msg "SWAP配置完成: ${swap_size}MB"
}

# 系统清理
system_cleanup() {
    info_msg "执行系统清理..."

    # 清理包缓存
    case $PKG_MANAGER in
        apt)
            apt-get autoremove -y > /dev/null 2>&1
            apt-get autoclean > /dev/null 2>&1
            ;;
        yum)
            yum autoremove -y > /dev/null 2>&1
            yum clean all > /dev/null 2>&1
            ;;
        dnf)
            dnf autoremove -y > /dev/null 2>&1
            dnf clean all > /dev/null 2>&1
            ;;
    esac

    # 清理日志文件
    find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null

    # 清理临时文件
    find /tmp -type f -mtime +1 -delete 2>/dev/null
    find /var/tmp -type f -mtime +1 -delete 2>/dev/null

    # 清理缓存目录
    find /root/.cache -type f -delete 2>/dev/null

    success_msg "系统清理完成"
}

# 完整的系统优化
system_optimization() {
    clear
    echo -e "${pink}系统优化配置${white}"
    echo "================================"

    echo "将执行以下优化操作："
    echo "1. 启用BBR拥塞控制算法"
    echo "2. 优化网络参数"
    echo "3. 优化文件描述符限制"
    echo "4. 配置SWAP虚拟内存"
    echo "5. 系统清理"
    echo ""

    if ! confirm_operation "系统优化"; then
        info_msg "操作已取消"
        return
    fi

    # 执行优化步骤
    show_progress 1 5 "启用BBR拥塞控制"
    enable_bbr

    show_progress 2 5 "优化网络参数"
    optimize_network_parameters

    show_progress 3 5 "优化文件描述符限制"
    optimize_file_limits

    show_progress 4 5 "配置SWAP虚拟内存"
    configure_swap

    show_progress 5 5 "系统清理"
    system_cleanup

    echo ""
    success_msg "系统优化完成！"
    echo -e "${yellow}注意：${white}"
    echo "1. 部分优化需要重启系统后生效"
    echo "2. BBR拥塞控制算法已配置"
    echo "3. 网络和文件系统参数已优化"
    echo "4. SWAP虚拟内存已配置"
    echo ""

    break_end
}
#endregion

#region //系统清理模块
# 清理系统日志
clean_system_logs() {
    info_msg "清理系统日志..."

    local cleaned_size=0

    # 清理journal日志（保留最近7天）
    if command_exists journalctl; then
        local before_size=$(du -sm /var/log/journal 2>/dev/null | awk '{print $1}' || echo "0")
        journalctl --vacuum-time=7d >/dev/null 2>&1
        local after_size=$(du -sm /var/log/journal 2>/dev/null | awk '{print $1}' || echo "0")
        cleaned_size=$((cleaned_size + before_size - after_size))
        echo "  - journal日志: 清理了 $((before_size - after_size))MB"
    fi

    # 清理旧的日志文件
    if [[ -d /var/log ]]; then
        find /var/log -name "*.log.*" -mtime +7 -delete 2>/dev/null
        find /var/log -name "*.gz" -mtime +7 -delete 2>/dev/null
        echo "  - 旧日志文件: 已清理7天前的压缩日志"
    fi

    # 清理wtmp和btmp日志
    if [[ -f /var/log/wtmp ]]; then
        local wtmp_size=$(du -sm /var/log/wtmp 2>/dev/null | awk '{print $1}' || echo "0")
        > /var/log/wtmp
        cleaned_size=$((cleaned_size + wtmp_size))
        echo "  - wtmp日志: 清理了 ${wtmp_size}MB"
    fi

    if [[ -f /var/log/btmp ]]; then
        local btmp_size=$(du -sm /var/log/btmp 2>/dev/null | awk '{print $1}' || echo "0")
        > /var/log/btmp
        cleaned_size=$((cleaned_size + btmp_size))
        echo "  - btmp日志: 清理了 ${btmp_size}MB"
    fi

    success_msg "系统日志清理完成，共清理 ${cleaned_size}MB"
}

# 清理包管理器缓存
clean_package_cache() {
    info_msg "清理包管理器缓存..."

    local cleaned_size=0

    case $PKG_MANAGER in
        apt)
            # 清理apt缓存
            local before_size=$(du -sm /var/cache/apt 2>/dev/null | awk '{print $1}' || echo "0")
            apt-get clean >/dev/null 2>&1
            apt-get autoclean >/dev/null 2>&1
            local after_size=$(du -sm /var/cache/apt 2>/dev/null | awk '{print $1}' || echo "0")
            cleaned_size=$((before_size - after_size))
            echo "  - APT缓存: 清理了 ${cleaned_size}MB"

            # 清理孤立包
            local orphaned=$(apt-get autoremove --dry-run 2>/dev/null | grep -c "^Remv" || echo "0")
            if [[ $orphaned -gt 0 ]]; then
                apt-get autoremove -y >/dev/null 2>&1
                echo "  - 孤立包: 清理了 $orphaned 个包"
            fi
            ;;
        yum)
            # 清理yum缓存
            local before_size=$(du -sm /var/cache/yum 2>/dev/null | awk '{print $1}' || echo "0")
            yum clean all >/dev/null 2>&1
            local after_size=$(du -sm /var/cache/yum 2>/dev/null | awk '{print $1}' || echo "0")
            cleaned_size=$((before_size - after_size))
            echo "  - YUM缓存: 清理了 ${cleaned_size}MB"
            ;;
        dnf)
            # 清理dnf缓存
            local before_size=$(du -sm /var/cache/dnf 2>/dev/null | awk '{print $1}' || echo "0")
            dnf clean all >/dev/null 2>&1
            local after_size=$(du -sm /var/cache/dnf 2>/dev/null | awk '{print $1}' || echo "0")
            cleaned_size=$((before_size - after_size))
            echo "  - DNF缓存: 清理了 ${cleaned_size}MB"
            ;;
    esac

    success_msg "包管理器缓存清理完成"
}

# 清理临时文件
clean_temp_files() {
    info_msg "清理临时文件..."

    local cleaned_size=0

    # 清理/tmp目录（保留最近1天的文件）
    if [[ -d /tmp ]]; then
        local before_size=$(du -sm /tmp 2>/dev/null | awk '{print $1}' || echo "0")
        find /tmp -type f -mtime +1 -delete 2>/dev/null
        find /tmp -type d -empty -delete 2>/dev/null
        local after_size=$(du -sm /tmp 2>/dev/null | awk '{print $1}' || echo "0")
        cleaned_size=$((cleaned_size + before_size - after_size))
        echo "  - /tmp目录: 清理了 $((before_size - after_size))MB"
    fi

    # 清理/var/tmp目录（保留最近3天的文件）
    if [[ -d /var/tmp ]]; then
        local before_size=$(du -sm /var/tmp 2>/dev/null | awk '{print $1}' || echo "0")
        find /var/tmp -type f -mtime +3 -delete 2>/dev/null
        find /var/tmp -type d -empty -delete 2>/dev/null
        local after_size=$(du -sm /var/tmp 2>/dev/null | awk '{print $1}' || echo "0")
        cleaned_size=$((cleaned_size + before_size - after_size))
        echo "  - /var/tmp目录: 清理了 $((before_size - after_size))MB"
    fi

    # 清理用户临时文件
    for user_home in /home/*; do
        if [[ -d "$user_home/.cache" ]]; then
            local cache_size=$(du -sm "$user_home/.cache" 2>/dev/null | awk '{print $1}' || echo "0")
            if [[ $cache_size -gt 100 ]]; then
                find "$user_home/.cache" -type f -mtime +7 -delete 2>/dev/null
                echo "  - 用户缓存 $(basename "$user_home"): 清理了部分缓存文件"
            fi
        fi
    done

    success_msg "临时文件清理完成"
}

# 清理内核文件
clean_old_kernels() {
    info_msg "清理旧内核文件..."

    case $PKG_MANAGER in
        apt)
            # 获取当前内核版本
            local current_kernel=$(uname -r)
            echo "  当前内核版本: $current_kernel"

            # 列出已安装的内核
            local installed_kernels=$(dpkg -l | grep -E "linux-image-[0-9]" | awk '{print $2}' | grep -v "$current_kernel" | head -5)

            if [[ -n "$installed_kernels" ]]; then
                echo "  发现旧内核版本:"
                echo "$installed_kernels" | while read kernel; do
                    echo "    - $kernel"
                done

                # 只保留当前内核和最新的一个旧内核
                local kernels_to_remove=$(echo "$installed_kernels" | tail -n +2)
                if [[ -n "$kernels_to_remove" ]]; then
                    echo "$kernels_to_remove" | xargs apt-get remove -y >/dev/null 2>&1
                    echo "  - 已清理多余的旧内核"
                fi
            else
                echo "  - 没有发现需要清理的旧内核"
            fi
            ;;
        yum|dnf)
            # CentOS/RHEL系统
            local installed_count=$(rpm -q kernel | wc -l)
            if [[ $installed_count -gt 2 ]]; then
                package-cleanup --oldkernels --count=2 -y >/dev/null 2>&1 || echo "  - 旧内核清理工具不可用"
            else
                echo "  - 内核数量正常，无需清理"
            fi
            ;;
    esac

    success_msg "内核文件清理完成"
}

# 清理系统垃圾文件
clean_system_junk() {
    info_msg "清理系统垃圾文件..."

    local cleaned_files=0

    # 清理core dump文件
    local core_files=$(find /var/crash /tmp /var/tmp -name "core.*" -o -name "*.core" 2>/dev/null | wc -l)
    if [[ $core_files -gt 0 ]]; then
        find /var/crash /tmp /var/tmp -name "core.*" -o -name "*.core" -delete 2>/dev/null
        cleaned_files=$((cleaned_files + core_files))
        echo "  - Core dump文件: 清理了 $core_files 个文件"
    fi

    # 清理.swp和.tmp文件
    local swap_files=$(find /tmp /var/tmp -name "*.swp" -o -name "*.tmp" 2>/dev/null | wc -l)
    if [[ $swap_files -gt 0 ]]; then
        find /tmp /var/tmp -name "*.swp" -o -name "*.tmp" -delete 2>/dev/null
        cleaned_files=$((cleaned_files + swap_files))
        echo "  - 交换和临时文件: 清理了 $swap_files 个文件"
    fi

    # 清理旧的备份文件
    local backup_files=$(find /etc /home -name "*.bak" -o -name "*.backup" -o -name "*~" -mtime +30 2>/dev/null | wc -l)
    if [[ $backup_files -gt 0 ]]; then
        find /etc /home -name "*.bak" -o -name "*.backup" -o -name "*~" -mtime +30 -delete 2>/dev/null
        cleaned_files=$((cleaned_files + backup_files))
        echo "  - 旧备份文件: 清理了 $backup_files 个文件"
    fi

    # 清理空目录
    local empty_dirs=$(find /tmp /var/tmp -type d -empty 2>/dev/null | wc -l)
    if [[ $empty_dirs -gt 0 ]]; then
        find /tmp /var/tmp -type d -empty -delete 2>/dev/null
        echo "  - 空目录: 清理了 $empty_dirs 个目录"
    fi

    success_msg "系统垃圾文件清理完成，共清理 $cleaned_files 个文件"
}

# 系统清理主函数
system_cleanup() {
    clear
    echo -e "${pink}系统清理${white}"
    echo "================================"

    echo "系统清理将执行以下操作："
    echo "1. 清理系统日志文件"
    echo "2. 清理包管理器缓存"
    echo "3. 清理临时文件"
    echo "4. 清理旧内核文件"
    echo "5. 清理系统垃圾文件"
    echo ""

    echo -e "${yellow}注意：${white}"
    echo "- 清理操作不可逆，请确认继续"
    echo "- 建议在清理前创建系统快照"
    echo "- 清理过程中请勿中断操作"
    echo ""

    if ! confirm_operation "系统清理"; then
        info_msg "操作已取消"
        return
    fi

    # 显示清理前的磁盘使用情况
    echo -e "${cyan}清理前磁盘使用情况:${white}"
    df -h / | tail -1
    echo ""

    # 执行清理步骤
    show_progress 1 5 "清理系统日志"
    clean_system_logs

    show_progress 2 5 "清理包管理器缓存"
    clean_package_cache

    show_progress 3 5 "清理临时文件"
    clean_temp_files

    show_progress 4 5 "清理旧内核文件"
    clean_old_kernels

    show_progress 5 5 "清理系统垃圾文件"
    clean_system_junk

    echo ""

    # 显示清理后的磁盘使用情况
    echo -e "${cyan}清理后磁盘使用情况:${white}"
    df -h / | tail -1
    echo ""

    success_msg "系统清理完成！"

    echo -e "${yellow}建议：${white}"
    echo "1. 定期执行系统清理以保持系统性能"
    echo "2. 监控磁盘使用情况"
    echo "3. 及时清理不需要的文件"
    echo "4. 考虑设置自动清理任务"
    echo ""

    break_end
}
#endregion

#region //用户权限管理模块
# 创建新用户
create_new_user() {
    local username="$1"
    local create_home="${2:-true}"

    info_msg "创建用户: $username"

    # 检查用户是否已存在
    if id "$username" &>/dev/null; then
        warn_msg "用户 $username 已存在"
        return 1
    fi

    # 创建用户
    if [[ "$create_home" == "true" ]]; then
        useradd -m -s /bin/bash "$username"
    else
        useradd -s /bin/bash "$username"
    fi

    if [[ $? -eq 0 ]]; then
        success_msg "用户 $username 创建成功"
        return 0
    else
        error_exit "用户 $username 创建失败"
    fi
}

# 设置用户密码
set_user_password() {
    local username="$1"

    info_msg "为用户 $username 设置密码"

    # 检查用户是否存在
    if ! id "$username" &>/dev/null; then
        error_exit "用户 $username 不存在"
    fi

    echo "请为用户 $username 设置密码:"
    passwd "$username"
}

# 配置用户sudo权限
configure_user_sudo() {
    local username="$1"
    local sudo_type="${2:-limited}"  # limited, full, none

    info_msg "配置用户 $username 的sudo权限"

    # 检查用户是否存在
    if ! id "$username" &>/dev/null; then
        error_exit "用户 $username 不存在"
    fi

    local sudoers_file="/etc/sudoers.d/$username"

    case "$sudo_type" in
        "full")
            echo "$username ALL=(ALL:ALL) ALL" > "$sudoers_file"
            success_msg "已授予用户 $username 完整sudo权限"
            ;;
        "limited")
            cat > "$sudoers_file" << EOF
# 限制sudo权限 - 仅允许基本系统管理命令
$username ALL=(ALL) NOPASSWD: /bin/systemctl restart *, /bin/systemctl start *, /bin/systemctl stop *, /bin/systemctl status *
$username ALL=(ALL) NOPASSWD: /usr/bin/apt update, /usr/bin/apt upgrade, /usr/bin/yum update
$username ALL=(ALL) NOPASSWD: /bin/mount, /bin/umount
$username ALL=(ALL) NOPASSWD: /usr/bin/tail /var/log/*, /usr/bin/less /var/log/*
$username ALL=(ALL) NOPASSWD: /bin/netstat, /bin/ss, /usr/bin/lsof
EOF
            success_msg "已授予用户 $username 有限sudo权限"
            ;;
        "none")
            if [[ -f "$sudoers_file" ]]; then
                rm -f "$sudoers_file"
            fi
            success_msg "已移除用户 $username 的sudo权限"
            ;;
        *)
            error_exit "无效的sudo权限类型: $sudo_type"
            ;;
    esac

    # 验证sudoers文件语法
    if [[ -f "$sudoers_file" ]]; then
        if ! visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            rm -f "$sudoers_file"
            error_exit "sudoers文件语法错误，已删除"
        fi
    fi
}

# 配置用户SSH密钥
setup_user_ssh_key() {
    local username="$1"
    local public_key="$2"

    info_msg "为用户 $username 配置SSH密钥"

    # 检查用户是否存在
    if ! id "$username" &>/dev/null; then
        error_exit "用户 $username 不存在"
    fi

    local user_home=$(getent passwd "$username" | cut -d: -f6)
    local ssh_dir="$user_home/.ssh"
    local authorized_keys="$ssh_dir/authorized_keys"

    # 创建.ssh目录
    sudo -u "$username" mkdir -p "$ssh_dir"
    sudo -u "$username" chmod 700 "$ssh_dir"

    if [[ -n "$public_key" ]]; then
        # 使用提供的公钥
        echo "$public_key" | sudo -u "$username" tee "$authorized_keys" > /dev/null
    else
        # 生成新的密钥对
        sudo -u "$username" ssh-keygen -t rsa -b 4096 -f "$ssh_dir/id_rsa" -q -N ""
        sudo -u "$username" cp "$ssh_dir/id_rsa.pub" "$authorized_keys"

        echo -e "${yellow}SSH密钥已生成:${white}"
        echo "私钥: $ssh_dir/id_rsa"
        echo "公钥: $ssh_dir/id_rsa.pub"
    fi

    # 设置正确的权限
    sudo -u "$username" chmod 600 "$authorized_keys"

    success_msg "用户 $username 的SSH密钥配置完成"
}

# 删除用户
delete_user() {
    local username="$1"
    local remove_home="${2:-true}"

    info_msg "删除用户: $username"

    # 检查用户是否存在
    if ! id "$username" &>/dev/null; then
        warn_msg "用户 $username 不存在"
        return 1
    fi

    # 确认删除
    echo -e "${red}警告: 即将删除用户 $username${white}"
    if [[ "$remove_home" == "true" ]]; then
        echo "这将同时删除用户的主目录和所有文件"
    fi

    if ! confirm_operation "删除用户 $username"; then
        info_msg "操作已取消"
        return 1
    fi

    # 删除sudo权限文件
    local sudoers_file="/etc/sudoers.d/$username"
    if [[ -f "$sudoers_file" ]]; then
        rm -f "$sudoers_file"
    fi

    # 删除用户
    if [[ "$remove_home" == "true" ]]; then
        userdel -r "$username" 2>/dev/null
    else
        userdel "$username" 2>/dev/null
    fi

    if [[ $? -eq 0 ]]; then
        success_msg "用户 $username 删除成功"
    else
        error_exit "用户 $username 删除失败"
    fi
}

# 显示用户信息
show_user_info() {
    local username="$1"

    if [[ -n "$username" ]]; then
        # 显示特定用户信息
        if ! id "$username" &>/dev/null; then
            error_exit "用户 $username 不存在"
        fi

        echo -e "${cyan}用户 $username 详细信息:${white}"
        echo "================================"

        # 基本信息
        local user_info=$(getent passwd "$username")
        local uid=$(echo "$user_info" | cut -d: -f3)
        local gid=$(echo "$user_info" | cut -d: -f4)
        local home=$(echo "$user_info" | cut -d: -f6)
        local shell=$(echo "$user_info" | cut -d: -f7)

        echo "用户ID: $uid"
        echo "组ID: $gid"
        echo "主目录: $home"
        echo "Shell: $shell"

        # 组信息
        echo "所属组: $(groups "$username" | cut -d: -f2)"

        # sudo权限
        if [[ -f "/etc/sudoers.d/$username" ]]; then
            echo "sudo权限: 已配置"
        elif groups "$username" | grep -q sudo; then
            echo "sudo权限: 通过sudo组"
        else
            echo "sudo权限: 无"
        fi

        # SSH密钥
        if [[ -f "$home/.ssh/authorized_keys" ]]; then
            local key_count=$(wc -l < "$home/.ssh/authorized_keys" 2>/dev/null || echo "0")
            echo "SSH密钥: $key_count 个"
        else
            echo "SSH密钥: 未配置"
        fi

        # 最后登录
        local last_login=$(last -n 1 "$username" 2>/dev/null | head -1 | awk '{print $4, $5, $6, $7}')
        if [[ -n "$last_login" && "$last_login" != "wtmp begins" ]]; then
            echo "最后登录: $last_login"
        else
            echo "最后登录: 从未登录"
        fi

    else
        # 显示所有用户列表
        echo -e "${cyan}系统用户列表:${white}"
        echo "================================"

        # 普通用户 (UID >= 1000)
        echo -e "${yellow}普通用户:${white}"
        awk -F: '$3 >= 1000 && $3 < 65534 {printf "  %-15s (UID: %s)\n", $1, $3}' /etc/passwd

        echo ""
        echo -e "${yellow}系统用户:${white}"
        awk -F: '$3 < 1000 && $1 != "nobody" {printf "  %-15s (UID: %s)\n", $1, $3}' /etc/passwd | head -10

        echo ""
        echo -e "${yellow}具有sudo权限的用户:${white}"
        if command_exists getent; then
            getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sed 's/^/  /'
        fi

        # 检查sudoers.d目录中的用户
        if [[ -d "/etc/sudoers.d" ]]; then
            for file in /etc/sudoers.d/*; do
                if [[ -f "$file" && "$(basename "$file")" != "README" ]]; then
                    echo "  $(basename "$file") (通过sudoers.d)"
                fi
            done
        fi
    fi
}

# 用户权限管理主菜单
user_permission_management() {
    while true; do
        clear
        echo -e "${pink}用户权限管理${white}"
        echo "================================"

        # 显示当前用户概况
        echo -e "${cyan}当前用户概况:${white}"
        local normal_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | wc -l)
        local sudo_users=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | wc -l)
        echo "普通用户数量: $normal_users"
        echo "sudo用户数量: $sudo_users"
        echo ""

        echo "1. 创建新用户"
        echo "2. 删除用户"
        echo "3. 修改用户密码"
        echo "4. 配置sudo权限"
        echo "5. 配置SSH密钥"
        echo "6. 查看用户信息"
        echo "7. 用户安全审计"
        echo "================================"
        echo "0. 返回主菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择操作 [0-7]: " choice validate_numeric_range 0 7

        case $choice in
            1) create_user_interactive ;;
            2) delete_user_interactive ;;
            3) change_user_password_interactive ;;
            4) configure_sudo_interactive ;;
            5) configure_ssh_key_interactive ;;
            6) show_user_info_interactive ;;
            7) user_security_audit ;;
            0) break ;;
        esac
    done
}

# 交互式创建用户
create_user_interactive() {
    clear
    echo -e "${pink}创建新用户${white}"
    echo "================================"

    local username
    while true; do
        prompt_for_input "请输入用户名: " username

        # 验证用户名格式
        if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
            warn_msg "用户名格式无效。用户名必须以小写字母开头，只能包含小写字母、数字、下划线和连字符"
            continue
        fi

        # 检查用户名长度
        if [[ ${#username} -lt 3 || ${#username} -gt 32 ]]; then
            warn_msg "用户名长度必须在3-32个字符之间"
            continue
        fi

        # 检查用户是否已存在
        if id "$username" &>/dev/null; then
            warn_msg "用户 $username 已存在，请选择其他用户名"
            continue
        fi

        break
    done

    echo ""
    echo -e "${cyan}用户配置选项:${white}"
    echo "1. 创建主目录: 是"
    echo "2. 默认Shell: /bin/bash"
    echo ""

    if confirm_operation "创建用户 $username"; then
        create_new_user "$username" "true"

        echo ""
        if confirm_operation "是否立即设置密码"; then
            set_user_password "$username"
        fi

        echo ""
        if confirm_operation "是否配置sudo权限"; then
            echo "请选择sudo权限类型:"
            echo "1. 有限权限 (推荐)"
            echo "2. 完整权限"
            echo "3. 无权限"

            local sudo_choice
            prompt_for_input "请选择 [1-3]: " sudo_choice validate_numeric_range 1 3

            case $sudo_choice in
                1) configure_user_sudo "$username" "limited" ;;
                2) configure_user_sudo "$username" "full" ;;
                3) configure_user_sudo "$username" "none" ;;
            esac
        fi

        echo ""
        if confirm_operation "是否配置SSH密钥"; then
            setup_user_ssh_key "$username"
        fi

        echo ""
        success_msg "用户 $username 创建完成！"
        show_user_info "$username"
    fi

    break_end
}

# 交互式删除用户
delete_user_interactive() {
    clear
    echo -e "${pink}删除用户${white}"
    echo "================================"

    # 显示可删除的用户列表
    echo -e "${cyan}可删除的用户列表:${white}"
    local users=($(awk -F: '$3 >= 1000 && $3 < 65534 && $1 != "nobody" {print $1}' /etc/passwd))

    if [[ ${#users[@]} -eq 0 ]]; then
        warn_msg "没有可删除的普通用户"
        break_end
        return
    fi

    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[i]}"
    done
    echo ""

    local choice
    prompt_for_input "请选择要删除的用户编号 [1-${#users[@]}]: " choice validate_numeric_range 1 ${#users[@]}

    local username="${users[$((choice-1))]}"

    echo ""
    echo -e "${yellow}用户信息:${white}"
    show_user_info "$username"
    echo ""

    local remove_home="true"
    if confirm_operation "是否同时删除用户主目录"; then
        remove_home="true"
    else
        remove_home="false"
    fi

    delete_user "$username" "$remove_home"

    break_end
}

# 交互式修改用户密码
change_user_password_interactive() {
    clear
    echo -e "${pink}修改用户密码${white}"
    echo "================================"

    # 显示用户列表
    echo -e "${cyan}用户列表:${white}"
    local users=($(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd))

    if [[ ${#users[@]} -eq 0 ]]; then
        warn_msg "没有普通用户"
        break_end
        return
    fi

    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[i]}"
    done
    echo ""

    local choice
    prompt_for_input "请选择用户编号 [1-${#users[@]}]: " choice validate_numeric_range 1 ${#users[@]}

    local username="${users[$((choice-1))]}"

    set_user_password "$username"

    break_end
}

# 交互式配置sudo权限
configure_sudo_interactive() {
    clear
    echo -e "${pink}配置sudo权限${white}"
    echo "================================"

    # 显示用户列表
    echo -e "${cyan}用户列表:${white}"
    local users=($(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd))

    if [[ ${#users[@]} -eq 0 ]]; then
        warn_msg "没有普通用户"
        break_end
        return
    fi

    for i in "${!users[@]}"; do
        local username="${users[i]}"
        local sudo_status="无"

        if [[ -f "/etc/sudoers.d/$username" ]]; then
            sudo_status="已配置"
        elif groups "$username" | grep -q sudo; then
            sudo_status="sudo组"
        fi

        echo "$((i+1)). $username ($sudo_status)"
    done
    echo ""

    local choice
    prompt_for_input "请选择用户编号 [1-${#users[@]}]: " choice validate_numeric_range 1 ${#users[@]}

    local username="${users[$((choice-1))]}"

    echo ""
    echo -e "${cyan}sudo权限类型:${white}"
    echo "1. 有限权限 (推荐) - 仅允许基本系统管理命令"
    echo "2. 完整权限 - 允许所有sudo命令"
    echo "3. 移除权限 - 移除所有sudo权限"
    echo ""

    local sudo_choice
    prompt_for_input "请选择权限类型 [1-3]: " sudo_choice validate_numeric_range 1 3

    case $sudo_choice in
        1) configure_user_sudo "$username" "limited" ;;
        2) configure_user_sudo "$username" "full" ;;
        3) configure_user_sudo "$username" "none" ;;
    esac

    break_end
}

# 交互式配置SSH密钥
configure_ssh_key_interactive() {
    clear
    echo -e "${pink}配置SSH密钥${white}"
    echo "================================"

    # 显示用户列表
    echo -e "${cyan}用户列表:${white}"
    local users=($(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd))

    if [[ ${#users[@]} -eq 0 ]]; then
        warn_msg "没有普通用户"
        break_end
        return
    fi

    for i in "${!users[@]}"; do
        local username="${users[i]}"
        local user_home=$(getent passwd "$username" | cut -d: -f6)
        local key_status="未配置"

        if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
            local key_count=$(wc -l < "$user_home/.ssh/authorized_keys" 2>/dev/null || echo "0")
            key_status="$key_count 个密钥"
        fi

        echo "$((i+1)). $username ($key_status)"
    done
    echo ""

    local choice
    prompt_for_input "请选择用户编号 [1-${#users[@]}]: " choice validate_numeric_range 1 ${#users[@]}

    local username="${users[$((choice-1))]}"

    echo ""
    echo -e "${cyan}SSH密钥配置选项:${white}"
    echo "1. 生成新的密钥对"
    echo "2. 添加现有公钥"
    echo ""

    local key_choice
    prompt_for_input "请选择配置方式 [1-2]: " key_choice validate_numeric_range 1 2

    case $key_choice in
        1)
            setup_user_ssh_key "$username"
            ;;
        2)
            echo "请输入公钥内容 (ssh-rsa 或 ssh-ed25519 开头):"
            read -r public_key

            if [[ -n "$public_key" ]]; then
                setup_user_ssh_key "$username" "$public_key"
            else
                warn_msg "公钥内容不能为空"
            fi
            ;;
    esac

    break_end
}

# 交互式显示用户信息
show_user_info_interactive() {
    clear
    echo -e "${pink}查看用户信息${white}"
    echo "================================"

    echo "1. 查看所有用户概览"
    echo "2. 查看特定用户详情"
    echo ""

    local choice
    prompt_for_input "请选择查看方式 [1-2]: " choice validate_numeric_range 1 2

    case $choice in
        1)
            show_user_info
            ;;
        2)
            echo ""
            echo -e "${cyan}用户列表:${white}"
            local users=($(awk -F: '$3 >= 0 && $1 != "nobody" {print $1}' /etc/passwd))

            for i in "${!users[@]}"; do
                echo "$((i+1)). ${users[i]}"
            done
            echo ""

            local user_choice
            prompt_for_input "请选择用户编号 [1-${#users[@]}]: " user_choice validate_numeric_range 1 ${#users[@]}

            local username="${users[$((user_choice-1))]}"
            echo ""
            show_user_info "$username"
            ;;
    esac

    break_end
}

# 用户安全审计
user_security_audit() {
    clear
    echo -e "${pink}用户安全审计${white}"
    echo "================================"

    info_msg "正在进行用户安全审计..."
    echo ""

    local issues=0
    local warnings=0

    # 检查root用户状态
    echo -e "${cyan}1. Root用户安全检查${white}"
    if passwd -S root 2>/dev/null | grep -q "L"; then
        echo "  ✓ Root用户密码已锁定"
    else
        echo "  ⚠ Root用户密码未锁定，建议锁定"
        ((warnings++))
    fi

    # 检查空密码用户
    echo -e "${cyan}2. 空密码用户检查${white}"
    local empty_password_users=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$empty_password_users" ]]; then
        echo "  ✓ 没有空密码用户"
    else
        echo "  ✗ 发现空密码用户: $empty_password_users"
        ((issues++))
    fi

    # 检查相同UID的用户
    echo -e "${cyan}3. 重复UID检查${white}"
    local duplicate_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    if [[ -z "$duplicate_uids" ]]; then
        echo "  ✓ 没有重复的UID"
    else
        echo "  ⚠ 发现重复的UID: $duplicate_uids"
        ((warnings++))
    fi

    # 检查sudo权限用户
    echo -e "${cyan}4. sudo权限审计${white}"
    local sudo_users=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' ' ')
    if [[ -n "$sudo_users" ]]; then
        echo "  sudo组用户: $sudo_users"
    fi

    # 检查sudoers.d目录
    if [[ -d "/etc/sudoers.d" ]]; then
        local sudoers_files=$(find /etc/sudoers.d -name "*" -type f ! -name "README" 2>/dev/null)
        if [[ -n "$sudoers_files" ]]; then
            echo "  自定义sudo配置:"
            for file in $sudoers_files; do
                echo "    - $(basename "$file")"
            done
        fi
    fi

    # 检查最近登录的用户
    echo -e "${cyan}5. 用户登录活动${white}"
    echo "  最近登录的用户:"
    last -n 10 2>/dev/null | grep -v "reboot\|shutdown" | head -5 | while read line; do
        echo "    $line"
    done

    # 检查长时间未登录的用户
    echo -e "${cyan}6. 非活跃用户检查${white}"
    local inactive_users=()
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ $uid -ge 1000 && $uid -lt 65534 ]]; then
            if ! last "$username" 2>/dev/null | grep -q "$username"; then
                inactive_users+=("$username")
            fi
        fi
    done < /etc/passwd

    if [[ ${#inactive_users[@]} -gt 0 ]]; then
        echo "  从未登录的用户: ${inactive_users[*]}"
        ((warnings++))
    else
        echo "  ✓ 所有用户都有登录记录"
    fi

    echo ""
    echo "================================"

    # 显示审计结果
    if [[ $issues -eq 0 && $warnings -eq 0 ]]; then
        echo -e "${green}✓ 用户安全状况良好！${white}"
    elif [[ $issues -eq 0 ]]; then
        echo -e "${yellow}⚠ 发现 $warnings 个需要注意的项目${white}"
    else
        echo -e "${red}✗ 发现 $issues 个安全问题和 $warnings 个警告项${white}"
    fi

    echo ""
    echo -e "${yellow}安全建议:${white}"
    echo "1. 定期审查用户账户，删除不需要的账户"
    echo "2. 确保所有用户使用强密码"
    echo "3. 限制sudo权限，遵循最小权限原则"
    echo "4. 监控用户登录活动，及时发现异常"
    echo "5. 定期更新用户SSH密钥"

    break_end
}
#endregion

#region //fail2ban配置模块
# 安装fail2ban
install_fail2ban() {
    info_msg "安装fail2ban..."

    case $PKG_MANAGER in
        apt)
            install_package fail2ban
            ;;
        yum|dnf)
            install_package epel-release true
            install_package fail2ban
            ;;
        *)
            error_exit "不支持的包管理器: $PKG_MANAGER"
            ;;
    esac

    success_msg "fail2ban安装完成"
}

# 配置fail2ban
configure_fail2ban() {
    info_msg "配置fail2ban..."

    # 备份原始配置
    backup_file /etc/fail2ban/jail.conf

    # 获取SSH端口
    local ssh_port=$(sshd -T | grep -i "^port " | awk '{print $2}' 2>/dev/null || echo "22")

    # 创建自定义配置文件
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 忽略的IP列表(白名单)
ignoreip = 127.0.0.1/8 ::1

# 封禁时间(秒) - 24小时
bantime = 86400

# 查找时间窗口(秒) - 10分钟
findtime = 600

# 最大重试次数
maxretry = 3

# 后端类型
backend = systemd

# 邮件配置(可选)
# destemail = admin@example.com
# sender = fail2ban@example.com
# mta = sendmail

# 动作配置
action = %(action_)s

[sshd]
# SSH保护
enabled = true
port = $ssh_port
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 86400
findtime = 600

[sshd-ddos]
# SSH DDoS保护
enabled = true
port = $ssh_port
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 86400
findtime = 300

[apache-auth]
# Apache认证失败保护
enabled = false
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 3

[nginx-http-auth]
# Nginx认证失败保护
enabled = false
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
# Nginx请求限制保护
enabled = false
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 600
bantime = 600
EOF

    # 创建SSH DDoS过滤器
    cat > /etc/fail2ban/filter.d/sshd-ddos.conf << EOF
[Definition]
failregex = sshd(?:\[<HOST>\])?: Did not receive identification string from <HOST>
            sshd(?:\[<HOST>\])?: Connection closed by <HOST> port \d+ \[preauth\]
            sshd(?:\[<HOST>\])?: Connection reset by <HOST> port \d+ \[preauth\]
ignoreregex =
EOF

    success_msg "fail2ban配置完成"
}

# 启动fail2ban服务
start_fail2ban_service() {
    info_msg "启动fail2ban服务..."

    # 启用并启动服务
    manage_service enable fail2ban
    manage_service start fail2ban

    # 检查服务状态
    if manage_service status fail2ban > /dev/null 2>&1; then
        success_msg "fail2ban服务运行正常"
    else
        error_exit "fail2ban服务启动失败"
    fi
}

# 显示fail2ban状态
show_fail2ban_status() {
    echo -e "${cyan}fail2ban状态:${white}"

    # 显示服务状态
    if command_exists fail2ban-client; then
        echo "服务状态:"
        fail2ban-client status
        echo ""

        echo "SSH保护状态:"
        fail2ban-client status sshd 2>/dev/null || echo "SSH jail未启用"
        echo ""

        echo "当前封禁的IP:"
        fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" || echo "暂无封禁IP"
    else
        echo "fail2ban未安装或未正确配置"
    fi
}

# 完整的fail2ban安装配置
install_configure_fail2ban() {
    clear
    echo -e "${pink}fail2ban安装配置${white}"
    echo "================================"

    echo "fail2ban是一个入侵防护系统，功能包括："
    echo "1. SSH暴力破解防护"
    echo "2. DDoS攻击防护"
    echo "3. 自动封禁恶意IP"
    echo "4. 支持多种服务保护"
    echo ""

    echo "配置参数："
    echo "- 封禁时间: 24小时"
    echo "- 最大重试: 3次"
    echo "- 检测窗口: 10分钟"
    echo "- SSH端口: $(sshd -T | grep -i "^port " | awk '{print $2}' 2>/dev/null || echo "22")"
    echo ""

    if ! confirm_operation "fail2ban安装配置"; then
        info_msg "操作已取消"
        return
    fi

    # 执行安装配置步骤
    show_progress 1 4 "安装fail2ban"
    install_fail2ban

    show_progress 2 4 "配置fail2ban规则"
    configure_fail2ban

    show_progress 3 4 "启动fail2ban服务"
    start_fail2ban_service

    show_progress 4 4 "配置完成"

    echo ""
    success_msg "fail2ban安装配置完成！"
    echo ""
    show_fail2ban_status
    echo ""

    echo -e "${yellow}常用命令：${white}"
    echo "查看状态: fail2ban-client status"
    echo "查看SSH保护: fail2ban-client status sshd"
    echo "解封IP: fail2ban-client set sshd unbanip <IP>"
    echo "重启服务: systemctl restart fail2ban"
    echo ""

    break_end
}
#endregion

#region //Xray代理部署模块
# Xray配置目录和文件
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_FILE="$XRAY_CONFIG_DIR/config.json"
XRAY_BINARY="/usr/local/bin/xray"
XRAY_SERVICE_FILE="/etc/systemd/system/xray.service"

# 检测系统架构
detect_architecture() {
    local arch=$(uname -m)
    case $arch in
        x86_64)
            echo "64"
            ;;
        aarch64|arm64)
            echo "arm64-v8a"
            ;;
        armv7l)
            echo "arm32-v7a"
            ;;
        *)
            error_exit "不支持的系统架构: $arch"
            ;;
    esac
}

# 获取最新Xray版本
get_latest_xray_version() {
    local version
    if [[ "$COUNTRY" == "CN" ]]; then
        # 使用国内镜像
        version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | grep '"tag_name":' | cut -d'"' -f4)
    else
        version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | grep '"tag_name":' | cut -d'"' -f4)
    fi

    if [[ -z "$version" ]]; then
        warn_msg "无法获取最新版本，使用默认版本 v1.8.4"
        echo "v1.8.4"
    else
        echo "$version"
    fi
}

# 下载Xray-core
download_xray() {
    local version="$1"
    local arch="$2"
    local download_url

    info_msg "下载Xray-core $version ($arch)..."

    # 构建下载URL
    if [[ "$COUNTRY" == "CN" ]]; then
        # 使用国内镜像
        download_url="https://ghproxy.com/https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-${arch}.zip"
    else
        download_url="https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-${arch}.zip"
    fi

    # 创建临时目录
    local temp_dir
    temp_dir=$(mktemp -d)
    # 设置trap以确保在函数退出时清理临时目录
    trap 'rm -rf "$temp_dir"' EXIT

    # 进入临时目录
    cd "$temp_dir"

    # 下载文件
    if ! curl -L -o "xray.zip" "$download_url"; then
        error_exit "下载Xray失败"
    fi

    # 解压文件
    if ! unzip -q "xray.zip"; then
        error_exit "解压Xray失败"
    fi

    # 安装二进制文件
    if [[ -f "xray" ]]; then
        mv "xray" "$XRAY_BINARY"
        chmod +x "$XRAY_BINARY"
        success_msg "Xray二进制文件安装完成"
    else
        # trap会处理error_exit时的清理工作
        error_exit "Xray二进制文件不存在"
    fi

    # 返回原始目录并清除trap
    cd - > /dev/null 2>&1
    trap - EXIT
}

# 创建Xray配置目录
create_xray_directories() {
    info_msg "创建Xray配置目录..."

    mkdir -p "$XRAY_CONFIG_DIR"
    mkdir -p "/var/log/xray"

    success_msg "Xray目录创建完成"
}

# 创建Xray systemd服务
create_xray_service() {
    info_msg "创建Xray systemd服务..."

    cat > "$XRAY_SERVICE_FILE" << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BINARY run -config $XRAY_CONFIG_FILE
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载systemd
    systemctl daemon-reload

    success_msg "Xray服务创建完成"
}

# 检查Xray安装状态
check_xray_installation() {
    echo -e "${cyan}Xray安装状态:${white}"

    if [[ -f "$XRAY_BINARY" ]]; then
        local version=$($XRAY_BINARY version 2>/dev/null | head -1)
        echo "  二进制文件: 已安装 ($version)"
    else
        echo "  二进制文件: 未安装"
    fi

    if [[ -f "$XRAY_CONFIG_FILE" ]]; then
        echo "  配置文件: 已存在"
    else
        echo "  配置文件: 不存在"
    fi

    if [[ -f "$XRAY_SERVICE_FILE" ]]; then
        echo "  系统服务: 已创建"
        local status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
        echo "  服务状态: $status"
    else
        echo "  系统服务: 未创建"
    fi
}

# 完整的Xray-core安装
install_xray_core() {
    clear
    echo -e "${pink}Xray-core安装${white}"
    echo "================================"

    # 显示当前状态
    check_xray_installation
    echo ""

    echo "Xray-core是一个高性能的代理工具，支持："
    echo "1. VLESS协议"
    echo "2. HTTP/2传输"
    echo "3. REALITY安全层"
    echo "4. IPv4/IPv6双栈"
    echo ""

    if ! confirm_operation "Xray-core安装"; then
        info_msg "操作已取消"
        return
    fi

    # 检测系统架构
    local arch=$(detect_architecture)
    echo "检测到系统架构: $arch"

    # 获取最新版本
    local version=$(get_latest_xray_version)
    echo "最新版本: $version"
    echo ""

    # 执行安装步骤
    show_progress 1 5 "创建配置目录"
    create_xray_directories

    show_progress 2 5 "下载Xray-core"
    download_xray "$version" "$arch"

    show_progress 3 5 "创建系统服务"
    create_xray_service

    show_progress 4 5 "设置权限"
    chown -R nobody:nogroup "$XRAY_CONFIG_DIR"
    chown -R nobody:nogroup "/var/log/xray"

    show_progress 5 5 "安装完成"

    echo ""
    success_msg "Xray-core安装完成！"
    echo ""
    check_xray_installation
    echo ""

    echo -e "${yellow}下一步：${white}"
    echo "1. 配置VLESS-HTTP2-REALITY"
    echo "2. 生成客户端配置"
    echo "3. 启动Xray服务"
    echo ""

    break_end
}
#endregion

#region //VLESS-HTTP2-REALITY配置模块
# 生成UUID
generate_uuid() {
    if command_exists uuidgen; then
        uuidgen
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        # 备用方法
        python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null || \
        python -c "import uuid; print(uuid.uuid4())" 2>/dev/null || \
        echo "$(date +%s | sha256sum | cut -c1-8)-$(date +%N | cut -c1-4)-4$(date +%s | sha256sum | cut -c9-12)-$(date +%N | cut -c5-8)-$(date +%s | sha256sum | cut -c13-24)"
    fi
}

# 生成X25519密钥对
generate_x25519_keys() {
    if [[ -f "$XRAY_BINARY" ]]; then
        $XRAY_BINARY x25519
    else
        error_exit "Xray未安装，请先安装Xray-core"
    fi
}

# 生成短ID
generate_short_ids() {
    local short_ids=()
    for i in {1..3}; do
        local short_id=$(openssl rand -hex 8)
        short_ids+=("\"$short_id\"")
    done
    echo "[$(IFS=','; echo "${short_ids[*]}")]"
}

# 选择目标网站
select_target_website() {
    local websites=(
        "www.microsoft.com:443"
        "www.cloudflare.com:443"
        "www.apple.com:443"
        "www.amazon.com:443"
        "www.google.com:443"
    )

    # 随机选择一个网站
    local index=$((RANDOM % ${#websites[@]}))
    echo "${websites[$index]}"
}

# 获取目标网站的SNI
get_sni_from_dest() {
    local dest="$1"
    echo "${dest%:*}"
}

# 创建VLESS-HTTP2-REALITY配置
create_vless_reality_config() {
    local user_uuid="$1"
    local private_key="$2"
    local public_key="$3"
    local dest="$4"
    local server_names="$5"
    local short_ids="$6"
    local listen_port="${7:-443}"

    info_msg "创建VLESS-HTTP2-REALITY配置..."

    # 检查是否支持IPv6
    local ipv6_supported=false
    if [[ "$IPV6_ADDRESS" != "不支持" && "$IPV6_ADDRESS" != "" ]]; then
        ipv6_supported=true
        info_msg "检测到IPv6支持，将创建双栈配置"
    else
        info_msg "IPv6不可用，创建IPv4单栈配置"
    fi

    cat > "$XRAY_CONFIG_FILE" << EOF
{
  "log": {
    "loglevel": "debug"
  },
  "inbounds": [
    {
      "port": $listen_port,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$user_uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "h2",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$dest",
          "xver": 0,
          "serverNames": [
            "$server_names"
          ],
          "privateKey": "$private_key",
          "shortIds": $short_ids
        },
        "httpSettings": {
          "path": "/",
          "host": [
            "$server_names"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    }
EOF

    # 如果支持IPv6，添加IPv6 inbound
    if [[ "$ipv6_supported" == "true" ]]; then
        cat >> "$XRAY_CONFIG_FILE" << EOF
    ,
    {
      "port": $listen_port,
      "listen": "::",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$user_uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "h2",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$dest",
          "xver": 0,
          "serverNames": [
            "$server_names"
          ],
          "privateKey": "$private_key",
          "shortIds": $short_ids
        },
        "httpSettings": {
          "path": "/",
          "host": [
            "$server_names"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    }
EOF
    fi

    # 完成JSON配置
    cat >> "$XRAY_CONFIG_FILE" << EOF
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF

    success_msg "VLESS-HTTP2-REALITY配置创建完成"
}

# 保存配置信息
save_proxy_config() {
    local user_uuid="$1"
    local public_key="$2"
    local dest="$3"
    local server_names="$4"
    local short_ids="$5"
    local listen_port="$6"

    cat > "$config_dir/proxy_config.conf" << EOF
# VLESS-HTTP2-REALITY配置信息
USER_UUID=$user_uuid
PUBLIC_KEY=$public_key
DEST=$dest
SERVER_NAMES=$server_names
SHORT_IDS=$short_ids
LISTEN_PORT=$listen_port
SERVER_IPV4=$IPV4_ADDRESS
SERVER_IPV6=$IPV6_ADDRESS
DUAL_STACK=$(if [[ "$IPV6_ADDRESS" != "不支持" && "$IPV6_ADDRESS" != "" ]]; then echo "true"; else echo "false"; fi)
CREATION_TIME=$(date '+%Y-%m-%d %H:%M:%S')
EOF

    success_msg "配置信息已保存到 $config_dir/proxy_config.conf"
}

# 测试Xray配置
test_xray_config() {
    info_msg "测试Xray配置文件..."

    if [[ ! -f "$XRAY_CONFIG_FILE" ]]; then
        error_exit "配置文件不存在: $XRAY_CONFIG_FILE"
    fi

    # 检查Xray二进制文件是否存在
    if [[ ! -f "$XRAY_BINARY" ]]; then
        error_exit "Xray程序不存在: $XRAY_BINARY"
    fi

    # 使用正确的测试命令
    if "$XRAY_BINARY" test -c "$XRAY_CONFIG_FILE" 2>/dev/null; then
        success_msg "Xray配置文件语法正确"
    else
        echo -e "${red}Xray配置文件语法错误，详细信息：${white}"
        "$XRAY_BINARY" test -c "$XRAY_CONFIG_FILE"
        error_exit "请修复配置文件后重试"
    fi
}

# 启动Xray服务
start_xray_service() {
    info_msg "启动Xray服务..."

    # 启用并启动服务
    manage_service enable xray
    manage_service start xray

    # 检查服务状态
    sleep 2
    if manage_service status xray > /dev/null 2>&1; then
        success_msg "Xray服务启动成功"
    else
        error_exit "Xray服务启动失败，请检查配置和日志"
    fi
}

# 显示REALITY配置信息
show_reality_config() {
    if [[ -f "$config_dir/proxy_config.conf" ]]; then
        . "$config_dir/proxy_config.conf"

        echo -e "${cyan}VLESS-HTTP2-REALITY配置信息:${white}"
        echo "  IPv4地址: $SERVER_IPV4"
        if [[ "$SERVER_IPV6" != "不支持" && "$SERVER_IPV6" != "" ]]; then
            echo "  IPv6地址: $SERVER_IPV6"
            echo "  双栈支持: 是"
        else
            echo "  双栈支持: 否 (仅IPv4)"
        fi
        echo "  端口: $LISTEN_PORT"
        echo "  用户ID: $USER_UUID"
        echo "  公钥: $PUBLIC_KEY"
        echo "  目标网站: $DEST"
        echo "  SNI: $SERVER_NAMES"
        echo "  短ID: $SHORT_IDS"
        echo "  创建时间: $CREATION_TIME"
    else
        warn_msg "配置信息文件不存在"
    fi
}

# 完整的VLESS-TCP-REALITY配置
configure_vless_reality() {
    clear
    echo -e "${pink}VLESS-TCP-REALITY配置${white}"
    echo "================================"

    # 检查Xray是否已安装
    if [[ ! -f "$XRAY_BINARY" ]]; then
        error_exit "Xray未安装，请先安装Xray-core"
    fi

    echo "VLESS-TCP-REALITY协议特点："
    echo "1. 基于VLESS协议，性能优异"
    echo "2. 使用TCP传输，稳定可靠"
    echo "3. REALITY安全层，抗检测能力强"
    echo "4. 无需真实TLS证书"
    echo ""

    if ! confirm_operation "VLESS-TCP-REALITY配置"; then
        info_msg "操作已取消"
        return
    fi

    # 生成配置参数
    show_progress 1 6 "生成用户UUID"
    local user_uuid=$(generate_uuid)
    echo "用户UUID: $user_uuid"

    show_progress 2 6 "生成X25519密钥对"
    local keys_output=$(generate_x25519_keys)
    local private_key=$(echo "$keys_output" | grep "Private key" | cut -d: -f2 | tr -d ' ')
    local public_key=$(echo "$keys_output" | grep "Public key" | cut -d: -f2 | tr -d ' ')
    echo "私钥: $private_key"
    echo "公钥: $public_key"

    show_progress 3 6 "选择目标网站"
    local dest=$(select_target_website)
    local server_names=$(get_sni_from_dest "$dest")
    echo "目标网站: $dest"
    echo "SNI: $server_names"

    show_progress 4 6 "生成短ID"
    local short_ids=$(generate_short_ids)
    echo "短ID: $short_ids"

    show_progress 5 6 "创建配置文件"
    create_vless_reality_config "$user_uuid" "$private_key" "$public_key" "$dest" "$server_names" "$short_ids" "443"

    show_progress 6 6 "测试配置"
    test_xray_config

    # 保存配置信息
    save_proxy_config "$user_uuid" "$public_key" "$dest" "$server_names" "$short_ids" "443"

    echo ""
    success_msg "VLESS-TCP-REALITY配置完成！"
    echo ""
    show_reality_config
    echo ""

    read -p "是否立即启动Xray服务？(Y/n): " start_now
    if [[ ! "$start_now" =~ ^[Nn]$ ]]; then
        start_xray_service
        echo ""
        success_msg "Xray服务已启动！"
    fi

    echo ""
    echo -e "${yellow}下一步：${white}"
    echo "1. 生成客户端配置"
    echo "2. 配置防火墙规则"
    echo "3. 测试连接"
    echo ""

    break_end
}
#endregion

#region //客户端配置生成模块
# 生成客户端JSON配置
generate_client_json() {
    if [[ ! -f "$config_dir/proxy_config.conf" ]]; then
        error_exit "代理配置文件不存在，请先配置VLESS-HTTP2-REALITY"
    fi

    . "$config_dir/proxy_config.conf"

    local client_config="{
  \"log\": {
    \"loglevel\": \"warning\"
  },
  \"inbounds\": [
    {
      \"port\": 1080,
      \"protocol\": \"socks\",
      \"settings\": {
        \"auth\": \"noauth\",
        \"udp\": true
      }
    },
    {
      \"port\": 1081,
      \"protocol\": \"http\"
    }
  ],
  \"outbounds\": [
    {
      \"protocol\": \"vless\",
      \"settings\": {
        \"vnext\": [
          {
            \"address\": \"$SERVER_IPV4\",
            \"port\": $LISTEN_PORT,
            \"users\": [
              {
                \"id\": \"$USER_UUID\",
                \"flow\": \"xtls-rprx-vision\"
              }
            ]
          }
        ]
      },
      \"streamSettings\": {
        \"network\": \"h2\",
        \"security\": \"reality\",
        \"realitySettings\": {
          \"serverName\": \"$SERVER_NAMES\",
          \"fingerprint\": \"chrome\",
          \"publicKey\": \"$PUBLIC_KEY\",
          \"shortId\": \"$(command_exists jq && echo "$SHORT_IDS" | jq -r '.[0]' 2>/dev/null || echo "")\"
        },
        \"httpSettings\": {
          \"path\": \"/\",
          \"host\": [
            \"$SERVER_NAMES\"
          ]
        }
      }
    }
  ]
}"

    echo "$client_config"
}

# 生成VLESS分享链接
generate_vless_share_link() {
    if [[ ! -f "$config_dir/proxy_config.conf" ]]; then
        error_exit "代理配置文件不存在，请先配置VLESS-HTTP2-REALITY"
    fi

    . "$config_dir/proxy_config.conf"

    # 提取第一个短ID
    local first_short_id=$(echo "$SHORT_IDS" | jq -r '.[0]' 2>/dev/null || echo "")

    # 构建VLESS URL (使用IPv4地址)
    local vless_url="vless://${USER_UUID}@${SERVER_IPV4}:${LISTEN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SERVER_NAMES}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${first_short_id}&type=http&host=${SERVER_NAMES}&path=%2F#VLESS-HTTP2-REALITY-IPv4"

    echo "$vless_url"
}

# 生成IPv6 VLESS分享链接
generate_vless_share_link_ipv6() {
    if [[ ! -f "$config_dir/proxy_config.conf" ]]; then
        error_exit "代理配置文件不存在，请先配置VLESS-HTTP2-REALITY"
    fi

    . "$config_dir/proxy_config.conf"

    # 检查IPv6支持
    if [[ "$SERVER_IPV6" == "不支持" || "$SERVER_IPV6" == "" ]]; then
        echo "IPv6不支持"
        return 1
    fi

    # 提取第一个短ID
    local first_short_id=$(echo "$SHORT_IDS" | jq -r '.[0]' 2>/dev/null || echo "")

    # 构建IPv6 VLESS URL (IPv6地址需要用方括号包围)
    local vless_url="vless://${USER_UUID}@[${SERVER_IPV6}]:${LISTEN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SERVER_NAMES}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${first_short_id}&type=http&host=${SERVER_NAMES}&path=%2F#VLESS-HTTP2-REALITY-IPv6"

    echo "$vless_url"
}

# 生成Clash配置
generate_clash_config() {
    if [[ ! -f "$config_dir/proxy_config.conf" ]]; then
        error_exit "代理配置文件不存在，请先配置VLESS-HTTP2-REALITY"
    fi

    . "$config_dir/proxy_config.conf"

    local first_short_id=$(echo "$SHORT_IDS" | jq -r '.[0]' 2>/dev/null || echo "")

    local clash_config="port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - name: \"VLESS-HTTP2-REALITY\"
    type: vless
    server: $SERVER_IPV4
    port: $LISTEN_PORT
    uuid: $USER_UUID
    network: h2
    tls: true
    udp: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: $PUBLIC_KEY
      short-id: $first_short_id
    h2-opts:
      host:
        - $SERVER_NAMES
      path: \"/\"

proxy-groups:
  - name: \"Proxy\"
    type: select
    proxies:
      - \"VLESS-HTTP2-REALITY\"
      - \"DIRECT\"

rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Proxy"

    echo "$clash_config"
}

# 保存客户端配置文件
save_client_configs() {
    local output_dir="$config_dir/client_configs"
    mkdir -p "$output_dir"

    info_msg "生成客户端配置文件..."

    # 生成JSON配置
    generate_client_json > "$output_dir/client_config.json"
    success_msg "客户端JSON配置已保存: $output_dir/client_config.json"

    # 生成分享链接
    generate_vless_share_link > "$output_dir/vless_share_link_ipv4.txt"
    success_msg "VLESS IPv4分享链接已保存: $output_dir/vless_share_link_ipv4.txt"

    # 生成IPv6分享链接（如果支持）
    if generate_vless_share_link_ipv6 > "$output_dir/vless_share_link_ipv6.txt" 2>/dev/null; then
        success_msg "VLESS IPv6分享链接已保存: $output_dir/vless_share_link_ipv6.txt"
    else
        info_msg "IPv6不支持，跳过IPv6分享链接生成"
    fi

    # 生成Clash配置
    generate_clash_config > "$output_dir/clash_config.yaml"
    success_msg "Clash配置已保存: $output_dir/clash_config.yaml"

    # 生成使用说明
    cat > "$output_dir/README.txt" << EOF
VLESS-HTTP2-REALITY客户端配置说明
================================

配置文件说明：
1. client_config.json - Xray客户端配置文件
2. vless_share_link.txt - VLESS分享链接
3. clash_config.yaml - Clash客户端配置文件

使用方法：

1. Xray客户端：
   - 下载Xray客户端
   - 使用client_config.json作为配置文件
   - 启动客户端，SOCKS代理端口：1080，HTTP代理端口：1081

2. 移动端（v2rayNG、Shadowrocket等）：
   - 复制vless_share_link.txt中的链接
   - 在客户端中导入链接

3. Clash客户端：
   - 使用clash_config.yaml作为配置文件
   - 代理端口：7890，控制端口：9090

服务器信息：
- IPv4地址：$(cat "$config_dir/proxy_config.conf" | grep SERVER_IPV4 | cut -d= -f2)
- IPv6地址：$(cat "$config_dir/proxy_config.conf" | grep SERVER_IPV6 | cut -d= -f2)
- 端口：$(cat "$config_dir/proxy_config.conf" | grep LISTEN_PORT | cut -d= -f2)
- 协议：VLESS-HTTP2-REALITY

注意事项：
1. 请妥善保管配置文件
2. 不要泄露用户UUID和公钥
3. 如遇连接问题，请检查防火墙设置
4. 建议定期更新客户端软件

生成时间：$(date '+%Y-%m-%d %H:%M:%S')
EOF

    success_msg "使用说明已保存: $output_dir/README.txt"
}

# 显示客户端配置
show_client_configs() {
    clear
    echo -e "${pink}客户端配置信息${white}"
    echo "================================"

    if [[ ! -f "$config_dir/proxy_config.conf" ]]; then
        error_exit "代理配置文件不存在，请先配置VLESS-HTTP2-REALITY"
    fi

    . "$config_dir/proxy_config.conf"

    echo -e "${cyan}服务器信息:${white}"
    echo "  IPv4地址: $SERVER_IPV4"
    if [[ "$SERVER_IPV6" != "不支持" && "$SERVER_IPV6" != "" ]]; then
        echo "  IPv6地址: $SERVER_IPV6"
    fi
    echo "  端口: $LISTEN_PORT"
    echo "  协议: VLESS-HTTP2-REALITY"
    echo ""

    echo -e "${cyan}VLESS分享链接:${white}"
    echo "IPv4: $(generate_vless_share_link)"
    if [[ "$SERVER_IPV6" != "不支持" && "$SERVER_IPV6" != "" ]]; then
        echo "IPv6: $(generate_vless_share_link_ipv6)"
    fi
    echo ""

    echo -e "${cyan}客户端配置文件位置:${white}"
    echo "  JSON配置: $config_dir/client_configs/client_config.json"
    echo "  分享链接: $config_dir/client_configs/vless_share_link.txt"
    echo "  Clash配置: $config_dir/client_configs/clash_config.yaml"
    echo "  使用说明: $config_dir/client_configs/README.txt"
    echo ""

    echo -e "${yellow}快速使用：${white}"
    echo "1. 移动端：复制上面的分享链接导入客户端"
    echo "2. 电脑端：下载对应配置文件使用"
    echo "3. 详细说明请查看README.txt文件"
}

# 完整的客户端配置生成
generate_client_configs() {
    clear
    echo -e "${pink}客户端配置生成${white}"
    echo "================================"

    if [[ ! -f "$config_dir/proxy_config.conf" ]]; then
        error_exit "代理配置文件不存在，请先配置VLESS-HTTP2-REALITY"
    fi

    echo "将生成以下客户端配置："
    echo "1. Xray客户端JSON配置"
    echo "2. VLESS分享链接（移动端）"
    echo "3. Clash配置文件"
    echo "4. 详细使用说明"
    echo ""

    if ! confirm_operation "生成客户端配置"; then
        info_msg "操作已取消"
        return
    fi

    # 执行生成步骤
    show_progress 1 3 "生成配置文件"
    save_client_configs

    show_progress 2 3 "验证配置"
    if [[ -f "$config_dir/client_configs/client_config.json" ]]; then
        success_msg "配置文件生成成功"
    else
        error_exit "配置文件生成失败"
    fi

    show_progress 3 3 "生成完成"

    echo ""
    success_msg "客户端配置生成完成！"
    echo ""

    show_client_configs

    break_end
}

# 代理服务管理
proxy_service_management() {
    while true; do
        clear
        echo -e "${pink}代理服务管理${white}"
        echo "================================"

        # 显示服务状态
        if command_exists systemctl && [[ -f "$XRAY_SERVICE_FILE" ]]; then
            local status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
            echo "Xray服务状态: $status"
        else
            echo "Xray服务: 未安装"
        fi
        echo ""

        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 查看服务状态"
        echo "5. 查看服务日志"
        echo "6. 测试配置文件"
        echo "================================"
        echo "0. 返回上级菜单"
        echo "================================"

        read -p "请选择操作 [0-6]: " choice

        case $choice in
            1)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    manage_service start xray
                    success_msg "服务启动命令已执行"
                else
                    error_exit "Xray服务未安装"
                fi
                break_end
                ;;
            2)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    manage_service stop xray
                    success_msg "服务停止命令已执行"
                else
                    error_exit "Xray服务未安装"
                fi
                break_end
                ;;
            3)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    manage_service restart xray
                    success_msg "服务重启命令已执行"
                else
                    error_exit "Xray服务未安装"
                fi
                break_end
                ;;
            4)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    systemctl status xray
                else
                    echo "Xray服务未安装"
                fi
                break_end
                ;;
            5)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    echo "最近的服务日志："
                    journalctl -u xray -n 50 --no-pager
                else
                    echo "Xray服务未安装"
                fi
                break_end
                ;;
            6)
                if [[ -f "$XRAY_CONFIG_FILE" ]]; then
                    test_xray_config
                else
                    error_exit "Xray配置文件不存在"
                fi
                break_end
                ;;
            0) break ;;
            *) warn_msg "无效选择，请重新输入"; sleep 2 ;;
        esac
    done
}
#endregion

#region //网络质量检测模块
# 安装网络测试工具
install_network_tools() {
    info_msg "安装网络测试工具..."

    # 检查并安装基础工具
    local basic_tools=()
    case $PKG_MANAGER in
        apt)
            basic_tools=("curl" "wget" "traceroute" "mtr-tiny" "bc")
            ;;
        yum|dnf)
            basic_tools=("curl" "wget" "traceroute" "mtr" "bc")
            ;;
    esac

    # 逐个检查和安装工具
    for tool in "${basic_tools[@]}"; do
        if ! command_exists "${tool%%-*}"; then  # 处理mtr-tiny这种情况
            echo "  安装 $tool..."
            install_package "$tool" true 2>/dev/null || {
                warn_msg "$tool 安装失败，将使用备用方法"
            }
        else
            echo "  ✓ $tool 已安装"
        fi
    done

    # 尝试安装speedtest-cli（可选）
    if ! command_exists speedtest; then
        echo "  尝试安装 speedtest..."
        case $PKG_MANAGER in
            apt)
                # 尝试从官方源安装
                if curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash 2>/dev/null; then
                    install_package speedtest true 2>/dev/null || echo "    speedtest 安装失败，将使用备用测试"
                else
                    # 尝试安装speedtest-cli
                    install_package speedtest-cli true 2>/dev/null || echo "    speedtest-cli 安装失败，将使用备用测试"
                fi
                ;;
            yum|dnf)
                install_package speedtest-cli true 2>/dev/null || echo "    speedtest-cli 安装失败，将使用备用测试"
                ;;
        esac
    else
        echo "  ✓ speedtest 已安装"
    fi

    success_msg "网络测试工具检查完成"
}

# 测试网络延迟
test_network_latency() {
    echo -e "${cyan}网络延迟测试:${white}"

    local test_targets=(
        "8.8.8.8:Google DNS"
        "1.1.1.1:Cloudflare DNS"
        "114.114.114.114:114 DNS"
        "223.5.5.5:阿里DNS"
    )

    for target in "${test_targets[@]}"; do
        local ip="${target%:*}"
        local name="${target#*:}"
        local ping_result=$(ping -c 4 -W 3 "$ip" 2>/dev/null | tail -1 | awk -F'/' '{print $5}' 2>/dev/null)

        if [[ -n "$ping_result" ]]; then
            printf "  %-15s: %6.2f ms\n" "$name" "$ping_result"
        else
            printf "  %-15s: %s\n" "$name" "超时"
        fi
    done
    echo ""
}

# 测试网络带宽
test_network_bandwidth() {
    echo -e "${cyan}网络带宽测试:${white}"

    # 首先尝试speedtest
    if command_exists speedtest; then
        echo "  正在使用 speedtest 测试带宽..."
        local speedtest_result

        # 尝试JSON格式输出
        speedtest_result=$(timeout 60 speedtest --accept-license --accept-gdpr -f json 2>/dev/null)

        if [[ $? -eq 0 && -n "$speedtest_result" ]]; then
            # 解析JSON结果
            if command_exists python3; then
                local download_mbps=$(echo "$speedtest_result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"{data['download']['bandwidth'] * 8 / 1000000:.2f}\")
except:
    print('N/A')
" 2>/dev/null)
                local upload_mbps=$(echo "$speedtest_result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"{data['upload']['bandwidth'] * 8 / 1000000:.2f}\")
except:
    print('N/A')
" 2>/dev/null)
                local server_name=$(echo "$speedtest_result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['server']['name'])
except:
    print('Unknown')
" 2>/dev/null)
                local ping_latency=$(echo "$speedtest_result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"{data['ping']['latency']:.2f}\")
except:
    print('N/A')
" 2>/dev/null)
            else
                # 使用基础工具解析
                local download_mbps=$(echo "$speedtest_result" | grep -o '"download":{"bandwidth":[0-9]*' | cut -d: -f3 | head -1)
                local upload_mbps=$(echo "$speedtest_result" | grep -o '"upload":{"bandwidth":[0-9]*' | cut -d: -f3 | head -1)

                if [[ -n "$download_mbps" && -n "$upload_mbps" ]]; then
                    download_mbps=$(echo "scale=2; $download_mbps * 8 / 1000000" | bc 2>/dev/null || echo "N/A")
                    upload_mbps=$(echo "scale=2; $upload_mbps * 8 / 1000000" | bc 2>/dev/null || echo "N/A")
                fi

                local server_name="Unknown"
                local ping_latency="N/A"
            fi

            if [[ "$download_mbps" != "N/A" && "$upload_mbps" != "N/A" ]]; then
                echo "    测试服务器: $server_name"
                echo "    延迟: ${ping_latency} ms"
                echo "    下载速度: ${download_mbps} Mbps"
                echo "    上传速度: ${upload_mbps} Mbps"
            else
                echo "    speedtest 结果解析失败，尝试备用测试..."
                test_bandwidth_alternative
            fi
        else
            echo "    speedtest 执行失败，尝试备用测试..."
            test_bandwidth_alternative
        fi
    elif command_exists speedtest-cli; then
        echo "  正在使用 speedtest-cli 测试带宽..."
        local result=$(timeout 60 speedtest-cli --simple 2>/dev/null)
        if [[ $? -eq 0 && -n "$result" ]]; then
            echo "$result" | while read line; do
                echo "    $line"
            done
        else
            echo "    speedtest-cli 执行失败，尝试备用测试..."
            test_bandwidth_alternative
        fi
    else
        echo "  speedtest 工具未安装，使用备用测试方法..."
        test_bandwidth_alternative
    fi
    echo ""
}

# 备用带宽测试
test_bandwidth_alternative() {
    echo "    使用curl测试下载速度..."

    if ! command_exists curl; then
        echo "    curl未安装，跳过带宽测试"
        return
    fi

    local test_files=(
        "http://speedtest.tele2.net/1MB.zip:1MB测试文件"
        "https://proof.ovh.net/files/1Mb.dat:OVH 1MB文件"
        "http://ipv4.download.thinkbroadband.com/5MB.zip:5MB测试文件"
    )

    local best_speed=0
    local success=false

    for test_file in "${test_files[@]}"; do
        local url="${test_file%:*}"
        local desc="${test_file#*:}"

        echo "      测试 $desc..."

        # 使用timeout确保不会卡住
        local speed=$(timeout 30 curl -o /dev/null -s -w "%{speed_download}" --connect-timeout 10 --max-time 25 "$url" 2>/dev/null)

        if [[ -n "$speed" && "$speed" != "0.000" ]]; then
            if command_exists bc; then
                local speed_mbps=$(echo "scale=2; $speed * 8 / 1000000" | bc 2>/dev/null)
            else
                # 简单计算，不使用bc
                local speed_mbps=$(awk "BEGIN {printf \"%.2f\", $speed * 8 / 1000000}")
            fi

            if [[ -n "$speed_mbps" ]]; then
                echo "      下载速度: ${speed_mbps} Mbps"
                success=true

                # 记录最佳速度
                if command_exists bc; then
                    if (( $(echo "$speed > $best_speed" | bc -l) )); then
                        best_speed=$speed
                    fi
                fi
                break
            fi
        else
            echo "      测试失败，尝试下一个..."
        fi
    done

    if ! $success; then
        echo "      所有带宽测试都失败了"
        echo "      可能原因: 网络连接问题或防火墙限制"
    fi
}

# 测试路由追踪
test_network_route() {
    echo -e "${cyan}路由追踪测试:${white}"

    local trace_targets=(
        "8.8.8.8:Google"
        "1.1.1.1:Cloudflare"
    )

    for target in "${trace_targets[@]}"; do
        local ip="${target%:*}"
        local name="${target#*:}"

        echo "  追踪到 $name ($ip):"
        if command_exists mtr; then
            mtr -r -c 5 "$ip" 2>/dev/null | head -10 | sed 's/^/    /'
        elif command_exists traceroute; then
            traceroute -m 10 "$ip" 2>/dev/null | head -10 | sed 's/^/    /'
        else
            echo "    路由追踪工具未安装"
        fi
        echo ""
    done
}

# 检查DNS配置
check_dns_config() {
    echo -e "${cyan}当前DNS配置:${white}"

    # 检查/etc/resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        echo "  /etc/resolv.conf内容:"
        while IFS= read -r line; do
            if [[ "$line" =~ ^nameserver ]]; then
                echo "    $line"
            fi
        done < /etc/resolv.conf
    else
        echo "  /etc/resolv.conf 不存在"
    fi

    # 检查systemd-resolved状态
    if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
        echo "  systemd-resolved: 运行中"
        if command_exists resolvectl; then
            echo "  DNS服务器:"
            resolvectl status 2>/dev/null | grep "DNS Servers" | head -3 | sed 's/^/    /'
        fi
    fi
    echo ""
}

# 修复DNS配置
fix_dns_config() {
    info_msg "修复DNS配置..."

    # 检查 systemd-resolved 服务状态
    if systemctl is-active --quiet systemd-resolved; then
        info_msg "检测到 systemd-resolved 正在运行，将配置 systemd-resolved。"
        
        # 备份 resolved.conf
        backup_file /etc/systemd/resolved.conf

        # 配置DNS和FallbackDNS
        sed -i -e 's/#DNS=/DNS=8.8.8.8 1.1.1.1/' \
               -e 's/#FallbackDNS=/FallbackDNS=8.8.4.4 1.0.0.1/' \
               -e 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
        
        # 重启服务
        systemctl restart systemd-resolved
        
        # 确保 /etc/resolv.conf 是指向 systemd-resolved 的存根文件
        if [[ ! -L /etc/resolv.conf ]] || [[ "$(readlink -f /etc/resolv.conf)" != "/run/systemd/resolve/stub-resolv.conf" ]]; then
             ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        fi
        success_msg "systemd-resolved DNS 配置完成。"
    else
        info_msg "未检测到 systemd-resolved，将直接修改 /etc/resolv.conf。"
        # 备份原配置
        backup_file /etc/resolv.conf

        # 设置可靠的DNS服务器
        cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 8.8.4.4
EOF
        success_msg "/etc/resolv.conf 已更新。"
    fi
    cat > /etc/resolv.conf << EOF
# 由security-hardening.sh自动配置
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
nameserver 1.0.0.1
options timeout:2
options attempts:3
EOF

    echo "  已设置DNS服务器:"
    echo "    - 8.8.8.8 (Google DNS)"
    echo "    - 8.8.4.4 (Google DNS)"
    echo "    - 1.1.1.1 (Cloudflare DNS)"
    echo "    - 1.0.0.1 (Cloudflare DNS)"

    # 如果使用systemd-resolved，也配置它
    if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
        echo "  配置systemd-resolved..."

        # 创建systemd-resolved配置
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/dns.conf << EOF
[Resolve]
DNS=8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1
FallbackDNS=114.114.114.114 223.5.5.5
Domains=~.
DNSSEC=no
DNSOverTLS=no
Cache=yes
EOF

        # 重启systemd-resolved
        systemctl restart systemd-resolved
        echo "  systemd-resolved已重启"
    fi

    echo "  DNS配置修复完成"
    echo ""
}

# 测试DNS解析
test_dns_resolution() {
    echo -e "${cyan}DNS解析测试:${white}"

    local test_domains=(
        "google.com"
        "cloudflare.com"
        "github.com"
        "baidu.com"
        "8.8.8.8"  # 直接测试IP
    )

    local failed_count=0
    local total_count=${#test_domains[@]}

    for domain in "${test_domains[@]}"; do
        echo "  测试解析 $domain..."

        # 尝试多种DNS解析方法
        local resolve_result=""
        local resolve_time="N/A"
        local method_used=""

        # 如果是IP地址，直接ping测试
        if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if ping -c 1 -W 3 "$domain" >/dev/null 2>&1; then
                resolve_result="$domain"
                method_used="ping"
            fi
        else
            # 方法1: 使用nslookup
            if [[ -z "$resolve_result" ]] && command_exists nslookup; then
                local start_time=$(date +%s 2>/dev/null)
                resolve_result=$(timeout 10 nslookup "$domain" 8.8.8.8 2>/dev/null | grep -A1 "Name:" | grep "Address:" | head -1 | awk '{print $2}')
                local end_time=$(date +%s 2>/dev/null)

                if [[ -n "$resolve_result" ]]; then
                    method_used="nslookup"
                    if [[ -n "$start_time" && -n "$end_time" ]]; then
                        resolve_time="$((end_time - start_time))s"
                    fi
                fi
            fi

            # 方法2: 使用dig
            if [[ -z "$resolve_result" ]] && command_exists dig; then
                resolve_result=$(timeout 10 dig +short "$domain" @8.8.8.8 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
                if [[ -n "$resolve_result" ]]; then
                    method_used="dig"
                fi
            fi

            # 方法3: 使用host
            if [[ -z "$resolve_result" ]] && command_exists host; then
                resolve_result=$(timeout 10 host "$domain" 8.8.8.8 2>/dev/null | grep "has address" | head -1 | awk '{print $4}')
                if [[ -n "$resolve_result" ]]; then
                    method_used="host"
                fi
            fi

            # 方法4: 使用curl测试连通性
            if [[ -z "$resolve_result" ]]; then
                if timeout 10 curl -s --connect-timeout 5 "http://$domain" >/dev/null 2>&1; then
                    resolve_result="连通"
                    method_used="curl"
                fi
            fi
        fi

        if [[ -n "$resolve_result" ]]; then
            if [[ "$resolve_time" != "N/A" ]]; then
                printf "    %-15s: %s (%s, %s)\n" "$domain" "$resolve_result" "$resolve_time" "$method_used"
            else
                printf "    %-15s: %s (%s)\n" "$domain" "$resolve_result" "$method_used"
            fi
        else
            printf "    %-15s: 解析失败\n" "$domain"
            ((failed_count++))
        fi
    done

    echo ""
    echo "  解析统计: $((total_count - failed_count))/$total_count 成功"

    # 如果失败率超过50%，建议修复DNS
    if [[ $failed_count -gt $((total_count / 2)) ]]; then
        echo -e "  ${red}DNS解析异常，建议修复DNS配置${white}"
        echo ""
        read -p "是否立即修复DNS配置？(Y/n): " fix_dns
        if [[ ! "$fix_dns" =~ ^[Nn]$ ]]; then
            fix_dns_config
            echo "重新测试DNS解析..."
            test_dns_resolution
        fi
    fi
    echo ""
}

# 检测网络质量评分
calculate_network_score() {
    echo -e "${cyan}网络质量评分:${white}"

    local score=100
    local issues=()

    # 检查延迟
    local avg_latency=$(ping -c 4 -W 3 8.8.8.8 2>/dev/null | tail -1 | awk -F'/' '{print $5}' 2>/dev/null)
    if [[ -n "$avg_latency" ]]; then
        if (( $(echo "$avg_latency > 200" | bc -l 2>/dev/null || echo 0) )); then
            score=$((score - 30))
            issues+=("高延迟 (${avg_latency}ms)")
        elif (( $(echo "$avg_latency > 100" | bc -l 2>/dev/null || echo 0) )); then
            score=$((score - 15))
            issues+=("中等延迟 (${avg_latency}ms)")
        fi
    else
        score=$((score - 50))
        issues+=("网络连接异常")
    fi

    # 检查丢包率
    local packet_loss=$(ping -c 10 -W 3 8.8.8.8 2>/dev/null | grep "packet loss" | awk '{print $6}' | tr -d '%')
    if [[ -n "$packet_loss" && "$packet_loss" != "0" ]]; then
        if (( $(echo "$packet_loss > 5" | bc -l 2>/dev/null || echo 0) )); then
            score=$((score - 25))
            issues+=("高丢包率 (${packet_loss}%)")
        elif (( $(echo "$packet_loss > 1" | bc -l 2>/dev/null || echo 0) )); then
            score=$((score - 10))
            issues+=("轻微丢包 (${packet_loss}%)")
        fi
    fi

    # 检查DNS解析
    local dns_ok=false
    if command_exists nslookup; then
        if timeout 10 nslookup google.com >/dev/null 2>&1; then
            dns_ok=true
        fi
    elif command_exists dig; then
        if timeout 10 dig google.com >/dev/null 2>&1; then
            dns_ok=true
        fi
    elif command_exists host; then
        if timeout 10 host google.com >/dev/null 2>&1; then
            dns_ok=true
        fi
    fi

    if ! $dns_ok; then
        score=$((score - 20))
        issues+=("DNS解析异常")
    fi

    # 显示评分
    if [[ $score -ge 90 ]]; then
        echo -e "  总体评分: ${green}$score/100 (优秀)${white}"
    elif [[ $score -ge 70 ]]; then
        echo -e "  总体评分: ${yellow}$score/100 (良好)${white}"
    elif [[ $score -ge 50 ]]; then
        echo -e "  总体评分: ${yellow}$score/100 (一般)${white}"
    else
        echo -e "  总体评分: ${red}$score/100 (较差)${white}"
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        echo "  发现问题:"
        for issue in "${issues[@]}"; do
            echo "    - $issue"
        done
    else
        echo "  网络状况良好"
    fi
    echo ""
}

# 生成网络质量报告
generate_network_report() {
    local report_file="$config_dir/network_quality_report.txt"

    {
        echo "网络质量检测报告"
        echo "=================="
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "服务器IP: $IPV4_ADDRESS"
        echo "地理位置: $COUNTRY"
        echo ""

        echo "延迟测试结果:"
        ping -c 4 8.8.8.8 2>/dev/null | tail -1 || echo "测试失败"
        echo ""

        echo "带宽测试结果:"
        if command_exists speedtest; then
            speedtest --accept-license --accept-gdpr 2>/dev/null || echo "测试失败"
        else
            echo "speedtest工具未安装"
        fi
        echo ""

        echo "DNS解析测试:"
        for domain in google.com cloudflare.com github.com; do
            echo "$domain: $(nslookup $domain 2>/dev/null | grep "Address" | tail -1 | awk '{print $2}' || echo "解析失败")"
        done
        echo ""

    } > "$report_file"

    success_msg "网络质量报告已保存到: $report_file"
}

# 完整的网络质量测试
test_network_quality() {
    clear
    echo -e "${pink}网络质量检测${white}"
    echo "================================"

    echo "正在检测服务器网络质量，请稍候..."
    echo ""

    # 检查基本网络连接
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${red}错误: 无法连接到外网，请检查网络连接${white}"
        echo ""
        echo "可能的原因："
        echo "1. 网络接口未正确配置"
        echo "2. 防火墙阻止了网络连接"
        echo "3. DNS配置问题"
        echo "4. 路由配置问题"
        echo ""
        if [[ "$1" != "--non-interactive" ]]; then
            break_end
        fi
        return 1
    fi

    # 安装必要工具（静默模式，减少输出）
    echo "正在检查网络测试工具..."
    install_network_tools >/dev/null 2>&1

    echo "开始网络质量检测..."
    echo ""

    # 执行各项测试
    test_network_latency
    test_dns_resolution
    test_network_bandwidth
    test_network_route
    calculate_network_score

    # 生成报告
    generate_network_report

    echo -e "${yellow}优化建议:${white}"
    echo "1. 如果延迟较高，考虑更换服务器位置"
    echo "2. 如果带宽不足，考虑升级服务器套餐"
    echo "3. 如果DNS解析异常，使用 './security-hardening.sh --fix-dns' 修复"
    echo "4. 定期进行网络质量检测以监控性能"
    echo "5. 可以使用 './security-hardening.sh --test-network' 进行快速测试"
    echo ""

    if [[ "$1" != "--non-interactive" ]]; then
        break_end
    fi
}
#endregion

#region //一键部署模块
# 执行一键部署
execute_one_click_deploy() {
    clear
    echo -e "${pink}开始一键部署...${white}"
    echo "================================"

    local total_steps=10
    local current_step=0

    # 步骤1: 系统环境检测
    ((current_step++))
    show_progress $current_step $total_steps "系统环境检测"
    detect_system_environment

    # 步骤2: SSH安全配置
    ((current_step++))
    show_progress $current_step $total_steps "SSH安全配置"
    echo "配置SSH安全设置..."
    change_ssh_port "$SSH_DEFAULT_PORT"
    setup_ssh_keys
    configure_ssh_security_settings
    restart_ssh_service

    # 步骤3: 防火墙配置
    ((current_step++))
    show_progress $current_step $total_steps "防火墙配置"
    echo "配置防火墙规则..."
    local fw_type=$(detect_firewall_type)
    if [[ "$fw_type" == "none" ]]; then
        install_firewall ufw
        fw_type="ufw"
    fi
    case $fw_type in
        ufw) configure_ufw ;;
        iptables) configure_iptables ;;
    esac

    # 步骤4: 系统优化
    ((current_step++))
    show_progress $current_step $total_steps "系统优化"
    echo "优化系统参数..."
    enable_bbr
    optimize_network_parameters
    optimize_file_limits
    configure_swap

    # 步骤5: fail2ban安装
    ((current_step++))
    show_progress $current_step $total_steps "fail2ban安装"
    echo "安装fail2ban..."
    install_fail2ban
    configure_fail2ban
    start_fail2ban_service

    # 步骤6: Xray-core安装
    ((current_step++))
    show_progress $current_step $total_steps "Xray-core安装"
    echo "安装Xray-core..."
    local arch=$(detect_architecture)
    local version=$(get_latest_xray_version)
    create_xray_directories
    download_xray "$version" "$arch"
    create_xray_service

    # 步骤7: VLESS-HTTP2-REALITY配置
    ((current_step++))
    show_progress $current_step $total_steps "VLESS-HTTP2-REALITY配置"
    echo "配置VLESS-HTTP2-REALITY..."
    local user_uuid=$(generate_uuid)
    local keys_output=$(generate_x25519_keys)
    local private_key=$(echo "$keys_output" | grep "Private key" | cut -d: -f2 | tr -d ' ')
    local public_key=$(echo "$keys_output" | grep "Public key" | cut -d: -f2 | tr -d ' ')
    local dest=$(select_target_website)
    local server_names=$(get_sni_from_dest "$dest")
    local short_ids=$(generate_short_ids)

    create_vless_reality_config "$user_uuid" "$private_key" "$public_key" "$dest" "$server_names" "$short_ids" "443"
    save_proxy_config "$user_uuid" "$public_key" "$dest" "$server_names" "$short_ids" "443"
    test_xray_config

    # 步骤8: 服务启动
    ((current_step++))
    show_progress $current_step $total_steps "启动服务"
    echo "启动Xray服务..."
    start_xray_service

    # 步骤9: 客户端配置生成
    ((current_step++))
    show_progress $current_step $total_steps "生成客户端配置"
    echo "生成客户端配置..."
    save_client_configs

    # 步骤10: 完成部署
    ((current_step++))
    show_progress $current_step $total_steps "部署完成"

    # 显示部署结果
    show_deployment_result
}

# 显示部署结果
show_deployment_result() {
    clear
    echo -e "${green}🎉 一键部署完成！${white}"
    echo "================================"

    # 读取配置信息
    if [[ -f "$config_dir/proxy_config.conf" ]]; then
        . "$config_dir/proxy_config.conf"
    fi

    echo -e "${cyan}部署摘要:${white}"
    echo "✅ SSH安全配置完成"
    echo "   - 端口: $SSH_DEFAULT_PORT"
    echo "   - 密钥认证已启用"
    echo "   - 密码认证已禁用"
    echo ""
    echo "✅ 防火墙配置完成"
    echo "   - 默认拒绝策略"
    echo "   - DDoS防护已启用"
    echo ""
    echo "✅ 系统优化完成"
    echo "   - BBR拥塞控制已启用"
    echo "   - 网络参数已优化"
    echo "   - SWAP已配置"
    echo ""
    echo "✅ fail2ban已安装"
    echo "   - SSH暴力破解防护"
    echo "   - 自动封禁恶意IP"
    echo ""
    echo "✅ VLESS-HTTP2-REALITY已配置"
    echo "   - 服务器 (IPv4): $SERVER_IPV4:443"
    if [[ "$SERVER_IPV6" != "不支持" && "$SERVER_IPV6" != "" ]]; then
        echo "   - 服务器 (IPv6): [$SERVER_IPV6]:443"
    fi
    echo "   - 协议: VLESS-HTTP2-REALITY"
    echo "   - 状态: $(systemctl is-active xray 2>/dev/null || echo "未知")"
    echo ""

    echo -e "${yellow}重要信息:${white}"
    echo "🔑 SSH私钥:"
    echo "================================"
    if [[ -f ~/.ssh/id_rsa ]]; then
        echo "已保存至 ~/.ssh/id_rsa，请妥善保管。"
    fi
    echo "================================"
    echo ""

    echo "📱 VLESS分享链接:"
    echo "================================"
    if [[ -f "$config_dir/client_configs/vless_share_link.txt" ]]; then
        echo "已保存至 $config_dir/client_configs/vless_share_link.txt"
    fi
    echo "================================"
    echo ""

    . "$config_dir/proxy_config.conf"

    echo "✅ VLESS-HTTP2-REALITY 部署完成"
    echo "================================"
    echo ""
    echo "💻 服务器信息:"
    echo "================================"
    echo "  - IPv4地址: $SERVER_IPV4"
    if [[ "$SERVER_IPV6" != "不支持" && "$SERVER_IPV6" != "" ]]; then
        echo "  - IPv6地址: $SERVER_IPV6"
    fi
    echo "  - 端口: $LISTEN_PORT"
    echo "  - 用户UUID: $USER_UUID"
    echo "================================"
    echo ""

    echo -e "${red}⚠️  重要提醒:${white}"
    echo "1. 请立即保存SSH私钥，用于后续登录"
    echo "2. 新的SSH端口: $SSH_DEFAULT_PORT"
    echo "3. 请在断开前测试新的SSH连接"
    echo "4. 客户端配置文件位于: $config_dir/client_configs/"
    echo "5. 建议重启系统以确保所有优化生效"
    echo ""

    echo -e "${green}🎯 下一步操作:${white}"
    echo "1. 保存SSH私钥到本地"
    echo "2. 使用新端口测试SSH连接"
    echo "3. 下载客户端配置文件"
    echo "4. 测试代理连接"
    echo "5. 重启服务器(可选)"
    echo ""

    read -p "按任意键继续..." -n 1 -s
    echo ""
}
#endregion

#region //系统检测模块
# 全局系统信息变量
OS=""
DIST=""
PKG_MANAGER=""
ARCH=""
COUNTRY=""
IPV4_ADDRESS=""
IPV6_ADDRESS=""

# 检测操作系统
detect_os() {
    info_msg "检测操作系统..."

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        DIST=$VERSION_ID

        case $OS in
            ubuntu|debian)
                PKG_MANAGER="apt"
                ;;
            centos|rhel|rocky|almalinux)
                PKG_MANAGER="yum"
                if command -v dnf > /dev/null; then
                    PKG_MANAGER="dnf"
                fi
                ;;
            fedora)
                PKG_MANAGER="dnf"
                ;;
            *)
                warn_msg "未知的操作系统: $OS"
                PKG_MANAGER="unknown"
                ;;
        esac
    else
        error_exit "无法检测操作系统版本"
    fi

    # 检测架构
    ARCH=$(uname -m)

    success_msg "系统检测完成: $OS $DIST ($ARCH), 包管理器: $PKG_MANAGER"
}

# 检测地理位置
detect_geographic_location() {
    info_msg "检测地理位置..."

    # 尝试多个服务检测地理位置
    COUNTRY=$(curl -s --max-time 3 ipinfo.io/country 2>/dev/null)

    if [[ -z "$COUNTRY" ]]; then
        COUNTRY=$(curl -s --max-time 3 cip.cc 2>/dev/null | grep -o "中国" | head -1)
        if [[ "$COUNTRY" == "中国" ]]; then
            COUNTRY="CN"
        fi
    fi

    if [[ -z "$COUNTRY" ]]; then
        warn_msg "无法检测地理位置，将使用默认设置"
        COUNTRY="UNKNOWN"
    else
        if [[ "$COUNTRY" == "CN" ]]; then
            success_msg "检测到国内环境，将使用国内镜像源"
        else
            success_msg "检测到海外环境: $COUNTRY"
        fi
    fi
}

# 检测网络地址
detect_network_addresses() {
    info_msg "检测网络地址..."

    # 检测IPv4地址
    IPV4_ADDRESS=$(curl -s --max-time 5 -4 ipv4.ip.sb 2>/dev/null)
    if [[ -z "$IPV4_ADDRESS" ]]; then
        IPV4_ADDRESS=$(curl -s --max-time 5 -4 ifconfig.me 2>/dev/null)
    fi

    # 检测IPv6地址
    IPV6_ADDRESS=$(curl -s --max-time 5 -6 ipv6.ip.sb 2>/dev/null)
    if [[ -z "$IPV6_ADDRESS" ]]; then
        IPV6_ADDRESS="不支持"
    fi

    if [[ -n "$IPV4_ADDRESS" ]]; then
        success_msg "IPv4地址: $IPV4_ADDRESS"
    else
        warn_msg "无法获取IPv4地址"
    fi

    if [[ "$IPV6_ADDRESS" != "不支持" ]]; then
        success_msg "IPv6地址: $IPV6_ADDRESS"
    else
        info_msg "IPv6: 不支持或未配置"
    fi
}

# 检测系统资源
detect_system_resources() {
    info_msg "检测系统资源..."

    # CPU信息
    local cpu_cores=$(nproc)
    local cpu_model=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}' 2>/dev/null || echo "未知")

    # 内存信息
    local mem_total=$(free -h | awk 'NR==2{print $2}')
    local mem_used=$(free -h | awk 'NR==2{print $3}')

    # 磁盘信息
    local disk_info=$(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')

    echo -e "${cyan}系统资源信息:${white}"
    echo "  CPU: $cpu_model ($cpu_cores 核心)"
    echo "  内存: $mem_used/$mem_total"
    echo "  磁盘: $disk_info"
}

# 完整的系统环境检测
detect_system_environment() {
    echo -e "${pink}正在进行系统环境检测...${white}"
    echo "================================"

    detect_os
    detect_geographic_location
    detect_network_addresses
    detect_system_resources

    echo "================================"
    success_msg "系统环境检测完成"

    # 保存检测结果到配置文件
    cat > "$config_dir/system_info.conf" << EOF
OS=$OS
DIST=$DIST
PKG_MANAGER=$PKG_MANAGER
ARCH=$ARCH
COUNTRY=$COUNTRY
IPV4_ADDRESS=$IPV4_ADDRESS
IPV6_ADDRESS=$IPV6_ADDRESS
DETECTION_TIME=$(date '+%Y-%m-%d %H:%M:%S')
EOF
}
#endregion

#region //配置管理模块
# 备份配置文件
backup_all_configs() {
    info_msg "备份所有配置文件..."

    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$backup_dir/full_backup_$backup_timestamp"

    mkdir -p "$backup_path"

    # 备份SSH配置
    if [[ -f "$SSH_CONFIG" ]]; then
        cp "$SSH_CONFIG" "$backup_path/sshd_config"
        echo "  ✓ SSH配置已备份"
    fi

    # 备份Xray配置
    if [[ -f "$XRAY_CONFIG_FILE" ]]; then
        cp "$XRAY_CONFIG_FILE" "$backup_path/xray_config.json"
        echo "  ✓ Xray配置已备份"
    fi

    # 备份fail2ban配置
    if [[ -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.local "$backup_path/fail2ban_jail.local"
        echo "  ✓ fail2ban配置已备份"
    fi

    # 备份防火墙规则
    if command_exists ufw; then
        ufw status numbered > "$backup_path/ufw_rules.txt" 2>/dev/null
        echo "  ✓ UFW规则已备份"
    fi

    if command_exists iptables; then
        iptables-save > "$backup_path/iptables_rules.txt" 2>/dev/null
        echo "  ✓ iptables规则已备份"
    fi

    # 备份代理配置信息
    if [[ -f "$config_dir/proxy_config.conf" ]]; then
        cp "$config_dir/proxy_config.conf" "$backup_path/proxy_config.conf"
        echo "  ✓ 代理配置信息已备份"
    fi

    # 备份系统信息
    if [[ -f "$config_dir/system_info.conf" ]]; then
        cp "$config_dir/system_info.conf" "$backup_path/system_info.conf"
        echo "  ✓ 系统信息已备份"
    fi

    # 创建备份清单
    cat > "$backup_path/backup_info.txt" << EOF
备份信息
========
备份时间: $(date '+%Y-%m-%d %H:%M:%S')
备份路径: $backup_path
脚本版本: $version
系统信息: $(uname -a)

备份文件列表:
$(ls -la "$backup_path")
EOF

    success_msg "配置备份完成！备份路径: $backup_path"
}

# 恢复配置文件
restore_configs() {
    clear
    echo -e "${pink}配置恢复${white}"
    echo "================================"

    # 列出可用的备份
    echo "可用的备份："
    local backup_count=0
    local backup_list=()

    if [[ -d "$backup_dir" ]]; then
        while IFS= read -r -d '' backup; do
            backup_count=$((backup_count + 1))
            backup_list+=("$backup")
            echo "$backup_count. $(basename "$backup")"
        done < <(find "$backup_dir" -maxdepth 1 -type d -name "full_backup_*" -print0 | sort -z)
    fi

    if [[ $backup_count -eq 0 ]]; then
        warn_msg "没有找到可用的备份"
        break_end
        return
    fi

    echo ""
    read -p "请选择要恢复的备份 [1-$backup_count]: " choice

    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [[ $choice -lt 1 ]] || [[ $choice -gt $backup_count ]]; then
        warn_msg "无效选择"
        break_end
        return
    fi

    local selected_backup="${backup_list[$((choice-1))]}"

    echo ""
    echo -e "${yellow}警告：恢复配置将覆盖当前配置文件${white}"
    echo "选择的备份: $(basename "$selected_backup")"

    if ! confirm_operation "配置恢复"; then
        info_msg "操作已取消"
        return
    fi

    # 执行恢复
    info_msg "正在恢复配置..."

    # 恢复SSH配置
    if [[ -f "$selected_backup/sshd_config" ]]; then
        cp "$selected_backup/sshd_config" "$SSH_CONFIG"
        echo "  ✓ SSH配置已恢复"
    fi

    # 恢复Xray配置
    if [[ -f "$selected_backup/xray_config.json" ]]; then
        mkdir -p "$(dirname "$XRAY_CONFIG_FILE")"
        cp "$selected_backup/xray_config.json" "$XRAY_CONFIG_FILE"
        echo "  ✓ Xray配置已恢复"
    fi

    # 恢复fail2ban配置
    if [[ -f "$selected_backup/fail2ban_jail.local" ]]; then
        cp "$selected_backup/fail2ban_jail.local" /etc/fail2ban/jail.local
        echo "  ✓ fail2ban配置已恢复"
    fi

    # 恢复代理配置信息
    if [[ -f "$selected_backup/proxy_config.conf" ]]; then
        cp "$selected_backup/proxy_config.conf" "$config_dir/proxy_config.conf"
        echo "  ✓ 代理配置信息已恢复"
    fi

    success_msg "配置恢复完成！"

    echo ""
    echo -e "${yellow}注意：${white}"
    echo "1. 配置恢复后建议重启相关服务"
    echo "2. 请验证配置文件的正确性"
    echo "3. 如有问题可以重新恢复其他备份"

    break_end
}

# 导出配置
export_configs() {
    clear
    echo -e "${pink}导出配置${white}"
    echo "================================"

    local export_timestamp=$(date +%Y%m%d_%H%M%S)
    local export_file="$config_dir/config_export_$export_timestamp.tar.gz"

    info_msg "正在导出配置..."

    # 创建临时目录
    local temp_dir="/tmp/config_export_$$"
    mkdir -p "$temp_dir"

    # 收集配置文件
    if [[ -f "$SSH_CONFIG" ]]; then
        cp "$SSH_CONFIG" "$temp_dir/sshd_config"
    fi

    if [[ -f "$XRAY_CONFIG_FILE" ]]; then
        cp "$XRAY_CONFIG_FILE" "$temp_dir/xray_config.json"
    fi

    if [[ -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.local "$temp_dir/fail2ban_jail.local"
    fi

    if [[ -f "$config_dir/proxy_config.conf" ]]; then
        cp "$config_dir/proxy_config.conf" "$temp_dir/proxy_config.conf"
    fi

    # 导出防火墙规则
    if command_exists ufw; then
        ufw status numbered > "$temp_dir/ufw_rules.txt" 2>/dev/null
    fi

    if command_exists iptables; then
        iptables-save > "$temp_dir/iptables_rules.txt" 2>/dev/null
    fi

    # 创建导出信息文件
    cat > "$temp_dir/export_info.txt" << EOF
配置导出信息
============
导出时间: $(date '+%Y-%m-%d %H:%M:%S')
脚本版本: $version
系统信息: $(uname -a)
服务器IP: $IPV4_ADDRESS

导出文件说明:
- sshd_config: SSH服务配置
- xray_config.json: Xray代理配置
- fail2ban_jail.local: fail2ban防护配置
- proxy_config.conf: 代理配置信息
- ufw_rules.txt: UFW防火墙规则
- iptables_rules.txt: iptables防火墙规则
EOF

    # 打包配置文件
    tar -czf "$export_file" -C "$temp_dir" . 2>/dev/null

    # 清理临时目录
    rm -rf "$temp_dir"

    if [[ -f "$export_file" ]]; then
        success_msg "配置导出完成！"
        echo "导出文件: $export_file"
        echo "文件大小: $(du -h "$export_file" | awk '{print $1}')"
        echo ""
        echo -e "${yellow}使用方法：${white}"
        echo "1. 下载导出文件到本地保存"
        echo "2. 在新服务器上使用导入功能恢复配置"
        echo "3. 可以通过SCP等工具传输文件"
    else
        error_exit "配置导出失败"
    fi

    break_end
}

# 导入配置
import_configs() {
    clear
    echo -e "${pink}导入配置${white}"
    echo "================================"

    local import_file
    prompt_for_input "请输入要导入的备份文件路径 (.tar.gz): " import_file validate_file_exists

    if [[ ! -f "$import_file" ]]; then
        warn_msg "文件不存在: $import_file"
        break_end
        return
    fi

    # 检查文件格式
    if [[ ! "$import_file" =~ \.tar\.gz$ ]]; then
        warn_msg "不支持的文件格式，请使用.tar.gz格式"
        break_end
        return
    fi

    echo ""
    echo -e "${yellow}警告：导入配置将覆盖当前配置${white}"

    if ! confirm_operation "配置导入"; then
        info_msg "操作已取消"
        return
    fi

    # 创建临时目录
    local temp_dir="/tmp/config_import_$$"
    mkdir -p "$temp_dir"

    # 解压配置文件
    if tar -xzf "$import_file" -C "$temp_dir" 2>/dev/null; then
        info_msg "正在导入配置..."

        # 导入SSH配置
        if [[ -f "$temp_dir/sshd_config" ]]; then
            cp "$temp_dir/sshd_config" "$SSH_CONFIG"
            echo "  ✓ SSH配置已导入"
        fi

        # 导入Xray配置
        if [[ -f "$temp_dir/xray_config.json" ]]; then
            mkdir -p "$(dirname "$XRAY_CONFIG_FILE")"
            cp "$temp_dir/xray_config.json" "$XRAY_CONFIG_FILE"
            echo "  ✓ Xray配置已导入"
        fi

        # 导入fail2ban配置
        if [[ -f "$temp_dir/fail2ban_jail.local" ]]; then
            cp "$temp_dir/fail2ban_jail.local" /etc/fail2ban/jail.local
            echo "  ✓ fail2ban配置已导入"
        fi

        # 导入代理配置信息
        if [[ -f "$temp_dir/proxy_config.conf" ]]; then
            cp "$temp_dir/proxy_config.conf" "$config_dir/proxy_config.conf"
            echo "  ✓ 代理配置信息已导入"
        fi

        success_msg "配置导入完成！"

        echo ""
        echo -e "${yellow}注意：${white}"
        echo "1. 配置导入后需要重启相关服务"
        echo "2. 请检查配置文件的正确性"
        echo "3. 建议先测试配置再正式使用"

    else
        error_exit "配置文件解压失败"
    fi

    # 清理临时目录
    rm -rf "$temp_dir"

    break_end
}

# 配置管理主菜单
configuration_management() {
    while true; do
        clear
        echo -e "${pink}配置管理${white}"
        echo "================================"
        echo "1. 备份所有配置"
        echo "2. 恢复配置"
        echo "3. 导出配置"
        echo "4. 导入配置"
        echo "5. 查看备份列表"
        echo "6. 清理旧备份"
        echo "================================"
        echo "0. 返回主菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择操作 [0-6]: " choice validate_numeric_range 0 6

        case $choice in
            1) backup_all_configs; break_end ;;
            2) restore_configs ;;
            3) export_configs ;;
            4) import_configs ;;
            5)
                echo -e "${cyan}备份文件列表:${white}"
                if [[ -d "$backup_dir" ]]; then
                    ls -la "$backup_dir" | grep "full_backup_" || echo "没有找到备份文件"
                else
                    echo "备份目录不存在"
                fi
                break_end
                ;;
            6)
                echo "清理30天前的备份文件..."
                if [[ -d "$backup_dir" ]]; then
                    find "$backup_dir" -name "full_backup_*" -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null
                    success_msg "旧备份清理完成"
                else
                    echo "备份目录不存在"
                fi
                break_end
                ;;
            0) break ;;
        esac
    done
}
#endregion

#region //测试工具模块
# 连接测试
test_connections() {
    clear
    echo -e "${pink}连接测试${white}"
    echo "================================"

    echo -e "${cyan}正在测试各项连接...${white}"
    echo ""

    # SSH连接测试
    echo -e "${yellow}1. SSH连接测试${white}"
    local ssh_port=$(grep -E "^Port " "$SSH_CONFIG" | awk '{print $2}' 2>/dev/null || echo "22")
    if netstat -tlnp | grep ":$ssh_port " >/dev/null 2>&1; then
        echo "  ✓ SSH服务正在监听端口 $ssh_port"
    else
        echo "  ✗ SSH服务未在端口 $ssh_port 监听"
    fi

    # Xray连接测试
    echo -e "${yellow}2. Xray连接测试${white}"
    if [[ -f "$XRAY_SERVICE_FILE" ]]; then
        if systemctl is-active xray >/dev/null 2>&1; then
            echo "  ✓ Xray服务运行正常"

            # 检查端口监听
            if [[ -f "$config_dir/proxy_config.conf" ]]; then
                . "$config_dir/proxy_config.conf"
                if netstat -tlnp | grep ":$LISTEN_PORT " >/dev/null 2>&1; then
                    echo "  ✓ Xray正在监听端口 $LISTEN_PORT"
                else
                    echo "  ✗ Xray未在端口 $LISTEN_PORT 监听"
                fi
            fi
        else
            echo "  ✗ Xray服务未运行"
        fi
    else
        echo "  - Xray服务未安装"
    fi

    # 防火墙测试
    echo -e "${yellow}3. 防火墙测试${white}"
    if command_exists ufw; then
        if ufw status | grep -q "Status: active"; then
            echo "  ✓ UFW防火墙已启用"
        else
            echo "  ⚠ UFW防火墙未启用"
        fi
    fi

    # 网络连通性测试
    echo -e "${yellow}4. 网络连通性测试${white}"
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "  ✓ 外网连接正常"
    else
        echo "  ✗ 外网连接异常"
    fi

    if ping -c 1 127.0.0.1 >/dev/null 2>&1; then
        echo "  ✓ 本地回环正常"
    else
        echo "  ✗ 本地回环异常"
    fi

    # DNS解析测试
    echo -e "${yellow}5. DNS解析测试${white}"
    if nslookup google.com >/dev/null 2>&1; then
        echo "  ✓ DNS解析正常"
    else
        echo "  ✗ DNS解析异常"
    fi

    echo ""
    success_msg "连接测试完成"
    break_end
}

# 性能测试
test_performance() {
    clear
    echo -e "${pink}性能测试${white}"
    echo "================================"

    echo -e "${cyan}正在进行性能测试...${white}"
    echo ""

    # CPU测试
    echo -e "${yellow}1. CPU信息${white}"
    echo "  CPU型号: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//')"
    echo "  CPU核心数: $(nproc)"
    echo "  当前负载: $(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')"

    # 内存测试
    echo -e "${yellow}2. 内存信息${white}"
    local mem_info=$(free -h | awk 'NR==2{printf "总计:%s 已用:%s 可用:%s 使用率:%.1f%%", $2,$3,$7,($3/$2)*100}')
    echo "  $mem_info"

    # 磁盘测试
    echo -e "${yellow}3. 磁盘信息${white}"
    echo "  根分区使用情况:"
    df -h / | tail -1 | awk '{printf "    总计:%s 已用:%s 可用:%s 使用率:%s\n", $2,$3,$4,$5}'

    # 网络测试
    echo -e "${yellow}4. 网络测试${white}"
    echo "  正在测试网络延迟..."
    local ping_result=$(ping -c 4 8.8.8.8 2>/dev/null | tail -1 | awk -F'/' '{print $5}' 2>/dev/null)
    if [[ -n "$ping_result" ]]; then
        echo "  平均延迟: ${ping_result}ms"
    else
        echo "  网络延迟测试失败"
    fi

    # 如果安装了speedtest，进行带宽测试
    if command_exists speedtest; then
        echo "  正在测试网络带宽..."
        speedtest --accept-license --accept-gdpr 2>/dev/null | grep -E "(Download|Upload)" || echo "  带宽测试失败"
    else
        echo "  带宽测试工具未安装"
    fi

    # I/O测试
    echo -e "${yellow}5. 磁盘I/O测试${white}"
    echo "  正在测试磁盘写入速度..."
    local write_speed=$(dd if=/dev/zero of=/tmp/test_write bs=1M count=100 2>&1 | grep -o '[0-9.]\+ MB/s' | tail -1)
    if [[ -n "$write_speed" ]]; then
        echo "  写入速度: $write_speed"
    else
        echo "  磁盘写入测试失败"
    fi
    rm -f /tmp/test_write

    echo "  正在测试磁盘读取速度..."
    local read_speed=$(dd if=/dev/zero of=/tmp/test_read bs=1M count=100 2>/dev/null && dd if=/tmp/test_read of=/dev/null bs=1M 2>&1 | grep -o '[0-9.]\+ MB/s' | tail -1)
    if [[ -n "$read_speed" ]]; then
        echo "  读取速度: $read_speed"
    else
        echo "  磁盘读取测试失败"
    fi
    rm -f /tmp/test_read

    echo ""
    success_msg "性能测试完成"
    break_end
}

# 安全测试
test_security() {
    clear
    echo -e "${pink}安全测试${white}"
    echo "================================"

    echo -e "${cyan}正在进行安全检查...${white}"
    echo ""

    # SSH安全检查
    echo -e "${yellow}1. SSH安全检查${white}"

    if grep -q "^PermitRootLogin no" "$SSH_CONFIG"; then
        echo "  ✓ Root登录已禁用"
    else
        echo "  ✗ Root登录未禁用"
    fi

    if grep -q "^PasswordAuthentication no" "$SSH_CONFIG"; then
        echo "  ✓ 密码认证已禁用"
    else
        echo "  ✗ 密码认证未禁用"
    fi

    local ssh_port=$(grep -E "^Port " "$SSH_CONFIG" | awk '{print $2}' 2>/dev/null || echo "22")
    if [[ "$ssh_port" != "22" ]]; then
        echo "  ✓ SSH端口已修改: $ssh_port"
    else
        echo "  ⚠ SSH使用默认端口22"
    fi

    # 防火墙检查
    echo -e "${yellow}2. 防火墙检查${white}"

    if command_exists ufw; then
        if ufw status | grep -q "Status: active"; then
            echo "  ✓ UFW防火墙已启用"
            local rule_count=$(ufw status numbered | grep -c "^\[")
            echo "  ✓ 防火墙规则数: $rule_count"
        else
            echo "  ✗ UFW防火墙未启用"
        fi
    fi

    # fail2ban检查
    echo -e "${yellow}3. fail2ban检查${white}"

    if command_exists fail2ban-client; then
        if systemctl is-active fail2ban >/dev/null 2>&1; then
            echo "  ✓ fail2ban服务运行正常"
            local banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "0")
            echo "  ✓ 当前封禁IP数: $banned_count"
        else
            echo "  ✗ fail2ban服务未运行"
        fi
    else
        echo "  ✗ fail2ban未安装"
    fi

    # 系统更新检查
    echo -e "${yellow}4. 系统更新检查${white}"

    case $PKG_MANAGER in
        apt)
            local updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo "0")
            if [[ $updates -gt 0 ]]; then
                echo "  ⚠ 有 $updates 个软件包可更新"
            else
                echo "  ✓ 系统已是最新版本"
            fi
            ;;
        yum|dnf)
            local updates=$(yum check-update 2>/dev/null | grep -c "updates" || echo "0")
            if [[ $updates -gt 0 ]]; then
                echo "  ⚠ 有 $updates 个软件包可更新"
            else
                echo "  ✓ 系统已是最新版本"
            fi
            ;;
    esac

    # 开放端口检查
    echo -e "${yellow}5. 开放端口检查${white}"

    echo "  当前监听的端口:"
    netstat -tlnp | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -n | uniq | while read port; do
        echo "    - 端口 $port"
    done

    # 用户检查
    echo -e "${yellow}6. 用户安全检查${white}"

    local user_count=$(cat /etc/passwd | grep -c "/bin/bash\|/bin/sh")
    echo "  ✓ 系统用户数: $user_count"

    local sudo_users=$(grep -c "sudo\|wheel" /etc/group 2>/dev/null || echo "0")
    echo "  ✓ 管理员用户数: $sudo_users"

    echo ""
    success_msg "安全测试完成"
    break_end
}

# 测试工具主菜单
test_tools_menu() {
    while true; do
        clear
        echo -e "${pink}测试工具${white}"
        echo "================================"
        echo "1. 连接测试"
        echo "2. 性能测试"
        echo "3. 安全测试"
        echo "4. 网络质量检测"
        echo "5. DNS解析修复"
        echo "6. 配置文件验证"
        echo "7. 服务状态检查"
        echo "================================"
        echo "0. 返回主菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择测试项目 [0-7]: " choice validate_numeric_range 0 7

        case $choice in
            1) test_connections ;;
            2) test_performance ;;
            3) test_security ;;
            4) test_network_quality ;;
            5)
                clear
                echo -e "${pink}DNS解析修复${white}"
                echo "================================"

                # 检查当前DNS配置
                check_dns_config

                # 测试DNS解析
                test_dns_resolution

                break_end
                ;;
            6)
                echo -e "${cyan}配置文件验证:${white}"
                echo ""

                # SSH配置验证
                echo "SSH配置验证:"
                if sshd -t 2>/dev/null; then
                    echo "  ✓ SSH配置文件语法正确"
                else
                    echo "  ✗ SSH配置文件有语法错误"
                fi

                # Xray配置验证
                if [[ -f "$XRAY_CONFIG_FILE" ]]; then
                    echo "Xray配置验证:"
                    if [[ -f "$XRAY_BINARY" ]] && "$XRAY_BINARY" test -c "$XRAY_CONFIG_FILE" 2>/dev/null; then
                        echo "  ✓ Xray配置文件语法正确"
                    else
                        echo "  ✗ Xray配置文件有语法错误"
                    fi
                else
                    echo "Xray配置文件不存在"
                fi

                break_end
                ;;
            7) show_all_services_status ;;
            0) break ;;
        esac
    done
}
#endregion

#region //快速工具安装模块
# 安装常用开发工具
install_dev_tools() {
    clear
    echo -e "${pink}安装常用开发工具${white}"
    echo "================================"

    echo "将安装以下开发工具："
    echo "1. Git 版本控制"
    echo "2. Vim 编辑器"
    echo "3. Htop 系统监控"
    echo "4. Tree 目录树显示"
    echo "5. Unzip/Zip 压缩工具"
    echo "6. Curl/Wget 下载工具"
    echo ""

    if ! confirm_operation "安装开发工具"; then
        info_msg "操作已取消"
        return
    fi

    info_msg "正在安装开发工具..."

    case $PKG_MANAGER in
        apt)
            install_package "git vim htop tree unzip zip curl wget build-essential" true
            ;;
        yum|dnf)
            install_package "git vim htop tree unzip zip curl wget gcc gcc-c++ make" true
            ;;
    esac

    success_msg "开发工具安装完成！"
    break_end
}

# 安装系统监控工具
install_monitor_tools() {
    clear
    echo -e "${pink}安装系统监控工具${white}"
    echo "================================"

    echo "将安装以下监控工具："
    echo "1. Htop - 进程监控"
    echo "2. Iotop - IO监控"
    echo "3. Nethogs - 网络监控"
    echo "4. Ncdu - 磁盘使用分析"
    echo "5. Glances - 综合监控"
    echo ""

    if ! confirm_operation "安装监控工具"; then
        info_msg "操作已取消"
        return
    fi

    info_msg "正在安装监控工具..."

    case $PKG_MANAGER in
        apt)
            install_package "htop iotop nethogs ncdu glances" true
            ;;
        yum|dnf)
            install_package "htop iotop nethogs ncdu glances" true
            ;;
    esac

    success_msg "监控工具安装完成！"
    echo ""
    echo -e "${yellow}使用说明：${white}"
    echo "  htop     - 查看进程和系统资源"
    echo "  iotop    - 查看磁盘IO使用情况"
    echo "  nethogs  - 查看网络使用情况"
    echo "  ncdu     - 分析磁盘空间使用"
    echo "  glances  - 综合系统监控"
    echo ""
    break_end
}

# 配置Git环境
configure_git_environment() {
    clear
    echo -e "${pink}配置Git环境${white}"
    echo "================================"

    echo "配置Git全局设置..."
    echo ""

    read -p "请输入Git用户名: " git_username
    read -p "请输入Git邮箱: " git_email

    if [[ -z "$git_username" || -z "$git_email" ]]; then
        warn_msg "用户名和邮箱不能为空"
        break_end
        return
    fi

    info_msg "正在配置Git环境..."

    # 配置Git全局设置
    git config --global user.name "$git_username"
    git config --global user.email "$git_email"
    git config --global core.editor vim
    git config --global color.ui auto
    git config --global init.defaultBranch main

    # 配置Git别名
    git config --global alias.st status
    git config --global alias.co checkout
    git config --global alias.br branch
    git config --global alias.ci commit
    git config --global alias.lg "log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"

    success_msg "Git环境配置完成！"
    echo ""
    echo -e "${yellow}配置信息：${white}"
    echo "  用户名: $git_username"
    echo "  邮箱: $git_email"
    echo "  编辑器: vim"
    echo "  默认分支: main"
    echo ""
    echo -e "${yellow}常用别名：${white}"
    echo "  git st   - git status"
    echo "  git co   - git checkout"
    echo "  git br   - git branch"
    echo "  git ci   - git commit"
    echo "  git lg   - 美化的git log"
    echo ""
    break_end
}

# 快速工具安装菜单
quick_tools_menu() {
    while true; do
        clear
        echo -e "${pink}快速工具安装${white}"
        echo "================================"
        echo "1. 安装开发工具包"
        echo "2. 安装系统监控工具"
        echo "3. 配置Git环境"
        echo "4. 安装Docker环境"
        echo "5. 安装Node.js环境"
        echo "================================"
        echo "0. 返回主菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择操作 [0-5]: " choice validate_numeric_range 0 5

        case $choice in
            1) install_dev_tools ;;
            2) install_monitor_tools ;;
            3) configure_git_environment ;;
            4)
                echo -e "${yellow}Docker安装功能开发中...${white}"
                echo "建议手动执行: curl -fsSL https://get.docker.com | bash"
                break_end
                ;;
            5)
                echo -e "${yellow}Node.js安装功能开发中...${white}"
                echo "建议手动执行: curl -fsSL https://deb.nodesource.com/setup_lts.x | bash && apt install nodejs"
                break_end
                ;;
            0) break ;;
        esac
    done
}
#endregion

#region //主程序入口
# 主函数
main() {
    # 复制脚本到系统路径
    copy_script_to_system

    # 检查授权
    authorization_check
    authorization_false

    # 权限检查
    root_check

    # 创建必要目录
    mkdir -p "$config_dir" "$backup_dir"

    # 环境检查
    check_system_compatibility
    check_network_environment

    # 系统环境检测
    detect_system_environment

    # 设置快捷指令
    setup_shortcut

    # 启动主菜单
    main_menu
}

# 显示系统信息
show_system_info() {
    clear
    echo -e "${pink}系统信息查询${white}"
    echo "================================"

    # 读取保存的系统信息
    if [[ -f "$config_dir/system_info.conf" ]]; then
        . "$config_dir/system_info.conf"
    fi

    echo -e "${cyan}基本信息:${white}"
    echo "  操作系统: $OS $DIST"
    echo "  内核版本: $(uname -r)"
    echo "  系统架构: $ARCH"
    echo "  包管理器: $PKG_MANAGER"
    echo "  地理位置: $COUNTRY"
    echo "  主机名: $(hostname)"
    echo "  时区: $(timedatectl show --property=Timezone --value 2>/dev/null || date +%Z)"

    echo -e "${cyan}网络信息:${white}"
    echo "  IPv4地址: ${IPV4_ADDRESS:-未检测}"
    echo "  IPv6地址: ${IPV6_ADDRESS:-未检测}"
    echo "  DNS服务器: $(cat /etc/resolv.conf | grep nameserver | head -2 | awk '{print $2}' | tr '\n' ' ' || echo "未配置")"
    echo "  网络接口: $(ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://' | grep -v lo | tr '\n' ' ')"

    # 硬件信息
    echo -e "${cyan}硬件信息:${white}"
    echo "  CPU型号: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//' || echo "未知")"
    echo "  CPU核心: $(nproc) 核心"
    echo "  CPU频率: $(grep "cpu MHz" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//' | awk '{printf "%.0f MHz", $1}' 2>/dev/null || echo "未知")"
    echo "  总内存: $(free -h | awk 'NR==2{print $2}' || echo "未知")"

    # 实时系统状态
    echo -e "${cyan}系统状态:${white}"
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "N/A")
    local mem_usage=$(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}' 2>/dev/null || echo "N/A")
    local disk_usage=$(df -h / | awk 'NR==2{print $5}' 2>/dev/null || echo "N/A")
    local uptime=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}' | sed 's/,//' || echo "N/A")
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^ *//' || echo "N/A")

    echo "  CPU使用率: $cpu_usage%"
    echo "  内存使用率: $mem_usage"
    echo "  磁盘使用率: $disk_usage"
    echo "  运行时间: $uptime"
    echo "  负载均衡: $load_avg"
    echo "  活跃进程: $(ps aux | wc -l) 个"

    # 存储信息
    echo -e "${cyan}存储信息:${white}"
    df -h | grep -E "^/dev/" | head -3 | awk '{printf "  %s: %s/%s (%s)\n", $1, $3, $2, $5}'

    # 关键服务状态
    echo -e "${cyan}服务状态:${white}"
    local services=("ssh" "sshd" "xray" "fail2ban")
    for service in "${services[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^$service.service"; then
            local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            local color="${green}"
            [[ "$status" != "active" ]] && color="${red}"
            echo -e "  $service: ${color}$status${white}"
        fi
    done

    echo "================================"
}

# 安全加固子菜单 (优化版)
security_hardening_menu() {
    while true; do
        clear
        echo -e "${pink}安全加固模块${white}"
        echo "================================"
        echo "参考: https://linux.do/t/topic/267502"
        echo "参考: https://101.lug.ustc.edu.cn/"
        echo ""

        # 显示当前SSH状态
        echo -e "${cyan}当前SSH状态:${white}"
        if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
            local current_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' || echo "未知")
            local password_auth=$(sshd -T 2>/dev/null | grep -i '^passwordauthentication ' | awk '{print $2}' || echo "未知")
            echo "  服务状态: 运行中 | 端口: $current_port | 密码认证: $password_auth"
        else
            echo "  服务状态: 未运行"
        fi
        echo ""

        echo "请选择操作："
        echo "1. ${pink}SSH配置管理 (推荐)${white}"
        echo "2. 防火墙设置"
        echo "3. 用户权限管理"
        echo "4. fail2ban安装配置"
        echo "5. 系统优化调优"
        echo "6. 系统清理"
        echo "7. 快速SSH安全配置"
        echo "8. SSH配置深度诊断"
        echo "================================"
        echo "0. 返回主菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择操作 [0-8]: " choice validate_numeric_range 0 8

        case $choice in
            1) ssh_config_management ;;
            2) configure_firewall ;;
            3) user_permission_management ;;
            4) install_configure_fail2ban ;;
            5) system_optimization ;;
            6) system_cleanup ;;
            7) configure_ssh_securely ;;
            8) ssh_config_diagnosis ;;
            0) break ;;
        esac
    done
}

# 代理部署子菜单
proxy_deployment_menu() {
    while true; do
        clear
        echo -e "${pink}代理部署模块${white}"
        echo "================================"
        echo "1. Xray-core安装"
        echo "2. VLESS-HTTP2-REALITY配置"
        echo "3. 客户端配置生成"
        echo "4. 服务管理"
        echo "5. 网络质量检测"
        echo "6. 性能优化"
        echo "================================"
        echo "0. 返回主菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择操作 [0-6]: " choice validate_numeric_range 0 6

        case $choice in
            1) install_xray_core ;;
            2) configure_vless_reality ;;
            3) generate_client_configs ;;
            4) proxy_service_management ;;
            5) test_network_quality ;;
            6) echo "性能优化功能开发中..."; break_end ;;
            0) break ;;
        esac
    done
}

# 启动所有服务
start_all_services() {
    clear
    echo -e "${pink}启动所有服务${white}"
    echo "================================"

    local services=("ssh" "xray" "fail2ban" "ufw")
    local started_count=0

    for service in "${services[@]}"; do
        echo -e "${cyan}正在启动 $service 服务...${white}"

        case $service in
            ssh)
                if manage_service start sshd 2>/dev/null || manage_service start ssh 2>/dev/null; then
                    success_msg "$service 服务启动成功"
                    ((started_count++))
                else
                    warn_msg "$service 服务启动失败或未安装"
                fi
                ;;
            xray)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    if manage_service start xray 2>/dev/null; then
                        success_msg "$service 服务启动成功"
                        ((started_count++))
                    else
                        warn_msg "$service 服务启动失败"
                    fi
                else
                    warn_msg "$service 服务未安装"
                fi
                ;;
            fail2ban)
                if [[ -f "/etc/fail2ban/jail.local" ]]; then
                    if manage_service start fail2ban 2>/dev/null; then
                        success_msg "$service 服务启动成功"
                        ((started_count++))
                    else
                        warn_msg "$service 服务启动失败"
                    fi
                else
                    warn_msg "$service 服务未配置"
                fi
                ;;
            ufw)
                if command -v ufw &> /dev/null && [[ "$(ufw status)" != "Status: inactive" ]]; then
                    if manage_service start ufw 2>/dev/null; then
                        success_msg "$service 服务启动成功"
                        ((started_count++))
                    else
                        warn_msg "$service 服务启动失败"
                    fi
                else
                    warn_msg "$service 服务未启用或未安装"
                fi
                ;;
        esac
        echo "--------------------------------"
    done

    echo ""
    success_msg "服务启动操作完成，共成功启动 $started_count 个服务。"
    break_end
}

# 主菜单
main_menu() {
    while true; do
        clear
        echo -e "${pink}Linux服务器安全加固与管理脚本 ${white}(v1.0.0)"
        echo "=================================================="
        echo -e "系统: ${green}$OS $DIST${white} | IP: ${green}${IPV4_ADDRESS:-N/A}${white}"
        echo "=================================================="
        echo "1. 🛡️  安全加固"
        echo "2. 🚀  代理部署"
        echo "3. 🛠️  快速工具"
        echo "4. ℹ️  系统信息"
        echo "5. 🔄  启动所有服务"
        echo "6. 🔄  重启所有服务"
        echo "7. 🛑  停止所有服务"
        echo "8. 卸载脚本"
        echo "=================================================="
        echo "0. 退出脚本"
        echo "=================================================="

        local choice
        prompt_for_input "请选择操作 [0-8]: " choice validate_numeric_range 0 8

        case $choice in
            1) security_hardening_menu ;;
            2) proxy_deployment_menu ;;
            3) quick_tools_menu ;;
            4) show_system_info; break_end ;;
            5) start_all_services ;;
            6) echo "重启所有服务功能开发中..."; break_end ;;
            7) echo "停止所有服务功能开发中..."; break_end ;;
            8) uninstall_script ;;
            0)
                clear
                echo "感谢使用！"
                exit 0
                ;;
        esac
    done
}

# 程序入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

# 停止所有服务
stop_all_services() {
    clear
    echo -e "${pink}停止所有服务${white}"
    echo "================================"

    echo -e "${red}警告：停止服务可能会影响系统安全和代理功能${white}"
    if ! confirm_operation "停止所有服务"; then
        info_msg "操作已取消"
        return
    fi

    local services=("xray" "fail2ban")
    local stopped_count=0

    for service in "${services[@]}"; do
        echo -e "${cyan}正在停止 $service 服务...${white}"

        case $service in
            xray)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    if manage_service stop xray 2>/dev/null; then
                        success_msg "$service 服务停止成功"
                        ((stopped_count++))
                    else
                        warn_msg "$service 服务停止失败"
                    fi
                else
                    warn_msg "$service 服务未安装"
                fi
                ;;
            fail2ban)
                if command_exists fail2ban-client; then
                    if manage_service stop fail2ban 2>/dev/null; then
                        success_msg "$service 服务停止成功"
                        ((stopped_count++))
                    else
                        warn_msg "$service 服务停止失败"
                    fi
                else
                    warn_msg "$service 服务未安装"
                fi
                ;;
        esac
        sleep 1
    done

    echo ""
    echo -e "${yellow}服务停止完成！成功停止 $stopped_count 个服务${white}"
    echo -e "${red}注意：SSH服务未停止以保持连接${white}"
    break_end
}

# 重启所有服务
restart_all_services() {
    clear
    echo -e "${pink}重启所有服务${white}"
    echo "================================"

    local services=("ssh" "xray" "fail2ban")
    local restarted_count=0

    for service in "${services[@]}"; do
        echo -e "${cyan}正在重启 $service 服务...${white}"

        case $service in
            ssh)
                if sshd -t 2>/dev/null; then
                    if manage_service restart sshd 2>/dev/null || manage_service restart ssh 2>/dev/null; then
                        success_msg "$service 服务重启成功"
                        ((restarted_count++))
                    else
                        warn_msg "$service 服务重启失败"
                    fi
                else
                    warn_msg "$service 配置文件有误，跳过重启"
                fi
                ;;
            xray)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    if [[ -f "$XRAY_CONFIG_FILE" ]] && [[ -f "$XRAY_BINARY" ]] && "$XRAY_BINARY" test -c "$XRAY_CONFIG_FILE" 2>/dev/null; then
                        if manage_service restart xray 2>/dev/null; then
                            success_msg "$service 服务重启成功"
                            ((restarted_count++))
                        else
                            warn_msg "$service 服务重启失败"
                        fi
                    else
                        warn_msg "$service 配置文件有误，跳过重启"
                    fi
                else
                    warn_msg "$service 服务未安装"
                fi
                ;;
            fail2ban)
                if command_exists fail2ban-client; then
                    if manage_service restart fail2ban 2>/dev/null; then
                        success_msg "$service 服务重启成功"
                        ((restarted_count++))
                    else
                        warn_msg "$service 服务重启失败"
                    fi
                else
                    warn_msg "$service 服务未安装"
                fi
                ;;
        esac
        sleep 1
    done

    echo ""
    echo -e "${green}服务重启完成！成功重启 $restarted_count 个服务${white}"
    break_end
}

# 查看所有服务状态
show_all_services_status() {
    clear
    echo -e "${pink}系统服务状态${white}"
    echo "================================"

    # SSH服务状态
    echo -e "${cyan}SSH服务状态:${white}"
    local ssh_status=$(systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown")
    local ssh_port=$(grep -E "^Port " "$SSH_CONFIG" | awk '{print $2}' 2>/dev/null || echo "22")
    echo "  状态: $ssh_status"
    echo "  端口: $ssh_port"
    echo "  配置: $SSH_CONFIG"
    echo ""

    # Xray服务状态
    echo -e "${cyan}Xray服务状态:${white}"
    if [[ -f "$XRAY_SERVICE_FILE" ]]; then
        local xray_status=$(systemctl is-active xray 2>/dev/null || echo "inactive")
        echo "  状态: $xray_status"
        if [[ -f "$config_dir/proxy_config.conf" ]]; then
            . "$config_dir/proxy_config.conf"
            echo "  端口: $LISTEN_PORT"
            echo "  协议: VLESS-HTTP2-REALITY"
        fi
        echo "  配置: $XRAY_CONFIG_FILE"
    else
        echo "  状态: 未安装"
    fi
    echo ""

    # fail2ban状态
    echo -e "${cyan}fail2ban状态:${white}"
    if command_exists fail2ban-client; then
        local f2b_status=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")
        echo "  状态: $f2b_status"
        if [[ "$f2b_status" == "active" ]]; then
            local banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "0")
            echo "  已封禁IP数: $banned_count"
        fi
    else
        echo "  状态: 未安装"
    fi
    echo ""

    # 防火墙状态
    echo -e "${cyan}防火墙状态:${white}"
    if command_exists ufw; then
        local ufw_status=$(ufw status | head -1 | awk '{print $2}')
        echo "  UFW状态: $ufw_status"
    fi
    if command_exists iptables; then
        local iptables_rules=$(iptables -L INPUT | wc -l)
        echo "  iptables规则数: $((iptables_rules - 2))"
    fi
    echo ""

    break_end
}

# 查看服务日志
show_services_logs() {
    while true; do
        clear
        echo -e "${pink}服务日志查看${white}"
        echo "================================"
        echo "1. SSH服务日志"
        echo "2. Xray服务日志"
        echo "3. fail2ban日志"
        echo "4. 系统日志"
        echo "5. 防火墙日志"
        echo "================================"
        echo "0. 返回上级菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择要查看的日志 [0-5]: " choice validate_numeric_range 0 5

        case $choice in
            1)
                echo -e "${cyan}SSH服务日志 (最近50条):${white}"
                journalctl -u sshd -u ssh -n 50 --no-pager 2>/dev/null || echo "无法获取SSH日志"
                break_end
                ;;
            2)
                if [[ -f "$XRAY_SERVICE_FILE" ]]; then
                    echo -e "${cyan}Xray服务日志 (最近50条):${white}"
                    journalctl -u xray -n 50 --no-pager 2>/dev/null || echo "无法获取Xray日志"
                else
                    echo "Xray服务未安装"
                fi
                break_end
                ;;
            3)
                if command_exists fail2ban-client; then
                    echo -e "${cyan}fail2ban日志 (最近50条):${white}"
                    tail -50 /var/log/fail2ban.log 2>/dev/null || echo "无法获取fail2ban日志"
                else
                    echo "fail2ban未安装"
                fi
                break_end
                ;;
            4)
                echo -e "${cyan}系统日志 (最近30条):${white}"
                journalctl -n 30 --no-pager 2>/dev/null || echo "无法获取系统日志"
                break_end
                ;;
            5)
                echo -e "${cyan}防火墙日志 (最近20条):${white}"
                if [[ -f /var/log/ufw.log ]]; then
                    tail -20 /var/log/ufw.log
                else
                    dmesg | grep -i "iptables\|firewall" | tail -20 || echo "无防火墙日志"
                fi
                break_end
                ;;
            0) break ;;
        esac
    done
}

# 系统健康检查
system_health_check() {
    clear
    echo -e "${pink}系统健康检查${white}"
    echo "================================"

    local issues=0
    local warnings=0

    echo -e "${cyan}正在检查系统健康状况...${white}"
    echo ""

    # 检查服务状态
    echo -e "${yellow}1. 服务状态检查${white}"

    # SSH服务检查
    if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
        echo "  ✓ SSH服务运行正常"
    else
        echo "  ✗ SSH服务未运行"
        ((issues++))
    fi

    # Xray服务检查
    if [[ -f "$XRAY_SERVICE_FILE" ]]; then
        if systemctl is-active xray >/dev/null 2>&1; then
            echo "  ✓ Xray服务运行正常"
        else
            echo "  ✗ Xray服务未运行"
            ((issues++))
        fi
    else
        echo "  - Xray服务未安装"
    fi

    # fail2ban检查
    if command_exists fail2ban-client; then
        if systemctl is-active fail2ban >/dev/null 2>&1; then
            echo "  ✓ fail2ban服务运行正常"
        else
            echo "  ✗ fail2ban服务未运行"
            ((issues++))
        fi
    else
        echo "  - fail2ban未安装"
    fi

    echo ""

    # 检查配置文件
    echo -e "${yellow}2. 配置文件检查${white}"

    # SSH配置检查
    if sshd -t 2>/dev/null; then
        echo "  ✓ SSH配置文件语法正确"
    else
        echo "  ✗ SSH配置文件有语法错误"
        ((issues++))
    fi

    # Xray配置检查
    if [[ -f "$XRAY_CONFIG_FILE" ]]; then
        if [[ -f "$XRAY_BINARY" ]] && "$XRAY_BINARY" test -c "$XRAY_CONFIG_FILE" 2>/dev/null; then
            echo "  ✓ Xray配置文件语法正确"
        else
            echo "  ✗ Xray配置文件有语法错误"
            ((issues++))
        fi
    else
        echo "  - Xray配置文件不存在"
    fi

    echo ""

    # 检查网络连接
    echo -e "${yellow}3. 网络连接检查${white}"

    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "  ✓ 外网连接正常"
    else
        echo "  ✗ 外网连接异常"
        ((issues++))
    fi

    if ping -c 1 127.0.0.1 >/dev/null 2>&1; then
        echo "  ✓ 本地回环正常"
    else
        echo "  ✗ 本地回环异常"
        ((issues++))
    fi

    echo ""

    # 检查系统资源
    echo -e "${yellow}4. 系统资源检查${white}"

    # 内存使用率
    local mem_usage=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
    if (( $(echo "$mem_usage > 90" | bc -l 2>/dev/null || echo 0) )); then
        echo "  ⚠ 内存使用率过高: ${mem_usage}%"
        ((warnings++))
    else
        echo "  ✓ 内存使用率正常: ${mem_usage}%"
    fi

    # 磁盘使用率
    local disk_usage=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 90 ]]; then
        echo "  ⚠ 磁盘使用率过高: ${disk_usage}%"
        ((warnings++))
    else
        echo "  ✓ 磁盘使用率正常: ${disk_usage}%"
    fi

    # CPU负载
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local cpu_cores=$(nproc)
    if (( $(echo "$load_avg > $cpu_cores" | bc -l 2>/dev/null || echo 0) )); then
        echo "  ⚠ CPU负载较高: $load_avg (核心数: $cpu_cores)"
        ((warnings++))
    else
        echo "  ✓ CPU负载正常: $load_avg (核心数: $cpu_cores)"
    fi

    echo ""

    # 检查安全状态
    echo -e "${yellow}5. 安全状态检查${white}"

    # 防火墙状态
    if command_exists ufw; then
        if ufw status | grep -q "Status: active"; then
            echo "  ✓ UFW防火墙已启用"
        else
            echo "  ⚠ UFW防火墙未启用"
            ((warnings++))
        fi
    fi

    # SSH端口检查
    local ssh_port=$(grep -E "^Port " "$SSH_CONFIG" | awk '{print $2}' 2>/dev/null || echo "22")
    if [[ "$ssh_port" != "22" ]]; then
        echo "  ✓ SSH端口已修改为非默认端口: $ssh_port"
    else
        echo "  ⚠ SSH仍使用默认端口22"
        ((warnings++))
    fi

    # 密码认证检查
    if grep -q "^PasswordAuthentication no" "$SSH_CONFIG"; then
        echo "  ✓ SSH密码认证已禁用"
    else
        echo "  ⚠ SSH密码认证未禁用"
        ((warnings++))
    fi

    echo ""
    echo "================================"

    # 显示检查结果
    if [[ $issues -eq 0 && $warnings -eq 0 ]]; then
        echo -e "${green}✓ 系统健康状况良好！${white}"
    elif [[ $issues -eq 0 ]]; then
        echo -e "${yellow}⚠ 系统基本正常，但有 $warnings 个警告项需要注意${white}"
    else
        echo -e "${red}✗ 发现 $issues 个严重问题和 $warnings 个警告项${white}"
        echo -e "${red}建议立即处理严重问题${white}"
    fi

    echo ""
    echo -e "${cyan}建议：${white}"
    echo "1. 定期进行健康检查"
    echo "2. 及时处理发现的问题"
    echo "3. 保持系统和软件更新"
    echo "4. 监控系统资源使用情况"

    break_end
}

# 启动所有服务
start_all_services() {
    info_msg "正在启动所有相关服务..."
    manage_service "start" "sshd"
    manage_service "start" "fail2ban"
    manage_service "start" "xray"
    success_msg "服务启动完成"
    break_end
}

# 停止所有服务
stop_all_services() {
    info_msg "正在停止所有相关服务..."
    manage_service "stop" "xray"
    manage_service "stop" "fail2ban"
    manage_service "stop" "sshd"
    success_msg "服务停止完成"
    break_end
}

# 重启所有服务
restart_all_services() {
    info_msg "正在重启所有相关服务..."
    manage_service "restart" "sshd"
    manage_service "restart" "fail2ban"
    manage_service "restart" "xray"
    success_msg "服务重启完成"
    break_end
}

# 服务管理子菜单
service_management_menu() {
    while true; do
        clear
        echo -e "${pink}服务管理模块${white}"
        echo "================================"
        echo "1. 启动所有服务"
        echo "2. 停止所有服务"
        echo "3. 重启所有服务"
        echo "4. 查看服务状态"
        echo "5. 查看服务日志"
        echo "6. 系统健康检查"
        echo "================================"
        echo "0. 返回主菜单"
        echo "================================"

        local choice
        prompt_for_input "请选择操作 [0-6]: " choice validate_numeric_range 0 6

        case $choice in
            1) start_all_services ;;
            2) stop_all_services ;;
            3) restart_all_services ;;
            4) show_all_services_status ;;
            5) show_services_logs ;;
            6) system_health_check ;;
            0) break ;;
        esac
    done
}

# 一键部署功能
one_click_deploy() {
    clear
    echo -e "${pink}一键部署 - VPS安全加固与代理搭建${white}"
    echo "================================"
    echo "此功能将自动完成以下操作："
    echo "1. 系统环境检测与准备"
    echo "2. SSH安全配置"
    echo "3. 防火墙设置"
    echo "4. 系统优化"
    echo "5. Xray-core安装"
    echo "6. VLESS-HTTP2-REALITY配置"
    echo "7. 服务启动"
    echo "8. 客户端配置生成"
    echo "================================"
    echo -e "${red}注意：此操作将修改系统关键配置，请确保在测试环境中使用${white}"
    echo ""

    if ! confirm_operation "一键部署所有功能"; then
        info_msg "操作已取消"
        return
    fi

    # 执行一键部署
    execute_one_click_deploy
}

# 多选菜单系统（借鉴参考脚本的设计）
declare -A batch_options
declare -A batch_choices=([1]="□" [2]="□" [3]="□" [4]="□" [5]="□" [6]="□" [7]="□")
batch_keys=(1 2 3 4 5 6 7)

# 定义批量操作选项
batch_options[1]="系统信息检测"
batch_options[2]="SSH安全配置"
batch_options[3]="防火墙设置"
batch_options[4]="系统优化"
batch_options[5]="fail2ban安装"
batch_options[6]="Xray-core安装"
batch_options[7]="VLESS-HTTP2-REALITY配置"

# 显示批量操作菜单
show_batch_menu() {
    clear
    echo -e "${pink}VPS安全加固与代理搭建工具 v${version}${white}"
    echo -e "${cyan}批量操作模式 - 多选配置${white}"
    echo "================================"
    echo -e "${yellow}说明: 选择需要执行的操作，支持多选${white}"
    echo "      ☑ = 已选择, □ = 未选择"
    echo "================================"

    for NUM in ${batch_keys[*]}; do
        echo -e "${green}[${batch_choices[$NUM]}] $NUM) ${batch_options[$NUM]}${white}"
    done

    echo "================================"
    echo -e "${cyan}8) 开始执行选中的操作${white}"
    echo -e "${yellow}9) 一键部署（全选）${white}"
    echo -e "${red}0) 返回主菜单${white}"
    echo "================================"
}

# 批量操作菜单处理
batch_operation_menu() {
    while true; do
        show_batch_menu
        
        local SELECTION
        prompt_for_input "选择操作 [0-9]: " SELECTION validate_numeric_range 0 9

        case $SELECTION in
            [1-7])
                if [[ "${batch_choices[$SELECTION]}" == "☑" ]]; then
                    batch_choices[$SELECTION]="□"
                else
                    batch_choices[$SELECTION]="☑"
                fi
                ;;
            8)
                execute_batch_operations
                break
                ;;
            9)
                # 全选
                for key in ${batch_keys[*]}; do
                    batch_choices[$key]="☑"
                done
                execute_batch_operations
                break
                ;;
            0)
                break
                ;;
        esac
    done
}

# 执行批量操作
execute_batch_operations() {
    local selected_operations=()

    # 收集选中的操作
    for key in ${batch_keys[*]}; do
        if [[ "${batch_choices[$key]}" == "☑" ]]; then
            selected_operations+=($key)
        fi
    done

    if [[ ${#selected_operations[@]} -eq 0 ]]; then
        warn_msg "没有选择任何操作"
        sleep 2
        return
    fi

    clear
    echo -e "${pink}开始执行批量操作${white}"
    echo "================================"
    echo "选中的操作："
    for op in ${selected_operations[*]}; do
        echo -e "${green}  ✓ ${batch_options[$op]}${white}"
    done
    echo "================================"

    if ! confirm_operation "批量执行选中的操作"; then
        info_msg "操作已取消"
        return
    fi

    local total_ops=${#selected_operations[@]}
    local current_op=0

    # 执行选中的操作
    for op in ${selected_operations[*]}; do
        ((current_op++))
        show_progress $current_op $total_ops "${batch_options[$op]}"

        case $op in
            1) detect_system_environment ;;
            2) configure_ssh_securely ;;
            3) configure_firewall ;;
            4) system_optimization ;;
            5) install_configure_fail2ban ;;
            6) install_xray_core ;;
            7) configure_vless_reality ;;
        esac

        sleep 1
    done

    echo ""
    success_msg "批量操作执行完成！"

    # 重置选择状态
    for key in ${batch_keys[*]}; do
        batch_choices[$key]="□"
    done

    break_end
}

# 主菜单
main_menu() {
    while true; do
        clear
        echo -e "${pink}VPS安全加固与代理搭建工具 v${version}${white}"
        echo "================================"
        echo "1. 系统信息查询"
        echo "2. 安全加固 ->"
        echo "3. 代理部署 ->"
        echo "4. 服务管理 ->"
        echo "5. 配置管理 ->"
        echo "6. 网络质量检测"
        echo "7. 测试工具 ->"
        echo "8. 批量操作模式"
        echo "9. 快速工具安装 ->"
        echo "================================"
        echo "0. 一键部署（安全+代理）"
        echo "================================"
        echo "q. 退出脚本"
        echo "================================"

        local choice
        prompt_for_input "请选择操作 [0-9,q]: " choice validate_numeric_range_or_q 0 9

        case $choice in
            1) show_system_info; break_end ;;
            2) security_hardening_menu ;;
            3) proxy_deployment_menu ;;
            4) service_management_menu ;;
            5) configuration_management ;;
            6) test_network_quality ;;
            7) test_tools_menu ;;
            8) batch_operation_menu ;;
            9) quick_tools_menu ;;
            0) one_click_deploy ;;
            q|Q)
                echo -e "${green}感谢使用VPS安全加固与代理搭建工具！${white}"
                log_operation "Script exited normally"
                exit 0
                ;;
        esac
    done
}

# 命令行参数处理
handle_command_line_args() {
    case "$1" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            echo "VPS安全加固与代理搭建工具 v$version"
            exit 0
            ;;
        --info|-i)
            detect_system_environment
            exit 0
            ;;
        --security)
            echo "执行安全加固..."
            configure_ssh_securely
            configure_firewall
            system_optimization
            install_configure_fail2ban
            echo "安全加固完成！"
            exit 0
            ;;
        --proxy)
            echo "执行代理部署..."
            install_xray_core
            configure_vless_reality
            generate_client_configs
            echo "代理部署完成！"
            exit 0
            ;;
        --deploy)
            echo "执行一键部署..."
            execute_one_click_deploy
            exit 0
            ;;
        --test-network)
            test_network_quality
            exit 0
            ;;
        --fix-dns)
            echo -e "${cyan}DNS解析修复${white}"
            echo "================================"
            check_dns_config
            test_dns_resolution
            exit 0
            ;;
        --status)
            show_system_status
            exit 0
            ;;
        "")
            # 无参数，启动交互模式
            main_menu
            ;;
        *)
            echo "未知参数: $1"
            echo "使用 --help 查看帮助信息"
            exit 1
            ;;
    esac
}

# 显示帮助信息
show_help() {
    echo "VPS安全加固与代理搭建工具 v$version"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help        显示此帮助信息"
    echo "  -v, --version     显示版本信息"
    echo "  -i, --info        显示系统信息"
    echo "  --security        执行安全加固"
    echo "  --proxy           执行代理部署"
    echo "  --deploy          执行一键部署"
    echo "  --test-network    测试网络质量"
    echo "  --fix-dns         修复DNS解析问题"
    echo "  --status          显示系统状态"
    echo ""
    echo "示例:"
    echo "  $0                启动交互模式"
    echo "  $0 --deploy       一键部署所有功能"
    echo "  $0 --security     仅执行安全加固"
    echo "  $0 --proxy        仅执行代理部署"
    echo "  $0 --test-network 测试网络线路质量"
    echo "  $0 --fix-dns      修复DNS解析问题"
    echo ""
}

# 显示系统状态
show_system_status() {
    clear
    echo -e "${pink}系统状态概览${white}"
    echo "================================"

    # 系统基本信息
    show_system_info
    echo ""

    # SSH服务状态
    echo -e "${cyan}SSH服务状态:${white}"
    local ssh_port=$(grep -E "^Port " "$SSH_CONFIG" | awk '{print $2}' 2>/dev/null || echo "22")
    echo "  端口: $ssh_port"
    echo "  状态: $(systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "未知")"
    echo ""

    # 防火墙状态
    echo -e "${cyan}防火墙状态:${white}"
    if command_exists ufw; then
        echo "  类型: UFW"
        echo "  状态: $(ufw status | head -1 | cut -d: -f2 | tr -d ' ')"
    elif command_exists iptables; then
        echo "  类型: iptables"
        echo "  规则数: $(iptables -L | grep -c "^Chain")"
    else
        echo "  状态: 未配置"
    fi
    echo ""

    # Xray服务状态
    echo -e "${cyan}Xray服务状态:${white}"
    if [[ -f "$XRAY_SERVICE_FILE" ]]; then
        echo "  状态: $(systemctl is-active xray 2>/dev/null || echo "未运行")"
        if [[ -f "$config_dir/proxy_config.conf" ]]; then
            . "$config_dir/proxy_config.conf"
            echo "  端口: $LISTEN_PORT"
            echo "  协议: VLESS-HTTP2-REALITY"
        fi
    else
        echo "  状态: 未安装"
    fi
    echo ""

    # fail2ban状态
    echo -e "${cyan}fail2ban状态:${white}"
    if command_exists fail2ban-client; then
        echo "  状态: $(systemctl is-active fail2ban 2>/dev/null || echo "未运行")"
        local banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "0")
        echo "  已封禁IP数: $banned_count"
    else
        echo "  状态: 未安装"
    fi
}

# 脚本主入口
main() {
    root_check
    copy_script_to_system
    authorization_check
    authorization_false
    detect_system_environment
    
    if [[ $# -gt 0 ]]; then
        handle_command_line_args "$@"
    else
        main_menu
    fi
}

# 脚本入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
