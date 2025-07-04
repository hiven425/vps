#!/bin/bash

# VPS安全加固与代理部署一体化工具
# 版本：3.0.0
# 作者：VPS Security Toolkit Team
# 支持系统：Ubuntu/Debian/CentOS
# 功能：安全加固 + 代理部署 + 系统优化

set -euo pipefail

#region //全局配置和版本信息
version="3.0.0"
script_name="vps-security-toolkit"

# 颜色定义 (终端兼容性优化)
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
    red='\033[31m'
    green='\033[32m'
    yellow='\033[33m'
    blue='\033[34m'
    pink='\033[35m'
    cyan='\033[36m'
    white='\033[0m'
    grey='\033[37m'
    bold='\033[1m'
else
    red='' green='' yellow='' blue='' pink='' cyan='' white='' grey='' bold=''
fi

# 全局变量
config_dir="/etc/vps-security-toolkit"
backup_dir="$config_dir/backup"
log_file="/var/log/vps-security.log"
user_authorization="false"

# 支持的模块
declare -A MODULES=(
    ["enhanced-logging"]="增强日志系统"
    ["secure-service-manager"]="安全服务管理"
    ["security-fixes"]="安全修复补丁"
)
#endregion

#region //基础工具函数
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

# 检查系统权限
check_root_permission() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "此脚本需要root权限运行。请使用: sudo $0"
    fi
}

# 创建必要目录
create_directories() {
    local dirs=("$config_dir" "$backup_dir" "$(dirname "$log_file")")
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chmod 750 "$dir"
        fi
    done
}

# 检测系统版本
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        error_exit "无法检测系统版本"
    fi
    
    case $OS in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel|fedora)
            PACKAGE_MANAGER="yum"
            ;;
        *)
            error_exit "不支持的操作系统: $OS"
            ;;
    esac
    
    info_msg "检测到系统: $OS $OS_VERSION"
}

# 加载外部模块
load_module() {
    local module_name="$1"
    local module_file="/home/hiven/workspace/vps/$module_name.sh"
    
    if [[ -f "$module_file" ]]; then
        source "$module_file"
        success_msg "模块加载成功: $module_name"
        return 0
    else
        warn_msg "模块文件不存在: $module_file"
        return 1
    fi
}
#endregion

#region //SSH安全配置模块
# 获取SSH配置值
get_ssh_config_value() {
    local key="$1"
    local default_value="${2:-}"
    
    if command -v sshd >/dev/null 2>&1; then
        sshd -T 2>/dev/null | grep -i "^$key " | awk '{print $2}' | head -1 || echo "$default_value"
    else
        echo "$default_value"
    fi
}

# SSH端口验证
validate_ssh_port() {
    local port="$1"
    
    # 检查端口格式
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # 检查端口范围
    if [[ $port -lt 1024 || $port -gt 65535 ]]; then
        return 1
    fi
    
    # 检查端口占用
    if ss -tuln 2>/dev/null | grep -q ":$port "; then
        warn_msg "端口 $port 可能已被占用"
        return 1
    fi
    
    return 0
}

# 处理云服务商配置冲突
handle_cloud_config_conflicts() {
    info_msg "检查云服务商SSH配置冲突..."
    
    local ssh_config_dir="/etc/ssh/sshd_config.d"
    local cloud_configs=(
        "50-cloud-init.conf"
        "60-cloudimg-settings.conf"
        "99-cloudimg-settings.conf"
    )
    
    local conflicts_found=false
    
    for config in "${cloud_configs[@]}"; do
        local config_path="$ssh_config_dir/$config"
        if [[ -f "$config_path" ]]; then
            conflicts_found=true
            warn_msg "发现云服务商配置: $config"
            
            # 创建备份并禁用
            local backup_name="${config}.disabled-$(date +%s)"
            mv "$config_path" "$ssh_config_dir/$backup_name"
            success_msg "已禁用配置文件: $config -> $backup_name"
        fi
    done
    
    if [[ "$conflicts_found" == "false" ]]; then
        success_msg "未发现云服务商配置冲突"
    fi
}

# 生成安全SSH配置
generate_secure_ssh_config() {
    local ssh_port="$1"
    local permit_root="${2:-prohibit-password}"
    local config_file="/etc/ssh/sshd_config.d/99-vps-security.conf"
    
    info_msg "生成安全SSH配置..."
    
    cat > "$config_file" << EOF
# VPS安全工具包 - SSH安全配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 版本: $version

# 基础连接设置
Port $ssh_port
Protocol 2
AddressFamily any

# 认证设置
PermitRootLogin $permit_root
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# 安全限制
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 60

# 连接保活
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes

# 功能控制
X11Forwarding no
AllowTcpForwarding yes
GatewayPorts no
PermitTunnel no

# 性能优化
UseDNS no
GSSAPIAuthentication no
Compression delayed

# 现代加密算法
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256

# 日志设置
SyslogFacility AUTH
LogLevel INFO
EOF
    
    chmod 644 "$config_file"
    success_msg "SSH配置文件已生成: $config_file"
    
    # 验证配置语法
    if sshd -t 2>/dev/null; then
        success_msg "SSH配置语法验证通过"
    else
        error_exit "SSH配置语法验证失败"
    fi
}

# SSH服务重启
restart_ssh_service() {
    local current_port=$(get_ssh_config_value "port" "22")
    info_msg "重启前SSH端口: $current_port"
    
    # 确保配置文件优先级
    handle_cloud_config_conflicts
    
    # 重启SSH服务
    if systemctl restart sshd || systemctl restart ssh; then
        sleep 2
        local new_port=$(get_ssh_config_value "port" "22")
        
        if [[ "$current_port" == "$new_port" ]]; then
            success_msg "SSH服务重启成功，端口保持为: $new_port"
        else
            warn_msg "SSH端口发生变化: $current_port -> $new_port"
        fi
    else
        error_exit "SSH服务重启失败"
    fi
}

# SSH安全配置主函数
configure_ssh_security() {
    clear
    echo -e "${cyan}=== SSH安全配置 ===${white}"
    echo
    
    # 显示当前配置
    local current_port=$(get_ssh_config_value "port" "22")
    local current_root=$(get_ssh_config_value "permitrootlogin" "yes")
    echo "当前SSH端口: $current_port"
    echo "当前Root登录: $current_root"
    echo
    
    # 获取新端口
    local new_port
    while true; do
        read -p "请输入新的SSH端口 (1024-65535) [默认: 55520]: " new_port
        new_port=${new_port:-55520}
        
        if validate_ssh_port "$new_port"; then
            break
        else
            warn_msg "端口 $new_port 无效或已被占用，请重新输入"
        fi
    done
    
    # 获取Root登录设置
    echo
    echo "Root登录选项:"
    echo "1. no - 完全禁止Root登录 (最安全)"
    echo "2. prohibit-password - 仅允许密钥登录 (推荐)"
    echo "3. yes - 允许密码登录 (不推荐)"
    echo
    
    local root_choice
    read -p "请选择Root登录方式 [1-3, 默认: 2]: " root_choice
    
    local permit_root
    case "${root_choice:-2}" in
        1) permit_root="no" ;;
        2) permit_root="prohibit-password" ;;
        3) permit_root="yes" ;;
        *) permit_root="prohibit-password" ;;
    esac
    
    # 应用配置
    info_msg "应用SSH安全配置..."
    generate_secure_ssh_config "$new_port" "$permit_root"
    
    # 更新防火墙
    update_firewall_for_ssh "$new_port"
    
    # 重启服务
    echo
    read -p "是否现在重启SSH服务使配置生效？(y/N): " restart_confirm
    if [[ "$restart_confirm" =~ ^[Yy]$ ]]; then
        restart_ssh_service
        
        echo
        success_msg "SSH安全配置完成！"
        echo -e "${yellow}重要提醒:${white}"
        echo "1. SSH端口已更改为: $new_port"
        echo "2. Root登录设置: $permit_root"
        echo "3. 请在新终端测试连接: ssh -p $new_port user@server"
        echo "4. 确认连接正常后再断开当前会话"
    else
        warn_msg "SSH服务未重启，请手动执行: systemctl restart sshd"
    fi
}
#endregion

#region //防火墙配置模块
# 更新防火墙规则
update_firewall_for_ssh() {
    local ssh_port="$1"
    
    info_msg "更新防火墙规则..."
    
    if command -v ufw >/dev/null 2>&1; then
        # UFW防火墙
        if ! ufw status | grep -q "Status: active"; then
            ufw --force enable
        fi
        
        ufw allow "$ssh_port/tcp" comment "SSH"
        success_msg "UFW防火墙规则已更新"
        
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # firewalld防火墙
        if ! systemctl is-active firewalld >/dev/null; then
            systemctl start firewalld
            systemctl enable firewalld
        fi
        
        firewall-cmd --permanent --add-port="$ssh_port/tcp"
        firewall-cmd --reload
        success_msg "firewalld防火墙规则已更新"
        
    else
        warn_msg "未检测到支持的防火墙，请手动配置"
    fi
}

# 配置基础防火墙
configure_basic_firewall() {
    info_msg "配置基础防火墙..."
    
    if command -v ufw >/dev/null 2>&1; then
        # 重置UFW规则
        ufw --force reset
        
        # 默认策略
        ufw default deny incoming
        ufw default allow outgoing
        
        # 基础服务
        ufw allow ssh
        ufw allow http
        ufw allow https
        
        # 启用防火墙
        ufw --force enable
        
        success_msg "UFW防火墙配置完成"
    else
        warn_msg "UFW未安装，跳过防火墙配置"
    fi
}
#endregion

#region //系统优化模块
# 启用BBR拥塞控制
enable_bbr() {
    info_msg "启用BBR拥塞控制..."
    
    # 检查内核版本
    local kernel_version=$(uname -r | cut -d. -f1-2)
    if [[ $(echo "$kernel_version >= 4.9" | bc 2>/dev/null || echo 0) -eq 1 ]]; then
        
        # 配置BBR
        cat > /etc/sysctl.d/99-bbr.conf << EOF
# BBR拥塞控制算法
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 网络性能优化
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
EOF
        
        sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
        success_msg "BBR拥塞控制已启用"
    else
        warn_msg "内核版本过低 ($kernel_version)，无法启用BBR"
    fi
}

# 系统性能优化
optimize_system_performance() {
    info_msg "优化系统性能参数..."
    
    cat > /etc/sysctl.d/99-performance.conf << EOF
# 文件描述符限制
fs.file-max = 1000000

# 网络连接优化
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# 内存管理
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF
    
    sysctl -p /etc/sysctl.d/99-performance.conf >/dev/null 2>&1
    
    # 配置用户限制
    cat > /etc/security/limits.d/99-performance.conf << EOF
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
EOF
    
    success_msg "系统性能优化完成"
}

# 系统优化主函数
optimize_system() {
    clear
    echo -e "${cyan}=== 系统性能优化 ===${white}"
    echo
    
    enable_bbr
    optimize_system_performance
    
    echo
    read -p "是否现在重启系统以应用所有优化？(y/N): " reboot_confirm
    if [[ "$reboot_confirm" =~ ^[Yy]$ ]]; then
        info_msg "系统将在5秒后重启..."
        sleep 5
        reboot
    else
        warn_msg "请手动重启系统以应用优化: reboot"
    fi
}
#endregion

#region //代理部署模块 (简化版本)
# 检测服务器IP
get_server_ip() {
    local ip
    ip=$(curl -s ipv4.ip.sb 2>/dev/null || curl -s ifconfig.me 2>/dev/null || echo "127.0.0.1")
    echo "$ip"
}

# 生成随机UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 简化的代理部署
deploy_simple_proxy() {
    clear
    echo -e "${cyan}=== 简化代理部署 ===${white}"
    echo "此功能提供基础的代理部署，完整功能请使用专用代理脚本"
    echo
    
    info_msg "代理部署功能已移至独立脚本"
    echo "请使用: ./proxy-deployment.sh"
    echo
    
    read -p "按任意键返回主菜单..." -n 1 -s
}
#endregion

#region //主菜单系统
# 显示系统状态
show_system_status() {
    clear
    echo -e "${pink}=== 系统状态总览 ===${white}"
    echo
    
    # 系统信息
    echo -e "${cyan}系统信息:${white}"
    echo "  操作系统: $(lsb_release -d 2>/dev/null | cut -d: -f2 | xargs || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
    echo "  内核版本: $(uname -r)"
    echo "  运行时间: $(uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | awk -F', load' '{print $1}')"
    echo
    
    # SSH状态
    echo -e "${cyan}SSH状态:${white}"
    if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
        echo "  服务状态: 运行中"
        echo "  监听端口: $(get_ssh_config_value 'port' '22')"
        echo "  Root登录: $(get_ssh_config_value 'permitrootlogin' '未知')"
    else
        echo "  服务状态: 未运行"
    fi
    echo
    
    # 防火墙状态
    echo -e "${cyan}防火墙状态:${white}"
    if command -v ufw >/dev/null 2>&1; then
        echo "  UFW状态: $(ufw status | head -1 | cut -d: -f2 | xargs)"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        echo "  firewalld状态: $(systemctl is-active firewalld)"
    else
        echo "  防火墙: 未检测到"
    fi
    echo
    
    # 系统负载
    echo -e "${cyan}系统负载:${white}"
    echo "  CPU使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d% -f1)%"
    echo "  内存使用: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
    echo "  磁盘使用: $(df / | tail -1 | awk '{print $5}')"
    echo
}

# 显示帮助信息
show_help() {
    clear
    echo -e "${pink}=== VPS安全工具包 v$version ===${white}"
    echo
    echo "用法: $0 [选项]"
    echo
    echo "选项:"
    echo "  --help, -h        显示此帮助信息"
    echo "  --version, -v     显示版本信息"
    echo "  --ssh             快速SSH安全配置"
    echo "  --firewall        快速防火墙配置"
    echo "  --optimize        系统性能优化"
    echo "  --status          显示系统状态"
    echo
    echo "交互模式:"
    echo "  直接运行脚本进入交互菜单"
    echo
    echo "支持的模块:"
    for module in "${!MODULES[@]}"; do
        echo "  - $module: ${MODULES[$module]}"
    done
    echo
    echo "更多信息请访问项目文档"
}

# 主菜单
main_menu() {
    while true; do
        clear
        echo -e "${pink}${bold}╔════════════════════════════════════════╗${white}"
        echo -e "${pink}${bold}║       VPS安全工具包 v$version        ║${white}"
        echo -e "${pink}${bold}╚════════════════════════════════════════╝${white}"
        echo
        echo -e "${cyan}🛡️  安全加固功能:${white}"
        echo "  1. SSH安全配置"
        echo "  2. 防火墙配置"
        echo "  3. 系统优化"
        echo
        echo -e "${cyan}🚀 代理功能:${white}"
        echo "  4. 简化代理部署 (推荐使用专用脚本)"
        echo
        echo -e "${cyan}📊 系统管理:${white}"
        echo "  5. 系统状态"
        echo "  6. 模块管理"
        echo "  7. 帮助信息"
        echo
        echo -e "${cyan}🔧 一键功能:${white}"
        echo "  8. 完整安全加固"
        echo "  9. 快速配置向导"
        echo
        echo "  0. 退出"
        echo
        
        local choice
        read -p "请选择 [0-9]: " choice
        
        case $choice in
            1) configure_ssh_security ;;
            2) configure_basic_firewall; read -p "按任意键继续..." -n 1 -s ;;
            3) optimize_system ;;
            4) deploy_simple_proxy ;;
            5) show_system_status; read -p "按任意键继续..." -n 1 -s ;;
            6) manage_modules ;;
            7) show_help; read -p "按任意键继续..." -n 1 -s ;;
            8) full_security_hardening ;;
            9) quick_setup_wizard ;;
            0) 
                echo -e "${green}感谢使用VPS安全工具包！${white}"
                exit 0
                ;;
            *)
                warn_msg "无效选择，请重新选择"
                sleep 1
                ;;
        esac
    done
}

# 模块管理
manage_modules() {
    clear
    echo -e "${cyan}=== 模块管理 ===${white}"
    echo
    
    echo "可用模块:"
    local i=1
    for module in "${!MODULES[@]}"; do
        echo "  $i. $module - ${MODULES[$module]}"
        ((i++))
    done
    echo
    
    read -p "请输入要加载的模块编号 (回车返回): " module_choice
    if [[ -n "$module_choice" && "$module_choice" =~ ^[0-9]+$ ]]; then
        local module_array=($(printf '%s\n' "${!MODULES[@]}" | sort))
        local selected_module="${module_array[$((module_choice-1))]}"
        
        if [[ -n "$selected_module" ]]; then
            load_module "$selected_module"
        else
            warn_msg "无效的模块编号"
        fi
    fi
    
    read -p "按任意键继续..." -n 1 -s
}

# 完整安全加固
full_security_hardening() {
    clear
    echo -e "${cyan}=== 完整安全加固 ===${white}"
    echo "此操作将执行完整的系统安全加固流程"
    echo
    
    read -p "确认执行完整安全加固？(y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        info_msg "开始完整安全加固..."
        
        # 执行各项配置
        configure_basic_firewall
        enable_bbr
        optimize_system_performance
        
        echo
        success_msg "完整安全加固已完成！"
        echo "建议手动配置SSH安全性"
    fi
    
    read -p "按任意键继续..." -n 1 -s
}

# 快速配置向导
quick_setup_wizard() {
    clear
    echo -e "${cyan}=== 快速配置向导 ===${white}"
    echo "此向导将引导您完成基本的安全配置"
    echo
    
    # 检查系统状态
    info_msg "检查系统状态..."
    detect_system
    
    # SSH配置
    echo
    read -p "是否配置SSH安全？(Y/n): " ssh_confirm
    if [[ ! "$ssh_confirm" =~ ^[Nn]$ ]]; then
        configure_ssh_security
    fi
    
    # 防火墙配置
    echo
    read -p "是否配置基础防火墙？(Y/n): " fw_confirm
    if [[ ! "$fw_confirm" =~ ^[Nn]$ ]]; then
        configure_basic_firewall
    fi
    
    # 系统优化
    echo
    read -p "是否进行系统优化？(Y/n): " opt_confirm
    if [[ ! "$opt_confirm" =~ ^[Nn]$ ]]; then
        enable_bbr
        optimize_system_performance
    fi
    
    echo
    success_msg "快速配置向导完成！"
    read -p "按任意键继续..." -n 1 -s
}
#endregion

#region //主程序入口
# 处理命令行参数
handle_arguments() {
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            echo "VPS安全工具包 v$version"
            exit 0
            ;;
        --ssh)
            configure_ssh_security
            exit 0
            ;;
        --firewall)
            configure_basic_firewall
            exit 0
            ;;
        --optimize)
            optimize_system
            exit 0
            ;;
        --status)
            show_system_status
            exit 0
            ;;
        "")
            # 无参数，进入交互模式
            ;;
        *)
            echo "未知参数: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
}

# 主函数
main() {
    # 检查权限
    check_root_permission
    
    # 创建必要目录
    create_directories
    
    # 处理命令行参数
    handle_arguments "$@"
    
    # 检测系统
    detect_system
    
    # 记录启动
    log_operation "VPS安全工具包 v$version 启动"
    
    # 进入主菜单
    main_menu
}

# 脚本执行入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
#endregion