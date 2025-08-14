#!/bin/bash

# VPS 安全加固脚本
# 版本: 1.0.0
# 作者: 系统安全专家
# 功能: SSH加固、Fail2ban配置、UFW防火墙设置
# 特性: 健壮性设计、用户友好、安全配置隔离
# ===========================================================

set -e  # 遇到错误立即退出

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# 全局变量
readonly SCRIPT_VERSION="1.0.0"
readonly CONFIG_DIR="/etc/security-hardening"
readonly CONFIG_FILE="${CONFIG_DIR}/config.conf"
readonly BACKUP_DIR="/root/security-backups"
readonly SSH_CUSTOM_CONFIG="/etc/ssh/sshd_config.d/99-hardening.conf"
readonly FAIL2BAN_CONFIG="/etc/fail2ban/jail.local"

# 配置变量
NEW_SSH_PORT=""
CURRENT_SSH_PORT=""
ROOT_LOGIN_POLICY="prohibit-password"  # 默认允许root密钥登录

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 用户运行"
        log_info "请使用: sudo $0"
        exit 1
    fi
}

# 检查并安装基础依赖
check_dependencies() {
    log_info "检查系统依赖..."

    # 基础命令列表
    local required_commands=("curl" "wget" "awk" "sed" "grep" "openssl" "ss" "systemctl")
    local missing_commands=()

    # 检查命令是否存在
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done

    # 如果有缺失的命令，尝试安装
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log_warn "检测到缺失的命令: ${missing_commands[*]}"
        log_info "正在安装基础依赖包..."

        local pkg_manager=$(detect_package_manager)
        case $pkg_manager in
            apt)
                apt update -y
                apt install -y curl wget gawk sed grep openssl iproute2 systemd coreutils
                ;;
            yum)
                yum install -y curl wget gawk sed grep openssl iproute systemd coreutils
                ;;
            *)
                log_error "不支持的包管理器: $pkg_manager"
                return 1
                ;;
        esac

        # 再次检查
        for cmd in "${missing_commands[@]}"; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                log_error "安装后仍然缺失命令: $cmd"
                return 1
            fi
        done

        log_success "基础依赖安装完成"
    else
        log_success "所有基础依赖已满足"
    fi
}

# 检查系统要求
check_system() {
    log_info "检查系统要求..."
    
    # 检查操作系统
    if command -v apt &> /dev/null; then
        log_info "检测到 Debian/Ubuntu 系统"
    elif command -v yum &> /dev/null; then
        log_info "检测到 CentOS/RHEL 系统"
    else
        log_error "不支持的操作系统"
        exit 1
    fi
    
    log_success "系统要求检查通过"
}

# 端口验证函数
validate_port() {
    local port=$1
    
    # 检查是否为纯数字
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # 检查端口范围 (1024-65535, 避免系统保留端口)
    if [[ $port -lt 1024 || $port -gt 65535 ]]; then
        return 1
    fi
    
    # 检查端口是否已被占用
    if ss -tlun | grep -q ":$port "; then
        return 1
    fi
    
    return 0
}

# 获取当前SSH端口
get_current_ssh_port() {
    log_info "检测当前SSH端口..."

    # 方法1: 从SSH配置文件获取端口
    local port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    # 方法2: 如果没有找到，检查自定义配置
    if [[ -z "$port" && -f "$SSH_CUSTOM_CONFIG" ]]; then
        port=$(grep -E "^Port " "$SSH_CUSTOM_CONFIG" 2>/dev/null | awk '{print $2}')
    fi

    # 方法3: 如果配置文件中没有，从实际监听端口检测
    if [[ -z "$port" ]]; then
        # 检测SSH服务实际监听的端口
        local listening_ports=$(ss -tlnp | grep sshd | grep -oE ':[0-9]+' | sed 's/://' | sort -u)
        if [[ -n "$listening_ports" ]]; then
            # 如果有多个端口，选择第一个非22的，如果没有则选择22
            for p in $listening_ports; do
                if [[ "$p" != "22" ]]; then
                    port="$p"
                    break
                fi
            done
            # 如果没有找到非22端口，使用第一个端口
            if [[ -z "$port" ]]; then
                port=$(echo "$listening_ports" | head -n1)
            fi
        fi
    fi

    # 默认端口
    if [[ -z "$port" ]]; then
        port="22"
    fi

    CURRENT_SSH_PORT="$port"
    log_info "当前SSH端口: $CURRENT_SSH_PORT"

    # 显示当前SSH监听状态
    log_info "当前SSH服务监听状态:"
    ss -tlnp | grep -E "sshd|:$CURRENT_SSH_PORT " || log_warn "未检测到SSH服务监听"
}

# 检查SSH密钥安全性
check_ssh_keys() {
    log_info "检查SSH密钥配置..."
    
    # 询问root登录策略
    echo ""
    echo -e "${YELLOW}Root登录策略:${NC}"
    echo "1. 允许root密钥登录 (推荐用于VPS)"
    echo "2. 完全禁止root登录 (仅允许普通用户)"
    echo ""
    
    while true; do
        read -p "请选择 [1-2]: " root_policy
        case $root_policy in
            1)
                ROOT_LOGIN_POLICY="prohibit-password"
                log_info "已选择：允许root密钥登录"
                break
                ;;
            2)
                ROOT_LOGIN_POLICY="no"
                log_info "已选择：完全禁止root登录"
                log_warn "请确保已创建普通用户账户"
                break
                ;;
            *)
                log_error "无效选择，请输入 1-2"
                ;;
        esac
    done
    
    # 只有在允许root登录时才处理root密钥
    if [[ "$ROOT_LOGIN_POLICY" == "prohibit-password" ]]; then
        # 检查root用户的authorized_keys
        if [[ -f "/root/.ssh/authorized_keys" ]]; then
            local key_count=$(wc -l < "/root/.ssh/authorized_keys")
            log_info "发现 $key_count 个已配置的SSH公钥"
            
            echo ""
            echo -e "${YELLOW}SSH密钥安全选项:${NC}"
            echo "1. 保留现有密钥 (使用云服务商提供的密钥)"
            echo "2. 添加新密钥 (推荐: 使用您自己的密钥)"
            echo "3. 替换所有密钥 (最安全: 完全使用新密钥)"
            echo ""
            
            while true; do
                read -p "请选择 [1-3]: " key_choice
                case $key_choice in
                    1)
                        log_info "保留现有SSH密钥"
                        return 0
                        ;;
                    2)
                        add_ssh_key
                        return 0
                        ;;
                    3)
                        replace_ssh_keys
                        return 0
                        ;;
                    *)
                        log_error "无效选择，请输入 1-3"
                        ;;
                esac
            done
        else
            log_warn "未找到SSH公钥文件，需要添加SSH密钥"
            add_ssh_key
        fi
    else
        log_info "已选择禁止root登录，跳过root密钥配置"
    fi
}

# 添加SSH密钥
add_ssh_key() {
    log_info "添加新的SSH密钥..."
    
    echo ""
    echo "请选择添加密钥的方式:"
    echo "1. 粘贴公钥内容"
    echo "2. 从文件读取公钥"
    echo ""
    
    while true; do
        read -p "请选择 [1-2]: " add_method
        case $add_method in
            1)
                add_key_from_input
                break
                ;;
            2)
                add_key_from_file
                break
                ;;
            *)
                log_error "无效选择，请输入 1-2"
                ;;
        esac
    done
}

# 从输入添加密钥
add_key_from_input() {
    echo ""
    echo "请粘贴您的SSH公钥内容 (通常以 ssh-rsa 或 ssh-ed25519 开头):"
    echo "提示: 可以使用 'ssh-keygen -t ed25519 -C \"your_email@example.com\"' 生成新密钥"
    echo ""
    
    read -p "公钥内容: " public_key
    
    if [[ -z "$public_key" ]]; then
        log_error "公钥内容不能为空"
        return 1
    fi
    
    # 验证公钥格式
    if [[ ! "$public_key" =~ ^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-) ]]; then
        log_error "公钥格式不正确"
        return 1
    fi
    
    # 确保 .ssh 目录存在
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # 添加公钥到 authorized_keys
    echo "$public_key" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    
    log_success "SSH公钥已添加"
}

# 从文件添加密钥
add_key_from_file() {
    echo ""
    read -p "请输入公钥文件路径: " key_file
    
    if [[ ! -f "$key_file" ]]; then
        log_error "文件不存在: $key_file"
        return 1
    fi
    
    # 确保 .ssh 目录存在
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # 添加公钥到 authorized_keys
    cat "$key_file" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    
    log_success "SSH公钥已从文件添加: $key_file"
}

# 替换SSH密钥
replace_ssh_keys() {
    log_warn "这将删除所有现有的SSH密钥！"
    read -p "确认要替换所有SSH密钥吗? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        log_info "操作已取消"
        return 0
    fi
    
    # 备份现有密钥
    if [[ -f "/root/.ssh/authorized_keys" ]]; then
        cp "/root/.ssh/authorized_keys" "/root/.ssh/authorized_keys.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "现有密钥已备份"
    fi
    
    # 清空现有密钥
    > /root/.ssh/authorized_keys
    
    # 添加新密钥
    add_ssh_key
}

# 收集SSH端口配置
collect_ssh_port() {
    log_info "配置SSH端口..."
    
    get_current_ssh_port
    
    while true; do
        read -p "请输入新的SSH端口 (1024-65535) [默认: 22222]: " input_port
        input_port=${input_port:-22222}
        
        if validate_port "$input_port"; then
            NEW_SSH_PORT="$input_port"
            log_success "新SSH端口设置为: $NEW_SSH_PORT"
            break
        else
            if [[ ! "$input_port" =~ ^[0-9]+$ ]]; then
                log_error "端口必须是数字"
            elif [[ $input_port -lt 1024 || $input_port -gt 65535 ]]; then
                log_error "端口必须在 1024-65535 范围内"
            else
                log_error "端口 $input_port 已被占用"
            fi
            log_info "请重新输入一个有效的端口号"
        fi
    done
}

# 创建备份目录
create_backup() {
    local backup_name="backup_$(date +%Y%m%d_%H%M%S)"
    local backup_path="${BACKUP_DIR}/${backup_name}"
    
    log_info "创建配置备份..."
    mkdir -p "$backup_path"
    
    # 备份SSH配置
    [[ -f "/etc/ssh/sshd_config" ]] && cp "/etc/ssh/sshd_config" "$backup_path/"
    [[ -f "$SSH_CUSTOM_CONFIG" ]] && cp "$SSH_CUSTOM_CONFIG" "$backup_path/"
    
    # 备份Fail2ban配置
    [[ -f "/etc/fail2ban/jail.conf" ]] && cp "/etc/fail2ban/jail.conf" "$backup_path/"
    [[ -f "$FAIL2BAN_CONFIG" ]] && cp "$FAIL2BAN_CONFIG" "$backup_path/"
    
    log_success "备份已创建: $backup_path"
}

# 处理云服务商SSH配置干扰
handle_cloud_ssh_configs() {
    log_info "检查并处理云服务商SSH配置文件..."
    
    # 查找云服务商配置文件
    local cloud_configs=$(find /etc/ssh/sshd_config.d/ -name "*cloud*" -o -name "*50-*" 2>/dev/null)
    
    if [[ -n "$cloud_configs" ]]; then
        log_warn "发现云服务商SSH配置文件，正在重命名以避免冲突..."
        
        while IFS= read -r config_file; do
            if [[ -f "$config_file" ]]; then
                local backup_name="${config_file}.bak"
                log_info "重命名 $config_file -> $backup_name"
                mv "$config_file" "$backup_name"
            fi
        done <<< "$cloud_configs"
        
        log_success "云服务商配置文件已重命名"
    else
        log_info "未发现云服务商SSH配置文件"
    fi
}

# 配置SSH安全加固
configure_ssh_security() {
    log_info "正在配置SSH安全加固..."
    
    # 处理云服务商配置干扰
    handle_cloud_ssh_configs
    
    # 创建自定义SSH配置目录
    mkdir -p /etc/ssh/sshd_config.d/
    
    # 生成SSH安全配置
    log_info "生成SSH安全配置文件..."
    cat > "$SSH_CUSTOM_CONFIG" << EOF
# SSH安全加固配置
# 生成时间: $(date)
# 此配置会覆盖 /etc/ssh/sshd_config 中的默认设置

# 修改SSH端口
Port $NEW_SSH_PORT

# 禁用root密码登录，根据用户选择设置
PermitRootLogin $ROOT_LOGIN_POLICY

# 禁用所有密码认证
PasswordAuthentication no

# 确保公钥认证启用
PubkeyAuthentication yes

# 禁止空密码
PermitEmptyPasswords no

# 限制认证尝试次数
MaxAuthTries 3

# 限制同时连接数
MaxSessions 5

# 禁用X11转发
X11Forwarding no

# 禁用agent转发
AllowAgentForwarding no

# 禁用TCP转发
AllowTcpForwarding no

# 客户端存活检查
ClientAliveInterval 300
ClientAliveCountMax 2

# 协议版本
Protocol 2

# 禁用不安全的认证方法
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
EOF
    
    # 设置权限
    chmod 644 "$SSH_CUSTOM_CONFIG"
    
    log_success "SSH安全配置已生成: $SSH_CUSTOM_CONFIG"
}

# 获取SSH服务名称
get_ssh_service_name() {
    # 检查不同的SSH服务名称
    if systemctl list-unit-files | grep -q "^sshd.service"; then
        echo "sshd"
    elif systemctl list-unit-files | grep -q "^ssh.service"; then
        echo "ssh"
    elif systemctl list-unit-files | grep -q "^openssh.service"; then
        echo "openssh"
    else
        log_error "未找到SSH服务"
        return 1
    fi
}

# 测试SSH配置
test_ssh_config() {
    log_info "测试SSH配置文件语法..."
    
    if sshd -t; then
        log_success "SSH配置文件语法正确"
        return 0
    else
        log_error "SSH配置文件语法错误"
        log_info "恢复原始配置..."
        
        # 删除有问题的配置文件
        rm -f "$SSH_CUSTOM_CONFIG"
        
        # 恢复云服务商配置
        find /etc/ssh/sshd_config.d/ -name "*.bak" | while read -r backup_file; do
            original_file="${backup_file%.bak}"
            mv "$backup_file" "$original_file"
        done
        
        return 1
    fi
}

# 重启SSH服务
restart_ssh_service() {
    log_info "重启SSH服务..."
    
    # 获取SSH服务名称
    local ssh_service=$(get_ssh_service_name)
    if [[ $? -ne 0 ]]; then
        log_error "无法确定SSH服务名称"
        return 1
    fi
    
    log_info "检测到SSH服务名称: $ssh_service"
    
    # 先验证端口是否已在监听旧端口
    log_info "当前SSH服务监听端口："
    ss -tlnp | grep -E ":(22|$CURRENT_SSH_PORT) " || log_warn "未检测到SSH服务监听"
    
    # 使用reload而不是restart，保持现有连接
    if systemctl reload "$ssh_service"; then
        log_info "SSH配置重载完成，等待3秒..."
        sleep 3
        
        # 检查新端口是否监听
        if ss -tlnp | grep -q ":$NEW_SSH_PORT "; then
            log_success "SSH服务重启成功，新端口已监听"
        else
            log_warn "新端口未监听，尝试完全重启..."
            systemctl restart "$ssh_service"
            sleep 3
            
            if ss -tlnp | grep -q ":$NEW_SSH_PORT "; then
                log_success "SSH服务完全重启成功"
            else
                log_error "SSH服务重启后新端口仍未监听"
                return 1
            fi
        fi
        
        log_warn "请注意: SSH端口已从 $CURRENT_SSH_PORT 更改为 $NEW_SSH_PORT"
        log_warn "请确保在断开连接前测试新端口: ssh -p $NEW_SSH_PORT user@server"
        
        # 显示当前监听端口
        log_info "当前SSH监听端口："
        ss -tlnp | grep -E ":(22|$CURRENT_SSH_PORT|$NEW_SSH_PORT) "
        
    else
        log_error "SSH配置重载失败"
        
        # 如果reload失败，尝试restart
        log_info "尝试完全重启SSH服务..."
        if systemctl restart "$ssh_service"; then
            sleep 3
            if ss -tlnp | grep -q ":$NEW_SSH_PORT "; then
                log_success "SSH服务重启成功"
                log_warn "请注意: SSH端口已从 $CURRENT_SSH_PORT 更改为 $NEW_SSH_PORT"
                log_warn "请确保在断开连接前测试新端口: ssh -p $NEW_SSH_PORT user@server"
            else
                log_error "SSH服务重启后端口仍未监听"
                return 1
            fi
        else
            log_error "SSH服务重启失败"
            return 1
        fi
    fi
}

# 检查包管理器
detect_package_manager() {
    if command -v apt &> /dev/null; then
        echo "apt"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    else
        echo "unknown"
    fi
}

# 安装Fail2ban
install_fail2ban() {
    log_info "检查并安装Fail2ban..."
    
    if command -v fail2ban-server &> /dev/null; then
        log_info "Fail2ban已安装，跳过安装步骤"
        return 0
    fi
    
    local pkg_manager=$(detect_package_manager)
    
    case $pkg_manager in
        apt)
            log_info "使用apt安装Fail2ban..."
            apt update -y
            apt install -y fail2ban
            ;;
        yum)
            log_info "使用yum安装Fail2ban..."
            yum install -y epel-release
            yum install -y fail2ban
            ;;
        dnf)
            log_info "使用dnf安装Fail2ban..."
            dnf install -y fail2ban
            ;;
        *)
            log_error "不支持的包管理器"
            return 1
            ;;
    esac
    
    log_success "Fail2ban安装完成"
}

# 配置Fail2ban
configure_fail2ban() {
    log_info "配置Fail2ban..."
    
    # 生成Fail2ban配置文件
    cat > "$FAIL2BAN_CONFIG" << EOF
# Fail2ban自定义配置
# 生成时间: $(date)

[DEFAULT]
# 忽略的IP地址 (本地环回地址)
ignoreip = 127.0.0.1/8 ::1

# 封禁时间 (秒) - 10分钟
bantime = 600

# 查找时间窗口 (秒) - 5分钟
findtime = 300

# 最大重试次数
maxretry = 5

# 邮件通知设置 (可选)
# mta = sendmail
# sender = fail2ban@localhost

[sshd]
# 启用SSH保护
enabled = true

# 监控的SSH端口
port = $NEW_SSH_PORT

# 过滤器
filter = sshd

# 日志文件位置
logpath = /var/log/auth.log

# SSH特定设置
maxretry = 5
findtime = 300
bantime = 600

# 动作设置
action = iptables[name=SSH, port=$NEW_SSH_PORT, protocol=tcp]
EOF
    
    # 设置权限
    chmod 644 "$FAIL2BAN_CONFIG"
    
    log_success "Fail2ban配置已生成: $FAIL2BAN_CONFIG"
}

# 启动Fail2ban服务
start_fail2ban_service() {
    log_info "启动Fail2ban服务..."
    
    # 启动服务
    systemctl start fail2ban
    systemctl enable fail2ban
    
    # 检查服务状态
    if systemctl is-active --quiet fail2ban; then
        log_success "Fail2ban服务启动成功"
        
        # 显示状态信息
        log_info "Fail2ban状态信息:"
        fail2ban-client status
        
        # 检查SSH规则
        log_info "SSH保护规则状态:"
        fail2ban-client status sshd 2>/dev/null || log_info "SSH规则将在首次检测到失败登录时激活"
    else
        log_error "Fail2ban服务启动失败"
        return 1
    fi
}

# 检查UFW是否安装
check_ufw_installation() {
    log_info "检查UFW防火墙..."
    
    if command -v ufw &> /dev/null; then
        log_info "UFW已安装"
        return 0
    fi
    
    local pkg_manager=$(detect_package_manager)
    
    case $pkg_manager in
        apt)
            log_info "使用apt安装UFW..."
            apt install -y ufw
            ;;
        yum)
            log_info "使用yum安装UFW..."
            yum install -y ufw
            ;;
        dnf)
            log_info "使用dnf安装UFW..."
            dnf install -y ufw
            ;;
        *)
            log_error "不支持的包管理器"
            return 1
            ;;
    esac
    
    log_success "UFW安装完成"
}

# 智能检测SSH配置状态
check_ssh_security_status() {
    log_info "检查SSH安全配置状态..."

    # 检查是否已经配置了密钥认证
    local password_auth=$(sshd -T | grep "passwordauthentication" | awk '{print $2}')
    local pubkey_auth=$(sshd -T | grep "pubkeyauthentication" | awk '{print $2}')
    local root_login=$(sshd -T | grep "permitrootlogin" | awk '{print $2}')

    log_info "当前SSH安全状态:"
    log_info "- 密码认证: $password_auth"
    log_info "- 公钥认证: $pubkey_auth"
    log_info "- Root登录: $root_login"

    # 如果已经是安全配置，询问是否跳过
    if [[ "$password_auth" == "no" && "$pubkey_auth" == "yes" && "$root_login" =~ ^(no|prohibit-password)$ ]]; then
        log_success "检测到SSH已经配置为安全模式"
        read -p "SSH已经安全配置，是否跳过SSH配置步骤？(Y/n): " skip_ssh
        if [[ "$skip_ssh" =~ ^[Nn]$ ]]; then
            return 1  # 不跳过
        else
            return 0  # 跳过SSH配置
        fi
    fi

    return 1  # 需要配置SSH
}

# 配置UFW防火墙
configure_ufw_firewall() {
    log_info "配置UFW防火墙..."

    # 智能检测当前SSH端口并确保防火墙规则正确
    log_info "步骤1: 智能配置SSH端口防火墙规则"

    # 如果当前SSH端口不是22且不等于新端口，也要保留
    if [[ "$CURRENT_SSH_PORT" != "22" && "$CURRENT_SSH_PORT" != "$NEW_SSH_PORT" ]]; then
        log_info "保留当前SSH端口 $CURRENT_SSH_PORT 的防火墙规则"
        ufw allow "$CURRENT_SSH_PORT/tcp"
    fi

    # 允许新的SSH端口
    if [[ "$NEW_SSH_PORT" != "$CURRENT_SSH_PORT" ]]; then
        log_info "添加新SSH端口 $NEW_SSH_PORT 的防火墙规则"
        ufw allow "$NEW_SSH_PORT/tcp"
    else
        log_info "SSH端口未更改，确保端口 $NEW_SSH_PORT 已开放"
        ufw allow "$NEW_SSH_PORT/tcp"
    fi
    
    # 设置默认策略
    log_info "步骤2: 设置默认策略"
    ufw default deny incoming
    ufw default allow outgoing
    
    # 添加常用服务端口
    log_info "步骤3: 添加常用服务端口"
    ufw allow 80/tcp    # HTTP
    ufw allow 443/tcp   # HTTPS
    
    # 询问是否需要其他端口
    echo ""
    read -p "是否需要开放其他端口？(y/N): " add_ports
    if [[ "$add_ports" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "请输入要开放的端口 (格式: 端口/协议, 如 8080/tcp): " custom_port
            if [[ -n "$custom_port" ]]; then
                ufw allow "$custom_port"
                log_info "已添加端口: $custom_port"
            fi
            
            read -p "是否继续添加端口？(y/N): " continue_add
            if [[ ! "$continue_add" =~ ^[Yy]$ ]]; then
                break
            fi
        done
    fi
    
    # 最后启用防火墙
    log_info "步骤4: 启用防火墙"
    ufw --force enable
    
    # 设置开机自启
    systemctl enable ufw
    
    log_success "UFW防火墙配置完成"
}

# 显示防火墙状态
show_ufw_status() {
    log_info "防火墙状态信息:"
    ufw status verbose
}

# 保存配置
save_config() {
    log_info "保存安全配置..."
    
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# 安全加固配置文件
# 生成时间: $(date)

# SSH配置
OLD_SSH_PORT="$CURRENT_SSH_PORT"
NEW_SSH_PORT="$NEW_SSH_PORT"

# 安装信息
INSTALL_DATE="$(date)"
SCRIPT_VERSION="$SCRIPT_VERSION"
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "配置已保存到: $CONFIG_FILE"
}

# 显示完成信息
show_completion_info() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                      安全加固完成！                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_success "VPS安全加固已完成"
    echo ""
    echo -e "${CYAN}配置摘要:${NC}"
    echo "- SSH端口: $CURRENT_SSH_PORT → $NEW_SSH_PORT"
    echo "- SSH密码认证: 已禁用"
    echo "- SSH密钥认证: 已启用"
    echo "- Fail2ban: 已启用 (5次失败尝试封禁10分钟)"
    echo "- UFW防火墙: 已启用"
    echo "- 允许端口: $NEW_SSH_PORT/tcp, 80/tcp, 443/tcp"
    echo ""
    echo -e "${YELLOW}重要提醒:${NC}"
    echo "1. SSH端口已更改为 $NEW_SSH_PORT"
    echo "2. 请立即测试新端口连接: ssh -p $NEW_SSH_PORT user@server"
    echo "3. SSH密钥认证已启用，密码认证已禁用"
    echo "4. 配置备份位置: $BACKUP_DIR"
    echo "5. SSH密钥备份位置: /root/.ssh/authorized_keys.backup.*"
    echo ""
    echo -e "${RED}安全警告: 在断开当前连接前，请务必测试新的SSH端口和密钥认证！${NC}"
}

# 主函数
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   VPS 安全加固脚本 v$SCRIPT_VERSION                  ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  功能: SSH加固 + Fail2ban + UFW防火墙                          ║${NC}"
    echo -e "${WHITE}║  特性: 智能检测 + 安全配置 + 用户友好                          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 检查系统要求
    check_root
    check_system

    # 检查系统依赖
    check_dependencies

    # 创建配置备份
    create_backup

    log_info "开始VPS安全加固流程..."
    echo ""
    
    # 第一阶段：SSH安全加固
    log_info "=== 第一阶段：SSH安全加固 ==="

    # 检查SSH安全状态，如果已经安全则询问是否跳过
    if check_ssh_security_status; then
        log_info "跳过SSH配置，使用现有安全设置"
        # 仍然需要获取当前SSH端口用于防火墙配置
        get_current_ssh_port
        NEW_SSH_PORT="$CURRENT_SSH_PORT"
    else
        collect_ssh_port
        check_ssh_keys
        configure_ssh_security

        if test_ssh_config; then
            restart_ssh_service
        else
            log_error "SSH配置测试失败，请检查配置"
            exit 1
        fi
    fi

    
    echo ""
    
    # 第二阶段：Fail2ban配置
    log_info "=== 第二阶段：Fail2ban配置 ==="
    install_fail2ban
    configure_fail2ban
    start_fail2ban_service
    
    echo ""
    
    # 第三阶段：UFW防火墙配置
    log_info "=== 第三阶段：UFW防火墙配置 ==="
    check_ufw_installation
    configure_ufw_firewall
    show_ufw_status
    
    echo ""
    
    # 保存配置
    save_config
    
    # 显示完成信息
    show_completion_info
}

# ========================================
# 交互式菜单功能
# ========================================

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    VPS 安全加固工具 v${SCRIPT_VERSION}                        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  ✓ 模块化设计  ✓ 智能检测  ✓ 安全备份  ✓ 用户友好        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  🚀 1. 一键安全加固 (推荐新手)                                   ║${NC}"
    echo -e "${WHITE}║  🔧 2. SSH 安全配置                                              ║${NC}"
    echo -e "${WHITE}║  🛡️  3. 配置 Fail2ban                                            ║${NC}"
    echo -e "${WHITE}║  🔥 4. 配置 UFW 防火墙                                           ║${NC}"
    echo -e "${WHITE}║  📊 5. 安全状态检查                                              ║${NC}"
    echo -e "${WHITE}║  ⚙️  6. 管理 Fail2ban                                            ║${NC}"
    echo -e "${WHITE}║  🔧 7. 管理 UFW                                                  ║${NC}"
    echo -e "${WHITE}║  0. 退出                                                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# 一键安全加固
one_click_hardening() {
    log_info "一键安全加固向导..."

    echo ""
    echo "=== VPS 一键安全加固向导 ==="
    echo ""
    log_info "此向导将自动配置以下安全设置:"
    echo "  ✓ SSH安全配置 (端口、密钥、禁用密码登录)"
    echo "  ✓ 防火墙配置 (UFW)"
    echo "  ✓ 入侵防护 (Fail2Ban)"
    echo ""

    log_warn "注意: 此操作将修改系统关键配置，请确保您了解这些更改"
    echo ""

    read -p "是否继续一键安全加固? (y/N): " confirm_hardening

    if [[ ! "$confirm_hardening" =~ ^[Yy]$ ]]; then
        log_info "取消一键安全加固"
        return 0
    fi

    # 执行原有的main函数逻辑
    execute_main_hardening

    read -p "按回车键返回主菜单..."
}

# 执行主要的安全加固流程
execute_main_hardening() {
    # 检查权限和系统
    check_root
    check_dependencies

    echo ""
    log_info "=== VPS 安全加固脚本 v${SCRIPT_VERSION} ==="
    echo ""

    # 第一阶段：SSH安全配置
    log_info "=== 第一阶段：SSH安全配置 ==="

    # 检查SSH安全状态，如果已经安全则询问是否跳过
    if check_ssh_security_status; then
        log_info "跳过SSH配置，使用现有安全设置"
        # 仍然需要获取当前SSH端口用于防火墙配置
        get_current_ssh_port
        NEW_SSH_PORT="$CURRENT_SSH_PORT"
    else
        collect_ssh_port
        check_ssh_keys
        configure_ssh_security

        if test_ssh_config; then
            restart_ssh_service
        else
            log_error "SSH配置测试失败，请检查配置"
            return 1
        fi
    fi

    echo ""

    # 第二阶段：Fail2ban配置
    log_info "=== 第二阶段：Fail2ban配置 ==="
    install_fail2ban
    configure_fail2ban
    start_fail2ban_service

    echo ""

    # 第三阶段：UFW防火墙配置
    log_info "=== 第三阶段：UFW防火墙配置 ==="
    check_ufw_installation
    configure_ufw_firewall
    show_ufw_status

    echo ""

    # 保存配置
    save_config

    # 显示完成信息
    show_completion_info
}

# SSH安全配置菜单
harden_ssh() {
    log_info "开始SSH安全加固..."

    # 检查SSH安全状态
    if check_ssh_security_status; then
        echo ""
        read -p "SSH已经安全配置，是否重新配置? (y/N): " reconfigure
        if [[ ! "$reconfigure" =~ ^[Yy]$ ]]; then
            log_info "保持现有SSH配置"
            return 0
        fi
    fi

    # 收集SSH配置
    collect_ssh_port
    check_ssh_keys
    configure_ssh_security

    if test_ssh_config; then
        restart_ssh_service
        log_success "SSH安全配置完成"
    else
        log_error "SSH配置测试失败"
        return 1
    fi

    echo ""
    read -p "按回车键返回主菜单..."
}

# 安全状态检查
security_status_check() {
    clear
    echo -e "${CYAN}=== VPS 安全状态检查 ===${NC}"
    echo ""

    # SSH状态检查
    log_info "检查SSH安全状态..."
    if check_ssh_security_status; then
        log_success "SSH配置安全"
    else
        log_warn "SSH配置需要加固"
    fi

    echo ""

    # Fail2ban状态检查
    log_info "检查Fail2ban状态..."
    if systemctl is-active --quiet fail2ban; then
        log_success "Fail2ban服务运行正常"
        local banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned:" | awk '{print $NF}' || echo "0")
        log_info "当前封禁IP数量: $banned_count"
    else
        log_warn "Fail2ban服务未运行"
    fi

    echo ""

    # UFW状态检查
    log_info "检查UFW防火墙状态..."
    if ufw status | grep -q "Status: active"; then
        log_success "UFW防火墙已启用"
        ufw status numbered
    else
        log_warn "UFW防火墙未启用"
    fi

    echo ""
    read -p "按回车键返回主菜单..."
}

# 管理Fail2ban
manage_fail2ban() {
    while true; do
        clear
        echo -e "${CYAN}=== Fail2ban 管理 ===${NC}"
        echo ""
        echo "1. 查看Fail2ban状态"
        echo "2. 查看被封禁的IP"
        echo "3. 解封IP地址"
        echo "4. 重启Fail2ban服务"
        echo "0. 返回主菜单"
        echo ""

        read -p "请选择 [0-4]: " choice

        case $choice in
            1)
                echo ""
                log_info "Fail2ban服务状态:"
                systemctl status fail2ban --no-pager
                echo ""
                log_info "Fail2ban监狱状态:"
                fail2ban-client status
                echo ""
                read -p "按回车键继续..."
                ;;
            2)
                echo ""
                log_info "被封禁的IP地址:"
                fail2ban-client status sshd
                echo ""
                read -p "按回车键继续..."
                ;;
            3)
                echo ""
                log_info "当前被封禁的IP:"
                local banned_ips=$(fail2ban-client status sshd | grep "Banned IP list:" | cut -d: -f2 | xargs)

                if [[ -z "$banned_ips" ]]; then
                    log_info "当前没有被封禁的IP"
                else
                    echo "$banned_ips"
                    echo ""
                    read -p "请输入要解封的IP地址: " ip_to_unban

                    if [[ -n "$ip_to_unban" ]]; then
                        echo ""
                        echo -e "${YELLOW}即将解封IP地址: $ip_to_unban${NC}"
                        read -p "确认要解封这个IP吗? (y/n): " confirm

                        if [[ "$confirm" =~ ^[Yy]$ ]]; then
                            if fail2ban-client set sshd unbanip "$ip_to_unban"; then
                                log_success "IP地址 $ip_to_unban 已成功解封"
                            else
                                log_error "解封IP地址失败"
                            fi
                        else
                            log_info "解封操作已取消"
                        fi
                    fi
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            4)
                echo ""
                log_info "重启Fail2ban服务..."
                if systemctl restart fail2ban; then
                    log_success "Fail2ban服务重启成功"
                else
                    log_error "Fail2ban服务重启失败"
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            0)
                return 0
                ;;
            *)
                log_error "无效选择，请输入 0-4"
                sleep 2
                ;;
        esac
    done
}

# 管理UFW
manage_ufw() {
    while true; do
        clear
        echo -e "${CYAN}=== UFW 防火墙管理 ===${NC}"
        echo ""
        echo "1. 查看UFW状态"
        echo "2. 添加防火墙规则"
        echo "3. 删除防火墙规则"
        echo "4. 重置UFW配置"
        echo "0. 返回主菜单"
        echo ""

        read -p "请选择 [0-4]: " choice

        case $choice in
            1)
                echo ""
                log_info "UFW防火墙状态:"
                ufw status verbose
                echo ""
                read -p "按回车键继续..."
                ;;
            2)
                echo ""
                log_info "添加防火墙规则"
                echo "示例: 22/tcp, 80/tcp, 443/tcp"
                read -p "请输入端口/协议 (如 8080/tcp): " port_rule

                if [[ -n "$port_rule" ]]; then
                    if ufw allow "$port_rule"; then
                        log_success "规则添加成功: $port_rule"
                    else
                        log_error "规则添加失败"
                    fi
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            3)
                echo ""
                log_info "当前防火墙规则:"
                ufw status numbered
                echo ""
                read -p "请输入要删除的规则编号: " rule_num

                if [[ -n "$rule_num" && "$rule_num" =~ ^[0-9]+$ ]]; then
                    echo "y" | ufw delete "$rule_num"
                    log_success "规则删除成功"
                else
                    log_error "无效的规则编号"
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            4)
                echo ""
                log_warn "这将重置所有UFW配置！"
                read -p "确认要重置UFW配置吗? (y/N): " confirm

                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    ufw --force reset
                    log_success "UFW配置已重置"
                    log_info "请重新配置防火墙规则"
                else
                    log_info "重置操作已取消"
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            0)
                return 0
                ;;
            *)
                log_error "无效选择，请输入 0-4"
                sleep 2
                ;;
        esac
    done
}

# 交互式主函数
interactive_main() {
    # 检查权限和系统
    check_root
    check_dependencies

    # 主循环
    while true; do
        show_main_menu
        read -p "请选择 [0-7]: " choice

        case $choice in
            1)
                one_click_hardening
                ;;
            2)
                harden_ssh
                ;;
            3)
                install_fail2ban
                configure_fail2ban
                start_fail2ban_service
                echo ""
                read -p "按回车键返回主菜单..."
                ;;
            4)
                check_ufw_installation
                configure_ufw_firewall
                show_ufw_status
                echo ""
                read -p "按回车键返回主菜单..."
                ;;
            5)
                security_status_check
                ;;
            6)
                manage_fail2ban
                ;;
            7)
                manage_ufw
                ;;
            0)
                echo ""
                log_info "感谢使用VPS安全加固工具！"
                echo ""
                exit 0
                ;;
            *)
                log_error "无效选择，请输入 0-7"
                sleep 2
                ;;
        esac
    done
}

# 主函数 - 支持交互式和非交互式模式
main() {
    # 如果有参数，执行非交互式模式（原有逻辑）
    if [[ $# -gt 0 ]]; then
        execute_main_hardening
    else
        # 无参数时，启动交互式模式
        interactive_main
    fi
}

# 运行主程序
main "$@"