#!/bin/bash

# VPS安全加固脚本
# 适用于Debian/Ubuntu系统
# 作者: VPS安全加固助手
# 版本: 1.0

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 错误处理函数
handle_error() {
    local last_command=$1
    local last_status=$2
    print_message "$RED" "错误: 命令 '$last_command' 执行失败，状态码: $last_status"
    log_message "错误: 命令 '$last_command' 执行失败，状态码: $last_status"
}

# 捕获错误（关闭自动退出，改为记录错误）
set +e
trap 'handle_error "${BASH_COMMAND}" "$?"' ERR

# 日志文件
LOG_FILE="/var/log/security-hardening.log"

# 配置备份目录
BACKUP_DIR="/root/security-backup-$(date +%Y%m%d-%H%M%S)"

# 打印带颜色的消息
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# 打印彩色消息（仅显示，不记录日志）
print_colored() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# 获取系统信息
get_system_info() {
    local hostname=$(hostname)
    local uptime=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')
    local kernel=$(uname -r)
    local os=$(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 || echo "Unknown")
    local ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "Unknown")
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local memory_usage=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')

    echo "$hostname|$uptime|$kernel|$os|$ip|$load_avg|$memory_usage|$disk_usage"
}

# 绘制状态指示器
draw_status_indicator() {
    local status=$1
    local service_name=$2
    local width=${3:-20}

    case $status in
        "RUNNING"|"OK"|"ACTIVE")
            printf "🟢 %-${width}s" "$service_name"
            ;;
        "WARNING"|"DEGRADED")
            printf "🟡 %-${width}s" "$service_name"
            ;;
        "CRITICAL"|"STOPPED"|"ERROR")
            printf "🔴 %-${width}s" "$service_name"
            ;;
        *)
            printf "⚪ %-${width}s" "$service_name"
            ;;
    esac
}

# 记录日志
log_message() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" >> "$LOG_FILE"
    print_message "$GREEN" "$message"
}

# 确认提示
confirm_action() {
    local message=$1
    print_message "$YELLOW" "$message"
    read -p "是否继续? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_message "$RED" "操作已取消"
        return 1
    fi
    return 0
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_message "$RED" "错误: 此脚本需要root权限运行"
        exit 1
    fi
}

# 检查系统版本
check_system() {
    if [[ -f /etc/debian_version ]]; then
        OS="debian"
        print_message "$GREEN" "检测到Debian/Ubuntu系统"
    else
        print_message "$RED" "警告: 此脚本主要针对Debian/Ubuntu系统设计"
        if ! confirm_action "是否继续执行?"; then
            exit 1
        fi
    fi
}

# 创建备份目录
create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    log_message "创建备份目录: $BACKUP_DIR"
}

# 备份配置文件
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/"
        log_message "备份文件: $file"
    fi
}

# 等待fail2ban socket文件创建
wait_for_fail2ban_socket() {
    local max_wait=${1:-30}
    local message=${2:-"等待fail2ban socket文件创建..."}

    print_message "$YELLOW" "$message"
    for i in $(seq 1 $max_wait); do
        if [[ -S "/var/run/fail2ban/fail2ban.sock" ]]; then
            print_message "$GREEN" "✓ Socket文件已创建"
            return 0
        fi
        sleep 1
        if (( i % 5 == 0 )); then
            echo -n "$i/$max_wait秒 "
        else
            echo -n "."
        fi
    done
    echo
    print_message "$YELLOW" "Socket文件创建超时"
    return 1
}

# 获取当前SSH端口
get_ssh_port() {
    local ssh_port=""

    # 方法1: 从sshd_config文件获取
    ssh_port=$(grep -E "^Port\s+|^#?Port\s+" /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -1 2>/dev/null)

    # 方法2: 从当前SSH连接获取
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(ss -tlnp | grep sshd | awk -F: '{print $2}' | awk '{print $1}' | head -1 2>/dev/null)
    fi

    # 方法3: 从环境变量获取
    if [[ -z "$ssh_port" ]] && [[ -n "$SSH_CONNECTION" ]]; then
        ssh_port=$(echo $SSH_CONNECTION | awk '{print $4}')
    fi

    # 方法4: 从netstat获取
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(netstat -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    fi

    # 验证端口有效性
    if [[ -n "$ssh_port" ]] && [[ "$ssh_port" =~ ^[0-9]+$ ]] && [[ "$ssh_port" -ge 1 ]] && [[ "$ssh_port" -le 65535 ]]; then
        echo "$ssh_port"
    else
        echo "22"  # 默认端口
    fi
}

# 系统信息显示
show_system_info() {
    print_message "$BLUE" "=== 系统信息 ==="
    echo "操作系统: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "内核版本: $(uname -r)"
    echo "CPU架构: $(uname -m)"
    echo "内存信息: $(free -h | grep Mem | awk '{print $2}')"
    echo "磁盘使用: $(df -h / | tail -1 | awk '{print $5}')"
    echo "当前用户: $(whoami)"
    echo "SSH连接: $(who am i 2>/dev/null || echo "本地终端")"
    echo
}

# 系统更新
update_system() {
    print_message "$BLUE" "=== 系统更新 ==="
    if confirm_action "是否更新系统软件包?"; then
        log_message "开始系统更新"
        apt update && apt upgrade -y
        apt autoremove -y
        apt autoclean
        log_message "系统更新完成"
    fi
}

# 创建非root用户
create_user() {
    print_message "$BLUE" "=== 创建非root用户 ==="

    while true; do
        read -p "请输入新用户名: " username
        if [[ -z "$username" ]]; then
            print_message "$RED" "用户名不能为空，请重新输入"
            continue
        fi

        # 验证用户名格式
        if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
            print_message "$RED" "用户名格式不正确，请使用小写字母开头，只包含字母、数字、下划线和连字符"
            continue
        fi

        if id "$username" &>/dev/null; then
            print_message "$YELLOW" "用户 $username 已存在"
            if confirm_action "是否为现有用户配置SSH密钥?"; then
                setup_ssh_key_for_user "$username"
            fi
            return 0
        fi
        break
    done

    # 设置密码（可见输入）
    print_message "$YELLOW" "为用户 $username 设置密码"
    while true; do
        read -p "请输入密码: " password
        if [[ ${#password} -lt 8 ]]; then
            print_message "$RED" "密码长度至少8位，请重新输入"
            continue
        fi

        read -p "请确认密码: " password_confirm
        if [[ "$password" != "$password_confirm" ]]; then
            print_message "$RED" "密码不匹配，请重新输入"
            continue
        fi
        break
    done

    if confirm_action "创建用户 $username 并添加到sudo组?"; then
        # 创建用户并设置密码
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        usermod -aG sudo "$username"

        log_message "创建用户 $username 并添加到sudo组"
        
        # 选择sudo权限级别
        print_message "$YELLOW" "配置sudo权限级别:"
        echo "1. 标准sudo权限 (执行sudo命令需要密码, 推荐)"
        echo "2. 无密码sudo权限 (执行sudo命令不需要密码, 不推荐, 存在安全风险)"
        
        read -p "请选择 (1-2，默认1): " sudo_level
        sudo_level=${sudo_level:-1}
        
        if [[ "$sudo_level" == "1" ]]; then
            # 标准sudo权限 - 需要密码
            echo "$username ALL=(ALL:ALL) ALL" > /etc/sudoers.d/"$username"
            print_message "$GREEN" "已配置标准sudo权限 (需要密码)"
        else
            # 无密码sudo权限 - 存在安全风险
            print_message "$RED" "警告: 无密码sudo权限存在潜在安全风险"
            if confirm_action "确定要配置无密码sudo权限吗？"; then
                echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$username"
                print_message "$YELLOW" "已配置无密码sudo权限 (存在安全风险)"
            else
                echo "$username ALL=(ALL:ALL) ALL" > /etc/sudoers.d/"$username"
                print_message "$GREEN" "已配置标准sudo权限 (需要密码)"
            fi
        fi
        
        chmod 440 /etc/sudoers.d/"$username"
        log_message "已配置 $username 的sudo权限"

        # 设置SSH目录
        user_home="/home/$username"
        mkdir -p "$user_home/.ssh"
        chmod 700 "$user_home/.ssh"
        chown "$username:$username" "$user_home/.ssh"

        print_message "$GREEN" "用户 $username 创建成功"

        # 配置SSH密钥
        setup_ssh_key_for_user "$username"
    fi
}

# 为用户配置SSH密钥
setup_ssh_key_for_user() {
    local username=$1
    local user_home="/home/$username"

    print_message "$YELLOW" "为用户 $username 配置SSH密钥"
    echo "选择配置方式:"
    echo "1. 粘贴现有公钥"
    echo "2. 复制root用户的authorized_keys"
    echo "3. 跳过密钥配置"

    read -p "请选择 (1-3): " key_choice

    case $key_choice in
        1)
            print_message "$YELLOW" "请粘贴SSH公钥:"
            print_message "$BLUE" "提示:"
            echo "- 公钥通常以 ssh-rsa, ssh-ed25519, ecdsa-sha2- 开头"
            echo "- 在终端中右键粘贴，或使用 Ctrl+Shift+V"
            echo "- 粘贴后直接按回车确认"
            echo "- 如需取消，输入 'cancel'"
            echo
            read -p "请粘贴SSH公钥: " ssh_key

            if [[ "$ssh_key" == "cancel" ]]; then
                print_message "$YELLOW" "已取消SSH密钥配置"
                return 0
            fi

            # 清理可能的多余空格和换行
            ssh_key=$(echo "$ssh_key" | tr -d '\n\r' | sed 's/[[:space:]]\+/ /g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            if [[ -n "$ssh_key" && "$ssh_key" =~ ^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-) ]]; then
                # 确保目录存在
                mkdir -p "$user_home/.ssh"

                # 如果文件已存在，追加而不是覆盖
                if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
                    echo "$ssh_key" >> "$user_home/.ssh/authorized_keys"
                    print_message "$GREEN" "SSH公钥已追加到现有配置"
                else
                    echo "$ssh_key" > "$user_home/.ssh/authorized_keys"
                    print_message "$GREEN" "SSH公钥已配置"
                fi

                chmod 600 "$user_home/.ssh/authorized_keys"
                chmod 700 "$user_home/.ssh"
                chown -R "$username:$username" "$user_home/.ssh"

                log_message "为用户 $username 配置SSH公钥"

                # 显示配置的密钥信息
                key_type=$(echo "$ssh_key" | awk '{print $1}')
                key_comment=$(echo "$ssh_key" | awk '{print $3}')
                print_message "$BLUE" "已配置密钥类型: $key_type"
                if [[ -n "$key_comment" ]]; then
                    print_message "$BLUE" "密钥备注: $key_comment"
                fi
            else
                print_message "$RED" "无效的SSH公钥格式"
                print_message "$YELLOW" "有效的公钥应该类似于:"
                echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx user@hostname"
                echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx user@hostname"
            fi
            ;;
        2)
            if [[ -f "/root/.ssh/authorized_keys" ]]; then
                cp "/root/.ssh/authorized_keys" "$user_home/.ssh/authorized_keys"
                chmod 600 "$user_home/.ssh/authorized_keys"
                chown "$username:$username" "$user_home/.ssh/authorized_keys"
                print_message "$GREEN" "已复制root用户的SSH密钥"
                log_message "为用户 $username 复制root的SSH密钥"
            else
                print_message "$RED" "root用户没有配置SSH密钥"
            fi
            ;;
        3)
            print_message "$YELLOW" "跳过SSH密钥配置"
            print_message "$RED" "警告: 如果禁用密码认证，该用户将无法通过SSH登录"
            ;;
        *)
            print_message "$RED" "无效选择，跳过密钥配置"
            ;;
    esac
}

# SSH安全配置
configure_ssh() {
    print_message "$BLUE" "=== SSH安全配置 ==="

    backup_file "/etc/ssh/sshd_config"

    # 检查并处理sshd_config.d目录中的配置文件
    print_message "$YELLOW" "检查SSH配置目录..."
    if [[ -d "/etc/ssh/sshd_config.d" ]]; then
        config_files=$(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)
        if [[ -n "$config_files" ]]; then
            print_message "$YELLOW" "发现现有SSH配置文件:"
            ls -la /etc/ssh/sshd_config.d/*.conf
            echo
            if confirm_action "是否备份并禁用这些配置文件以避免冲突?"; then
                for conf_file in $config_files; do
                    backup_name="${conf_file}.bak-$(date +%Y%m%d-%H%M%S)"
                    mv "$conf_file" "$backup_name"
                    print_message "$GREEN" "已备份: $conf_file -> $backup_name"
                    log_message "备份SSH配置文件: $conf_file"
                done
            fi
        fi
    else
        mkdir -p /etc/ssh/sshd_config.d
    fi
    
    # 修改SSH端口
    print_message "$YELLOW" "SSH端口配置"
    print_message "$CYAN" "建议使用非标准端口以减少自动扫描攻击"
    print_message "$CYAN" "常用安全端口: 4025, 2222, 2022, 22022"
    echo
    read -p "请输入新的SSH端口 (推荐4025, 直接回车保持当前端口): " ssh_port

    # 如果用户没有输入，获取当前SSH端口
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(sshd -T 2>/dev/null | grep -i "^port" | awk '{print $2}' || echo "22")
        print_message "$YELLOW" "保持当前SSH端口: $ssh_port"
    else
        # 验证端口号
        if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || [[ "$ssh_port" -lt 1024 ]] || [[ "$ssh_port" -gt 65535 ]]; then
            print_message "$RED" "无效的端口号，请使用1024-65535之间的端口"
            return 1
        fi

        # 检查端口是否被占用
        if netstat -tlnp 2>/dev/null | grep -q ":$ssh_port "; then
            print_message "$RED" "端口 $ssh_port 已被占用，请选择其他端口"
            return 1
        fi

        print_message "$GREEN" "将SSH端口设置为: $ssh_port"
    fi

    # SSH密钥验证
    print_message "$YELLOW" "SSH密钥验证"
    print_message "$RED" "⚠️  重要警告: 即将禁用密码认证，必须确保SSH密钥已正确配置！"
    echo

    # 检查当前用户的SSH密钥
    local current_user=$(who am i | awk '{print $1}' || echo "root")
    local ssh_key_configured=false

    # 检查root用户的SSH密钥
    if [[ -f "/root/.ssh/authorized_keys" && -s "/root/.ssh/authorized_keys" ]]; then
        print_message "$GREEN" "✓ Root用户已配置SSH密钥"
        ssh_key_configured=true
    else
        print_message "$RED" "✗ Root用户未配置SSH密钥"
    fi

    # 获取允许登录的用户列表
    print_message "$YELLOW" "配置允许SSH登录的用户"
    echo "当前登录用户: $current_user"
    echo
    print_message "$CYAN" "请输入允许SSH登录的用户名（多个用户用空格分隔）"
    print_message "$CYAN" "建议包含当前用户以避免被锁定"
    read -p "允许登录的用户 (默认: $current_user root): " allowed_users
    allowed_users=${allowed_users:-"$current_user root"}

    # 验证用户是否存在并检查SSH密钥
    local valid_users=()
    local users_with_keys=()

    for user in $allowed_users; do
        if id "$user" &>/dev/null; then
            valid_users+=("$user")
            # 检查用户的SSH密钥
            local user_home=$(eval echo "~$user")
            if [[ -f "$user_home/.ssh/authorized_keys" && -s "$user_home/.ssh/authorized_keys" ]]; then
                users_with_keys+=("$user")
                print_message "$GREEN" "✓ 用户 $user 已配置SSH密钥"
            else
                print_message "$RED" "✗ 用户 $user 未配置SSH密钥"
            fi
        else
            print_message "$RED" "✗ 用户 $user 不存在"
        fi
    done

    # 安全检查
    if [[ ${#users_with_keys[@]} -eq 0 ]]; then
        print_message "$RED" "严重警告: 没有用户配置SSH密钥！"
        print_message "$RED" "禁用密码认证后将无法登录服务器！"
        echo
        if ! confirm_action "是否继续配置SSH密钥? (强烈建议选择是)"; then
            print_message "$YELLOW" "SSH配置已取消"
            return 1
        fi

        # 引导用户配置SSH密钥
        print_message "$YELLOW" "SSH密钥配置指南:"
        echo "1. 在本地生成密钥对: ssh-keygen -t ed25519 -C 'your-email@example.com'"
        echo "2. 复制公钥到服务器: ssh-copy-id -p $ssh_port user@server-ip"
        echo "3. 或手动添加公钥到 ~/.ssh/authorized_keys"
        echo
        read -p "配置完成后按回车继续..." -r
    fi

    # 应用SSH安全配置
    print_message "$YELLOW" "应用SSH安全配置..."

    # 备份原始配置
    backup_file "/etc/ssh/sshd_config"

    # 使用sshd_config.d目录创建自定义配置
    cat > /etc/ssh/sshd_config.d/99-security-hardening.conf << EOF
# 安全加固自定义SSH配置
# 创建时间: $(date)
# 警告: 此配置禁用密码认证，请确保SSH密钥已正确配置

# SSH端口配置
Port $ssh_port

# Root用户仅允许密钥登录
PermitRootLogin prohibit-password

# 认证配置
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# 禁用不安全的认证方式
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

# PAM支持（允许本地认证）
UsePAM yes

# 连接保活配置（防止超时断开）
ClientAliveInterval 60
ClientAliveCountMax 3

# 性能优化
UseDNS no
TCPKeepAlive yes

# 安全限制
Protocol 2
MaxAuthTries 3
LoginGraceTime 60
MaxStartups 10:30:100
MaxSessions 4

# 允许的用户
AllowUsers ${valid_users[*]}

# 禁用不安全的功能
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog yes
Compression delayed

# 环境变量传递（保持系统兼容性）
AcceptEnv LANG LC_*

# SFTP子系统支持
Subsystem sftp /usr/lib/openssh/sftp-server

# 强化加密算法
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
EOF

    log_message "SSH安全配置已应用: 端口$ssh_port, 允许用户: ${valid_users[*]}, 禁用密码认证"

    # 最终安全检查
    if [[ ${#users_with_keys[@]} -eq 0 ]]; then
        print_message "$RED" "最终警告: 没有用户配置SSH密钥！"
        if confirm_action "是否现在配置SSH密钥?"; then
            setup_ssh_key_for_user "root"
        else
            print_message "$RED" "继续将导致无法通过SSH登录！"
            if ! confirm_action "确认继续? (非常危险)"; then
                return 1
            fi
        fi
    fi
    
    # 测试SSH配置
    print_message "$YELLOW" "测试SSH配置语法..."
    if sshd -t; then
        print_message "$GREEN" "SSH配置语法正确"

        # 显示有效配置
        print_message "$YELLOW" "当前有效SSH配置:"
        echo "端口: $(sshd -T | grep -i "^port" | awk '{print $2}')"
        echo "Root登录: $(sshd -T | grep -i "^permitrootlogin" | awk '{print $2}')"
        echo "密码认证: $(sshd -T | grep -i "^passwordauthentication" | awk '{print $2}')"
        echo "密钥认证: $(sshd -T | grep -i "^pubkeyauthentication" | awk '{print $2}')"
        echo
    else
        print_message "$RED" "SSH配置语法错误，请检查配置"
        return 1
    fi

    # 重启SSH服务
    print_message "$RED" "⚠️  重要警告 ⚠️"
    print_message "$YELLOW" "即将重启SSH服务，请确保："
    echo "1. 新SSH端口: $ssh_port"
    echo "2. 防火墙已开放该端口"
    echo "3. 您有其他方式访问服务器（如控制台）"
    echo "4. SSH密钥已正确配置（如果禁用了密码认证）"
    echo

    if confirm_action "确认重启SSH服务? (建议先开启新终端测试连接)"; then
        # 先测试新配置
        print_message "$YELLOW" "重启SSH服务..."
        systemctl restart sshd

        if systemctl is-active --quiet sshd; then
            print_message "$GREEN" "SSH服务重启成功"
            log_message "SSH服务已重启"

            print_message "$YELLOW" "新的连接方式:"
            echo "ssh -p $ssh_port username@$(hostname -I | awk '{print $1}')"
            print_message "$RED" "请立即在新终端测试连接，确保可以正常登录！"
        else
            print_message "$RED" "SSH服务启动失败！"
            print_message "$YELLOW" "尝试恢复配置..."
            cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
            systemctl restart sshd
            print_message "$YELLOW" "已恢复原始SSH配置"
        fi
    fi
}

# 防火墙配置
configure_firewall() {
    print_message "$BLUE" "=== 防火墙配置 ==="

    # 检查是否已安装ufw
    if ! command -v ufw &> /dev/null; then
        if confirm_action "ufw未安装，是否安装?"; then
            apt update && apt install -y ufw
            log_message "安装ufw防火墙"
        else
            return 1
        fi
    fi

    if confirm_action "是否配置基础防火墙规则?"; then
        # 重置防火墙规则
        ufw --force reset

        # 设置默认策略
        ufw default deny incoming
        ufw default allow outgoing

        # 允许SSH (获取当前SSH端口)
        ssh_port=$(get_ssh_port)
        print_message "$GREEN" "检测到SSH端口: $ssh_port"

        ufw allow "$ssh_port"/tcp comment 'SSH'
        print_message "$GREEN" "已允许SSH端口 $ssh_port/tcp"

        # 检测Web服务
        local web_server_installed=false
        if systemctl is-active --quiet nginx || systemctl is-active --quiet apache2; then
            web_server_installed=true
            print_message "$YELLOW" "检测到Web服务器正在运行"
        fi

        # 根据检测结果推荐操作
        if [[ "$web_server_installed" == true ]]; then
            # Web服务器已安装，建议开启HTTP/HTTPS
            if confirm_action "检测到Web服务器，建议开启HTTP(80)和HTTPS(443)端口，是否开启?"; then
                ufw allow 80/tcp comment 'HTTP'
                ufw allow 443/tcp comment 'HTTPS'
                log_message "已开启HTTP和HTTPS端口"
            fi
        else
            # Web服务器未安装，提供警告
            print_message "$YELLOW" "未检测到Web服务器"
            if confirm_action "没有运行中的Web服务器，是否仍要开启HTTP(80)和HTTPS(443)端口? (不建议)"; then
                print_message "$RED" "警告: 开启未使用的端口可能增加安全风险"
                if confirm_action "确认开启HTTP和HTTPS端口?"; then
                    ufw allow 80/tcp comment 'HTTP'
                    ufw allow 443/tcp comment 'HTTPS'
                    log_message "已开启HTTP和HTTPS端口 (尽管未检测到Web服务)"
                fi
            fi
        fi

        # 检测常见服务
        print_message "$YELLOW" "检测其他常见服务..."
        local detected_services=()
        
        # 检查常见服务是否正在运行
        if systemctl is-active --quiet mysql; then
            detected_services+=("MySQL(3306/tcp)")
        fi
        
        if systemctl is-active --quiet postgresql; then
            detected_services+=("PostgreSQL(5432/tcp)")
        fi
        
        if systemctl is-active --quiet redis-server; then
            detected_services+=("Redis(6379/tcp)")
        fi
        
        if systemctl is-active --quiet docker; then
            detected_services+=("Docker(可能需要额外端口)")
        fi
        
        # 检查是否运行了特定端口上的服务
        local listening_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -n | uniq)
        local common_ports=(3000 3306 5432 6379 8080 8443 27017)
        local detected_port_services=()
        
        for port in $listening_ports; do
            case $port in
                3000)
                    detected_port_services+=("NodeJS/服务(3000/tcp)")
                    ;;
                8080)
                    detected_port_services+=("Web服务(8080/tcp)")
                    ;;
                8443)
                    detected_port_services+=("Web服务(8443/tcp)")
                    ;;
                27017)
                    detected_port_services+=("MongoDB(27017/tcp)")
                    ;;
            esac
        done
        
        # 将检测到的端口服务添加到列表
        if [[ ${#detected_port_services[@]} -gt 0 ]]; then
            for service in "${detected_port_services[@]}"; do
                detected_services+=("$service")
            done
        fi
        
        # 如果检测到服务，询问是否开放相关端口
        if [[ ${#detected_services[@]} -gt 0 ]]; then
            print_message "$YELLOW" "检测到以下服务可能需要网络访问:"
            for service in "${detected_services[@]}"; do
                echo "- $service"
            done
            
            if confirm_action "是否为检测到的服务配置防火墙规则?"; then
                if systemctl is-active --quiet mysql; then
                    if confirm_action "允许MySQL端口(3306/tcp)? (仅当需要远程访问时)"; then
                        ufw allow 3306/tcp comment 'MySQL'
                        log_message "已开启MySQL端口"
                    fi
                fi
                
                if systemctl is-active --quiet postgresql; then
                    if confirm_action "允许PostgreSQL端口(5432/tcp)? (仅当需要远程访问时)"; then
                        ufw allow 5432/tcp comment 'PostgreSQL'
                        log_message "已开启PostgreSQL端口"
                    fi
                fi
                
                if systemctl is-active --quiet redis-server; then
                    if confirm_action "允许Redis端口(6379/tcp)? (仅当需要远程访问时)"; then
                        ufw allow 6379/tcp comment 'Redis'
                        log_message "已开启Redis端口"
                    fi
                fi
                
                if systemctl is-active --quiet docker; then
                    print_message "$YELLOW" "Docker可能需要多个端口，请在稍后手动添加"
                fi
                
                # 处理检测到的端口服务
                for service in "${detected_port_services[@]}"; do
                    if [[ "$service" == *"(3000/tcp)"* ]]; then
                        if confirm_action "允许NodeJS/服务端口(3000/tcp)?"; then
                            ufw allow 3000/tcp comment 'NodeJS'
                            log_message "已开启NodeJS端口"
                        fi
                    elif [[ "$service" == *"(8080/tcp)"* ]]; then
                        if confirm_action "允许Web服务端口(8080/tcp)?"; then
                            ufw allow 8080/tcp comment 'Web'
                            log_message "已开启8080端口"
                        fi
                    elif [[ "$service" == *"(8443/tcp)"* ]]; then
                        if confirm_action "允许Web服务端口(8443/tcp)?"; then
                            ufw allow 8443/tcp comment 'Web'
                            log_message "已开启8443端口"
                        fi
                    elif [[ "$service" == *"(27017/tcp)"* ]]; then
                        if confirm_action "允许MongoDB端口(27017/tcp)? (仅当需要远程访问时)"; then
                            ufw allow 27017/tcp comment 'MongoDB'
                            log_message "已开启MongoDB端口"
                        fi
                    fi
                done
            fi
        fi

        # 自定义端口
        read -p "是否需要开放其他端口? (格式: 端口/协议，如8080/tcp，多个用空格分隔): " custom_ports
        if [[ -n "$custom_ports" ]]; then
            for port in $custom_ports; do
                ufw allow "$port" comment 'Custom'
                log_message "开放端口: $port"
            done
        fi

        # 启用防火墙
        if confirm_action "是否启用防火墙?"; then
            print_message "$RED" "警告: 启用防火墙可能会断开现有连接"
            print_message "$YELLOW" "确保已允许SSH端口 ($ssh_port/tcp)"
            if confirm_action "确认启用防火墙?"; then
                ufw --force enable
                log_message "防火墙已启用"

                # 显示防火墙状态
                print_message "$GREEN" "防火墙规则:"
                ufw status numbered
            fi
        fi
    fi
}

# 安装和配置fail2ban
install_fail2ban() {
    print_message "$BLUE" "=== 安装fail2ban ==="

    if ! command -v fail2ban-server &> /dev/null; then
        if confirm_action "fail2ban未安装，是否安装?"; then
            apt update && apt install -y fail2ban
            log_message "安装fail2ban"
        else
            return 1
        fi
    fi

    if confirm_action "是否配置fail2ban规则?"; then
        # 备份现有配置
        backup_file "/etc/fail2ban/jail.local"
        
        # 检查jail.local是否存在，如果存在且包含[sshd]段，提示用户
        if [[ -f "/etc/fail2ban/jail.local" ]] && grep -q "\[sshd\]" "/etc/fail2ban/jail.local"; then
            print_message "$YELLOW" "检测到现有fail2ban配置，包含[sshd]段"
            if confirm_action "是否覆盖现有配置?"; then
                log_message "覆盖现有fail2ban配置"
            else
                print_message "$YELLOW" "将保留现有配置，仅更新端口和启用状态"
                # 更新ssh端口配置
                ssh_port=$(get_ssh_port)
                sed -i "s/^port = .*/port = $ssh_port/" "/etc/fail2ban/jail.local"
                # 确保sshd jail启用
                sed -i "s/^enabled = false/enabled = true/" "/etc/fail2ban/jail.local"
                
                log_message "更新fail2ban SSH端口配置为: $ssh_port"
                
                # 重启fail2ban服务
                systemctl restart fail2ban
                print_message "$GREEN" "fail2ban服务已重启，配置已更新"
                return 0
            fi
        fi

        # 获取SSH端口
        ssh_port=$(get_ssh_port)

        # 创建jail.local配置
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 封禁时间 (秒) - 默认1小时
bantime = 3600
# 查找时间窗口 (秒) - 10分钟
findtime = 600
# 最大重试次数
maxretry = 3
# 忽略的IP地址
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[ufw-block]
enabled = false
filter = ufw-block
logpath = /var/log/syslog
maxretry = 5
findtime = 600
bantime = 86400
action = ufw

[nginx-http-auth]
enabled = false
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-limit-req]
enabled = false
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600
EOF

        log_message "配置fail2ban规则"

        # 创建ufw-block过滤器 (检查是否存在)
        if [[ ! -f "/etc/fail2ban/filter.d/ufw-block.conf" ]]; then
            cat > /etc/fail2ban/filter.d/ufw-block.conf << 'EOF'
[Definition]
failregex = ^.*\[UFW BLOCK\].*SRC=<HOST>.*$
ignoreregex =
EOF
            log_message "创建ufw-block过滤器"
        fi

        # 创建ufw action (如果不存在)
        if [[ ! -f "/etc/fail2ban/action.d/ufw.conf" ]]; then
            cat > /etc/fail2ban/action.d/ufw.conf << 'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = ufw insert 1 deny from <ip> to any
actionunban = ufw delete deny from <ip> to any
EOF
            log_message "创建ufw action配置"
        fi

        # 验证fail2ban配置
        print_message "$YELLOW" "验证fail2ban配置..."

        # 首先测试完整配置
        if ! test_and_fix_fail2ban_config "$ssh_port" "full"; then
            print_message "$YELLOW" "完整配置失败，显示错误信息："
            fail2ban-client -t 2>&1 | head -5

            print_message "$YELLOW" "尝试基本配置..."
            if ! test_and_fix_fail2ban_config "$ssh_port" "basic"; then
                print_message "$YELLOW" "基本配置失败，尝试最简配置..."
                if ! test_and_fix_fail2ban_config "$ssh_port" "minimal"; then
                    print_message "$RED" "所有配置都失败，将使用默认配置并跳过验证"
                    # 创建最基本的配置，不验证
                    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $ssh_port
EOF
                fi
            fi
        fi

        # 启动fail2ban服务
        print_message "$YELLOW" "启动fail2ban服务..."
        systemctl enable fail2ban
        systemctl restart fail2ban
        log_message "启动fail2ban服务"

        # 使用systemctl检查服务状态
        print_message "$YELLOW" "等待fail2ban服务启动 (可能需要30-60秒)..."
        max_wait=60  # 最多等待60秒
        socket_ready=false
        service_ready=false

        for i in $(seq 1 $max_wait); do
            # 检查1: 服务是否处于active状态
            if systemctl is-active --quiet fail2ban; then
                service_ready=true
                print_message "$GREEN" "✓ 服务已激活"
                
                # 检查2: socket文件是否存在并可访问
                if [[ -S "/var/run/fail2ban/fail2ban.sock" ]]; then
                    socket_ready=true
                    print_message "$GREEN" "✓ Socket文件已就绪"
                    break
                fi
            fi
            
            # 显示等待进度
            if (( i % 5 == 0 )); then
                echo -n "$i/$max_wait秒 "
            else
                echo -n "."
            fi
            sleep 1
        done
        echo

        # 即使socket未就绪，也尝试继续执行
        if [[ "$service_ready" == true ]]; then
            print_message "$GREEN" "fail2ban服务已启动"
            
            # 使用systemd查询服务状态
            print_message "$YELLOW" "服务详细信息:"
            systemctl status fail2ban --no-pager -l | head -10
            
            # 检查系统日志中的fail2ban启动信息
            print_message "$YELLOW" "Fail2ban日志信息:"
            journalctl -u fail2ban --since "1 minute ago" --no-pager -l | grep -E "Starting|Started|Stopping|Stopped|ERROR" | tail -5
            
            if [[ "$socket_ready" == false ]]; then
                print_message "$YELLOW" "警告: fail2ban服务已启动，但socket文件可能尚未就绪"
                print_message "$YELLOW" "服务可能仍在初始化，这不影响fail2ban功能"
                
                # 显示socket文件信息(如果存在)
                if [[ -e "/var/run/fail2ban/fail2ban.sock" ]]; then
                    ls -la /var/run/fail2ban/fail2ban.sock
                else
                    print_message "$YELLOW" "Socket文件尚未创建: /var/run/fail2ban/fail2ban.sock"
                fi
                
                # 尝试强制重新加载服务
                print_message "$YELLOW" "尝试重新加载服务..."
                systemctl daemon-reload
                systemctl try-restart fail2ban
                sleep 5
            fi
            
            # 最后尝试使用客户端获取状态(即使失败也继续)
            print_message "$YELLOW" "尝试获取监狱信息 (可能不成功)..."
            if fail2ban-client status &>/dev/null; then
                print_message "$GREEN" "✓ fail2ban监狱列表:"
                fail2ban-client status | grep "Jail list" | sed 's/.*Jail list:/Jail list:/'
            else
                print_message "$YELLOW" "注意: fail2ban-client命令暂时无法使用"
                print_message "$YELLOW" "这不影响fail2ban功能，服务仍在运行中"
                print_message "$YELLOW" "稍后可使用以下命令查看状态:"
                echo "  systemctl status fail2ban"
                echo "  fail2ban-client status"
            fi
        else
            print_message "$RED" "fail2ban服务启动失败或超时"
            print_message "$YELLOW" "检查服务状态和错误日志:"
            systemctl status fail2ban --no-pager -l
            journalctl -u fail2ban --no-pager -n 20
            
            if confirm_action "是否尝试修复服务?"; then
                print_message "$YELLOW" "尝试修复fail2ban服务..."
                systemctl daemon-reload
                systemctl reset-failed fail2ban.service
                systemctl restart fail2ban
                sleep 5
                if systemctl is-active --quiet fail2ban; then
                    print_message "$GREEN" "✓ 服务已恢复运行"
                else
                    print_message "$RED" "服务恢复失败，可能需要手动检查"
                fi
            fi
        fi

        print_message "$YELLOW" "fail2ban配置说明:"
        echo "- SSH保护: 3次失败后封禁1小时"
        echo "- UFW阻止: 5次触发后封禁1天"
        echo "- 查看状态: fail2ban-client status"
        echo "- 解封IP: fail2ban-client set jail名 unbanip IP地址"
        echo "- 管理工具: 选择菜单选项 '12. fail2ban管理'"
        echo
        print_message "$YELLOW" "故障排除提示:"
        echo "- 如果遇到socket连接问题，请使用管理菜单中的'诊断和修复问题'选项"
        echo "- 服务启动可能需要30-60秒，请耐心等待"
        echo "- 配置文件位置: /etc/fail2ban/jail.local"
    fi
}

# 网络安全配置
configure_network_security() {
    print_message "$BLUE" "=== 网络安全配置 ==="

    if confirm_action "是否配置网络安全参数?"; then
        # 备份原始配置
        backup_file "/etc/sysctl.conf"
        
        # 创建独立配置文件
        local sysctl_security_conf="/etc/sysctl.d/99-security-hardening.conf"
        
        # 删除旧的安全配置文件(如果存在)
        if [[ -f "$sysctl_security_conf" ]]; then
            mv "$sysctl_security_conf" "$BACKUP_DIR/" 2>/dev/null
            log_message "备份旧的网络安全配置"
        fi

        # 网络安全参数写入独立配置文件
        cat > "$sysctl_security_conf" << EOF
# 网络安全配置 - 由安全加固脚本创建
# 创建时间: $(date)

# 禁用IP转发
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 禁用源路由
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# 禁用重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# 启用反向路径过滤
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 忽略ICMP ping请求
net.ipv4.icmp_echo_ignore_all = 1

# 忽略广播ping
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 启用SYN cookies
net.ipv4.tcp_syncookies = 1

# 记录可疑数据包
net.ipv4.conf.all.log_martians = 1
EOF

        # 应用配置
        sysctl -p "$sysctl_security_conf"
        log_message "应用网络安全配置"
        print_message "$GREEN" "网络安全参数已配置到: $sysctl_security_conf"
    fi

    # 禁用不必要的服务
    if confirm_action "是否检查并禁用不必要的网络服务?"; then
        print_message "$YELLOW" "当前监听的端口:"
        netstat -tlnp 2>/dev/null || ss -tlnp

        # 常见的可能需要禁用的服务
        services_to_check=("telnet" "rsh" "rlogin" "vsftpd" "apache2" "nginx")

        for service in "${services_to_check[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                if confirm_action "发现服务 $service 正在运行，是否禁用?"; then
                    systemctl stop "$service"
                    systemctl disable "$service"
                    log_message "禁用服务: $service"
                fi
            fi
        done
    fi
}

# 系统监控配置
configure_monitoring() {
    print_message "$BLUE" "=== 系统监控配置 ==="

    # 配置日志轮转
    if confirm_action "是否配置日志轮转?"; then
        backup_file "/etc/logrotate.conf"

        # 创建安全日志轮转配置
        cat > /etc/logrotate.d/security << EOF
/var/log/auth.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
}

/var/log/security-hardening.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
        log_message "配置日志轮转"
    fi

    # 安装系统监控工具
    if confirm_action "是否安装基础监控工具 (htop, iotop, nethogs)?"; then
        apt update && apt install -y htop iotop nethogs
        log_message "安装监控工具"
    fi

    # 配置定时任务检查
    if confirm_action "是否设置定时安全检查?"; then
        cat > /etc/cron.daily/security-check << 'EOF'
#!/bin/bash
# 每日安全检查脚本

LOG_FILE="/var/log/daily-security-check.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] 开始每日安全检查" >> "$LOG_FILE"

# 检查失败的登录尝试
echo "[$DATE] 检查失败的登录尝试:" >> "$LOG_FILE"
grep "Failed password" /var/log/auth.log | tail -10 >> "$LOG_FILE"

# 检查sudo使用情况
echo "[$DATE] 检查sudo使用情况:" >> "$LOG_FILE"
grep "sudo:" /var/log/auth.log | tail -10 >> "$LOG_FILE"

# 检查系统负载
echo "[$DATE] 系统负载: $(uptime)" >> "$LOG_FILE"

# 检查磁盘使用
echo "[$DATE] 磁盘使用:" >> "$LOG_FILE"
df -h >> "$LOG_FILE"

echo "[$DATE] 每日安全检查完成" >> "$LOG_FILE"
echo "----------------------------------------" >> "$LOG_FILE"
EOF

        chmod +x /etc/cron.daily/security-check
        log_message "设置定时安全检查"
    fi
}

# 精简系统组件
system_cleanup() {
    print_message "$BLUE" "=== 精简系统组件 ==="

    # 检查并移除不必要的软件包
    if confirm_action "是否检查并移除不必要的软件包?"; then
        print_message "$YELLOW" "检查已安装的网络服务..."

        # 常见的可能不需要的服务和软件包
        unnecessary_packages=("telnet" "rsh-client" "rsh-redone-client" "talk" "talkd"
                             "finger" "fingerd" "rwho" "rwhod" "rexec" "rexecd"
                             "rcp" "rlogin" "rlogind" "rsh" "rshd" "tftp" "tftpd"
                             "xinetd" "inetd" "openbsd-inetd" "nis" "ntpdate")

        removed_packages=()
        for package in "${unnecessary_packages[@]}"; do
            if dpkg -l | grep -q "^ii.*$package "; then
                print_message "$YELLOW" "发现软件包: $package"
                if confirm_action "是否移除 $package?"; then
                    apt remove --purge -y "$package"
                    removed_packages+=("$package")
                    log_message "移除软件包: $package"
                fi
            fi
        done

        if [[ ${#removed_packages[@]} -gt 0 ]]; then
            print_message "$GREEN" "已移除的软件包: ${removed_packages[*]}"
            apt autoremove -y
            apt autoclean
        else
            print_message "$GREEN" "未发现需要移除的不必要软件包"
        fi
    fi

    # 禁用不必要的服务
    if confirm_action "是否检查并禁用不必要的系统服务?"; then
        print_message "$YELLOW" "检查系统服务..."

        # 可能不需要的服务
        unnecessary_services=("avahi-daemon" "cups" "bluetooth" "ModemManager"
                             "whoopsie" "apport" "snapd" "accounts-daemon")

        disabled_services=()
        for service in "${unnecessary_services[@]}"; do
            if systemctl is-enabled "$service" &>/dev/null; then
                print_message "$YELLOW" "发现服务: $service"
                if confirm_action "是否禁用 $service 服务?"; then
                    systemctl stop "$service" 2>/dev/null || true
                    systemctl disable "$service" 2>/dev/null || true
                    disabled_services+=("$service")
                    log_message "禁用服务: $service"
                fi
            fi
        done

        if [[ ${#disabled_services[@]} -gt 0 ]]; then
            print_message "$GREEN" "已禁用的服务: ${disabled_services[*]}"
        else
            print_message "$GREEN" "未发现需要禁用的不必要服务"
        fi
    fi

    # 清理系统
    if confirm_action "是否清理系统缓存和临时文件?"; then
        # 清理包缓存
        apt clean
        apt autoclean
        apt autoremove -y

        # 清理日志文件（保留最近7天）
        journalctl --vacuum-time=7d

        # 清理临时文件
        find /tmp -type f -atime +7 -delete 2>/dev/null || true
        find /var/tmp -type f -atime +7 -delete 2>/dev/null || true

        log_message "系统清理完成"
        print_message "$GREEN" "系统清理完成"
    fi
}

# 安全扫描与检查
security_scan() {
    print_message "$BLUE" "=== 安全扫描与检查 ==="

    # 检查开放端口
    if confirm_action "是否检查开放端口?"; then
        print_message "$YELLOW" "当前开放的端口:"
        if command -v ss &> /dev/null; then
            ss -tlnp
        else
            netstat -tlnp 2>/dev/null || echo "netstat命令不可用"
        fi
        echo
    fi

    # 检查用户账户
    if confirm_action "是否检查用户账户安全?"; then
        print_message "$YELLOW" "系统用户账户检查:"

        # 检查空密码账户
        empty_password_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || echo "无法读取shadow文件")
        if [[ -n "$empty_password_users" && "$empty_password_users" != "无法读取shadow文件" ]]; then
            print_message "$RED" "发现空密码账户: $empty_password_users"
        else
            print_message "$GREEN" "未发现空密码账户"
        fi

        # 检查UID为0的账户
        root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
        print_message "$YELLOW" "UID为0的账户: $root_users"

        # 检查可登录的用户
        login_users=$(grep -E "(/bin/bash|/bin/sh|/bin/zsh)$" /etc/passwd | cut -d: -f1)
        print_message "$YELLOW" "可登录的用户: $login_users"
        echo
    fi

    # 检查文件权限
    if confirm_action "是否检查关键文件权限?"; then
        print_message "$YELLOW" "关键文件权限检查:"

        critical_files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow"
                       "/etc/ssh/sshd_config" "/etc/sudoers")

        for file in "${critical_files[@]}"; do
            if [[ -f "$file" ]]; then
                perms=$(stat -c "%a %n" "$file")
                print_message "$BLUE" "$perms"
            fi
        done
        echo
    fi

    # 检查最近登录
    if confirm_action "是否检查最近登录记录?"; then
        print_message "$YELLOW" "最近登录记录:"
        last -n 10
        echo

        print_message "$YELLOW" "失败的登录尝试:"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 || echo "无失败登录记录"
        echo
    fi

    # 检查系统完整性
    if confirm_action "是否安装并运行rkhunter进行系统扫描?"; then
        if ! command -v rkhunter &> /dev/null; then
            apt update && apt install -y rkhunter
        fi

        print_message "$YELLOW" "更新rkhunter数据库..."
        rkhunter --update

        print_message "$YELLOW" "运行系统扫描..."
        rkhunter --check --skip-keypress

        log_message "完成rkhunter系统扫描"
    fi
}

# 备份与恢复配置
backup_recovery() {
    print_message "$BLUE" "=== 备份与恢复配置 ==="

    # 创建完整备份
    if confirm_action "是否创建系统配置完整备份?"; then
        backup_full_dir="/root/full-backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup_full_dir"

        # 备份重要配置文件
        important_configs=("/etc/ssh/" "/etc/ufw/" "/etc/fail2ban/" "/etc/sudoers"
                          "/etc/passwd" "/etc/group" "/etc/shadow" "/etc/gshadow"
                          "/etc/hosts" "/etc/hostname" "/etc/resolv.conf"
                          "/etc/sysctl.conf" "/etc/fstab" "/etc/crontab"
                          "/var/spool/cron/")

        for config in "${important_configs[@]}"; do
            if [[ -e "$config" ]]; then
                cp -r "$config" "$backup_full_dir/" 2>/dev/null || true
                log_message "备份: $config"
            fi
        done

        # 备份已安装软件包列表
        dpkg --get-selections > "$backup_full_dir/installed-packages.txt"

        # 备份防火墙规则
        if command -v ufw &> /dev/null; then
            ufw status numbered > "$backup_full_dir/ufw-rules.txt"
        fi

        # 创建备份说明
        cat > "$backup_full_dir/README.txt" << EOF
系统配置备份
创建时间: $(date)
系统信息: $(uname -a)
备份内容: 重要配置文件、软件包列表、防火墙规则

恢复说明:
1. 恢复配置文件: cp -r backup_file /original/location/
2. 重启相关服务: systemctl restart service_name
3. 恢复软件包: dpkg --set-selections < installed-packages.txt && apt-get dselect-upgrade
EOF

        print_message "$GREEN" "完整备份创建完成: $backup_full_dir"
        log_message "创建完整备份: $backup_full_dir"
    fi

    # 设置自动备份
    if confirm_action "是否设置每周自动备份?"; then
        cat > /etc/cron.weekly/system-backup << 'EOF'
#!/bin/bash
# 每周系统配置备份脚本

BACKUP_DIR="/root/weekly-backup-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# 备份重要配置
cp -r /etc/ssh/ "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/ufw/ "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/fail2ban/ "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null || true

# 备份软件包列表
dpkg --get-selections > "$BACKUP_DIR/installed-packages.txt"

# 清理30天前的备份
find /root/ -name "weekly-backup-*" -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null || true

echo "[$(date)] 每周备份完成: $BACKUP_DIR" >> /var/log/system-backup.log
EOF

        chmod +x /etc/cron.weekly/system-backup
        log_message "设置每周自动备份"
        print_message "$GREEN" "每周自动备份已设置"
    fi

    # 显示现有备份
    print_message "$YELLOW" "现有备份目录:"
    ls -la /root/ | grep -E "(backup|security-backup)" || echo "未找到备份目录"
}

# 测试和修复fail2ban配置
test_and_fix_fail2ban_config() {
    local ssh_port=$1
    local config_level=${2:-"full"}  # full, basic, minimal

    case $config_level in
        "full")
            cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[ufw-block]
enabled = false
filter = ufw-block
logpath = /var/log/syslog
maxretry = 5
findtime = 600
bantime = 86400
action = ufw
EOF
            ;;
        "basic")
            cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
            ;;
        "minimal")
            cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
EOF
            ;;
    esac

    # 测试配置
    if fail2ban-client -t &>/dev/null; then
        print_message "$GREEN" "✓ $config_level 配置验证成功"
        return 0
    else
        print_message "$RED" "✗ $config_level 配置验证失败"
        return 1
    fi
}

# 安装acme.sh并申请证书
install_acme_and_request_cert() {
    local domain=$1
    local email=$2
    local cf_token=$3
    local cf_zone_id=$4
    local cf_account_id=$5
    local key_type=${6:-"ec-256"}

    print_message "$YELLOW" "开始申请TLS证书（密钥类型: $key_type）..."

    # 安装acme.sh
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        print_message "$YELLOW" "安装acme.sh..."
        curl https://get.acme.sh | sh -s email="$email"
        apt install socat -y
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
        source ~/.bashrc
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    else
        print_message "$GREEN" "acme.sh 已安装"
    fi

    # 设置环境变量
    export CF_Token="$cf_token"
    export CF_Zone_ID="$cf_zone_id"
    export CF_Account_ID="$cf_account_id"

    # 获取非root用户
    local username=$(getent passwd 1001 | cut -d: -f1)
    if [[ -z "$username" ]]; then
        username="vpsuser"
        print_message "$YELLOW" "未找到UID 1001的用户，使用默认用户名: $username"
    fi

    print_message "$YELLOW" "申请证书: $domain（密钥类型: $key_type）"

    # 检查证书是否已经存在且有效
    if [[ -f "/home/$username/$domain.cer" ]] && [[ -f "/home/$username/$domain.key" ]]; then
        if openssl x509 -in "/home/$username/$domain.cer" -noout -checkend 2592000 > /dev/null 2>&1; then
            print_message "$GREEN" "证书已存在且有效期超过30天，跳过申请"
            return 0
        else
            print_message "$YELLOW" "证书已存在但即将过期或无效，重新申请"
        fi
    fi

    # 申请证书
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$domain" -d "*.$domain" \
        --keylength "$key_type" \
        --key-file "/home/$username/$domain.key" \
        --fullchain-file "/home/$username/$domain.cer" \
        --reloadcmd 'bash -c "nginx -s reload 2>/dev/null || true; x-ui restart 2>/dev/null || true"'

    if [[ $? -eq 0 ]]; then
        # 修改权限
        print_message "$YELLOW" "修改证书权限..."
        chmod 644 "/home/$username/$domain.key"
        chmod 644 "/home/$username/$domain.cer"

        # 创建证书目录并复制
        mkdir -p "/root/cert/$domain"
        cp "/home/$username/$domain.cer" "/root/cert/$domain/fullchain.pem"
        cp "/home/$username/$domain.key" "/root/cert/$domain/privkey.pem"

        # 验证证书
        print_message "$YELLOW" "验证证书..."
        if openssl x509 -in "/home/$username/$domain.cer" -noout -text > /dev/null 2>&1; then
            print_message "$GREEN" "证书申请成功"

            # 显示证书信息
            print_message "$YELLOW" "证书有效期："
            openssl x509 -in "/home/$username/$domain.cer" -noout -dates

            print_message "$YELLOW" "证书包含的域名："
            openssl x509 -in "/home/$username/$domain.cer" -noout -text | grep -A1 "Subject Alternative Name" || echo "  $domain, *.$domain"

            log_message "证书申请成功: $domain"
        else
            print_message "$RED" "证书文件可能有问题，请检查"
            return 1
        fi
    else
        print_message "$RED" "证书申请失败"
        return 1
    fi
}

# 证书管理 (Cloudflare)
manage_certificates() {
    print_message "$BLUE" "=== 证书管理 (Cloudflare) ==="

    while true; do
        echo
        print_message "$YELLOW" "证书管理选项:"
        echo "1. 申请新证书"
        echo "2. 查看现有证书"
        echo "3. 续期证书"
        echo "4. 删除证书"
        echo "0. 返回主菜单"
        echo

        read -p "请选择操作 (0-4): " cert_choice

        case $cert_choice in
            1)
                print_message "$YELLOW" "申请新证书"
                read -p "请输入域名: " domain
                read -p "请输入邮箱: " email
                read -p "请输入Cloudflare API Token: " cf_token
                read -p "请输入Cloudflare Zone ID: " cf_zone_id
                read -p "请输入Cloudflare Account ID: " cf_account_id

                if [[ -n "$domain" && -n "$email" && -n "$cf_token" && -n "$cf_zone_id" && -n "$cf_account_id" ]]; then
                    install_acme_and_request_cert "$domain" "$email" "$cf_token" "$cf_zone_id" "$cf_account_id"
                else
                    print_message "$RED" "所有参数都是必需的"
                fi
                ;;
            2)
                print_message "$YELLOW" "查看现有证书:"
                if command -v ~/.acme.sh/acme.sh &> /dev/null; then
                    ~/.acme.sh/acme.sh --list
                else
                    print_message "$YELLOW" "acme.sh 未安装"
                fi
                ;;
            3)
                print_message "$YELLOW" "续期证书"
                if command -v ~/.acme.sh/acme.sh &> /dev/null; then
                    ~/.acme.sh/acme.sh --renew-all
                else
                    print_message "$RED" "acme.sh 未安装"
                fi
                ;;
            4)
                print_message "$YELLOW" "删除证书"
                read -p "请输入要删除的域名: " domain
                if [[ -n "$domain" ]] && command -v ~/.acme.sh/acme.sh &> /dev/null; then
                    ~/.acme.sh/acme.sh --remove -d "$domain"
                else
                    print_message "$RED" "域名不能为空或acme.sh未安装"
                fi
                ;;
            0)
                break
                ;;
            *)
                print_message "$RED" "无效选择"
                ;;
        esac

        echo
        read -p "按回车键继续..." -r
    done
}

# Hysteria2服务安装
install_hysteria2() {
    print_message "$BLUE" "=== Hysteria2服务安装 ==="

    read -p "请输入域名: " domain
    read -p "请输入端口 (默认8443): " port
    read -p "请输入用户名: " username
    read -p "请输入密码: " password

    port=${port:-8443}

    if [[ -z "$domain" || -z "$username" || -z "$password" ]]; then
        print_message "$RED" "域名、用户名和密码都是必需的"
        return 1
    fi

    print_message "$YELLOW" "开始安装Hysteria2服务..."

    # 安装Hysteria2
    print_message "$YELLOW" "安装Hysteria2..."
    bash <(curl -fsSL https://get.hy2.sh/)

    # 获取非root用户
    local vps_username=$(getent passwd 1001 | cut -d: -f1)
    if [[ -z "$vps_username" ]]; then
        vps_username="vpsuser"
    fi

    # 配置Hysteria2
    print_message "$YELLOW" "配置Hysteria2..."
    cat > /etc/hysteria/config.yaml << EOF
listen: :$port

tls:
  cert: /home/$vps_username/$domain.cer
  key: /home/$vps_username/$domain.key

auth:
  type: userpass
  userpass:
    $username: $password

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true
  listenHTTP: :80
  listenHTTPS: :$port

bandwidth:
  up: 20 mbps
  down: 50 mbps
EOF

    # 开放端口
    print_message "$YELLOW" "配置防火墙..."
    ufw allow $port

    # 启动服务
    print_message "$YELLOW" "启动Hysteria2服务..."
    systemctl enable hysteria-server.service --now

    if systemctl is-active --quiet hysteria-server; then
        print_message "$GREEN" "Hysteria2服务安装完成"
        print_message "$YELLOW" "配置信息:"
        echo "- 域名: $domain"
        echo "- 端口: $port"
        echo "- 用户名: $username"
        echo "- 密码: $password"
        log_message "Hysteria2服务安装完成: $domain:$port"
    else
        print_message "$RED" "Hysteria2服务启动失败"
        systemctl status hysteria-server --no-pager -l | head -10
    fi
}

# X-UI面板安装
install_xui() {
    print_message "$BLUE" "=== X-UI面板安装 ==="

    if confirm_action "是否安装3X-UI面板?"; then
        print_message "$YELLOW" "开始安装3X-UI面板..."

        # 安装3X-UI
        print_message "$YELLOW" "下载并安装3X-UI..."
        bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)

        # 配置提示
        print_message "$GREEN" "3X-UI面板安装完成"
        print_message "$YELLOW" "配置提示:"
        echo "1. 请手动配置3X-UI面板"
        echo "2. 记录访问端口用于nginx反向代理"
        echo "3. 配置SSL证书路径: /root/cert/域名/fullchain.pem 和 /root/cert/域名/privkey.pem"
        echo "4. 或者使用3X-UI备份恢复功能"

        if confirm_action "是否现在配置3X-UI?"; then
            x-ui
        fi

        log_message "3X-UI面板安装完成"
    fi
}

# Sub-Store服务安装
install_substore() {
    print_message "$BLUE" "=== Sub-Store服务安装 ==="

    read -p "请输入API密钥: " api_key

    if [[ -z "$api_key" ]]; then
        print_message "$RED" "API密钥是必需的"
        return 1
    fi

    print_message "$YELLOW" "开始安装Sub-Store服务..."

    # 安装依赖
    print_message "$YELLOW" "安装依赖..."
    apt update -y && apt install unzip curl wget git -y

    # 安装FNM
    if [[ ! -f ~/.local/share/fnm/fnm ]]; then
        print_message "$YELLOW" "安装FNM..."
        curl -fsSL https://fnm.vercel.app/install | bash
        source ~/.bashrc
    fi

    # 安装Node
    print_message "$YELLOW" "安装Node..."
    ~/.local/share/fnm/fnm install v20.18.0

    # 安装PNPM
    if ! command -v pnpm &> /dev/null; then
        print_message "$YELLOW" "安装PNPM..."
        curl -fsSL https://get.pnpm.io/install.sh | sh -
        source ~/.bashrc
    fi

    # 创建目录
    print_message "$YELLOW" "创建目录..."
    mkdir -p /root/sub-store
    cd /root/sub-store

    # 下载Sub-Store
    print_message "$YELLOW" "下载Sub-Store..."
    curl -fsSL https://github.com/sub-store-org/Sub-Store/releases/latest/download/sub-store.bundle.js -o sub-store.bundle.js
    curl -fsSL https://github.com/sub-store-org/Sub-Store-Front-End/releases/latest/download/dist.zip -o dist.zip
    unzip -o dist.zip && mv dist frontend && rm dist.zip

    # 创建服务
    print_message "$YELLOW" "创建服务..."
    cat > /etc/systemd/system/sub-store.service << EOF
[Unit]
Description=Sub-Store
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=32767
Type=simple
Environment="SUB_STORE_FRONTEND_BACKEND_PATH=/$api_key"
Environment="SUB_STORE_BACKEND_CRON=0 0 * * *"
Environment="SUB_STORE_FRONTEND_PATH=/root/sub-store/frontend"
Environment="SUB_STORE_FRONTEND_HOST=0.0.0.0"
Environment="SUB_STORE_FRONTEND_PORT=3001"
Environment="SUB_STORE_DATA_BASE_PATH=/root/sub-store"
Environment="SUB_STORE_BACKEND_API_HOST=127.0.0.1"
Environment="SUB_STORE_BACKEND_API_PORT=3000"
ExecStart=/root/.local/share/fnm/fnm exec --using v20.18.0 node /root/sub-store/sub-store.bundle.js
User=root
Group=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c ulimit -n 51200
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # 启动服务
    print_message "$YELLOW" "启动服务..."
    systemctl daemon-reload
    systemctl enable sub-store.service --now

    if systemctl is-active --quiet sub-store; then
        print_message "$GREEN" "Sub-Store服务安装完成"
        print_message "$YELLOW" "访问信息:"
        echo "- 前端端口: 3001"
        echo "- 后端端口: 3000"
        echo "- API路径: /$api_key"
        log_message "Sub-Store服务安装完成"
    else
        print_message "$RED" "Sub-Store服务启动失败"
        systemctl status sub-store --no-pager -l | head -10
    fi
}

# Nginx分流配置
configure_nginx() {
    print_message "$BLUE" "=== Nginx分流配置 ==="

    read -p "请输入主域名: " domain
    read -p "请输入X-UI域名: " xui_domain
    read -p "请输入Sub-Store域名: " substore_domain
    read -p "请输入X-UI访问端口: " port_xui

    if [[ -z "$domain" || -z "$xui_domain" || -z "$substore_domain" || -z "$port_xui" ]]; then
        print_message "$RED" "所有参数都是必需的"
        return 1
    fi

    print_message "$YELLOW" "开始配置Nginx分流..."

    # 安装Nginx
    if ! command -v nginx &> /dev/null; then
        print_message "$YELLOW" "安装Nginx..."
        apt install libnginx-mod-stream nginx -y
    else
        print_message "$GREEN" "Nginx已安装"
    fi

    # 获取非root用户
    local username=$(getent passwd 1001 | cut -d: -f1)
    if [[ -z "$username" ]]; then
        username="vpsuser"
    fi

    # 修改主配置文件
    if ! grep -q "include /etc/nginx/vps.conf;" /etc/nginx/nginx.conf; then
        print_message "$YELLOW" "添加vps.conf包含语句到nginx.conf"
        echo "    include /etc/nginx/vps.conf;" >> /etc/nginx/nginx.conf
    else
        print_message "$GREEN" "vps.conf包含语句已存在"
    fi

    # 创建分流配置
    print_message "$YELLOW" "创建分流配置..."
    cat > /etc/nginx/vps.conf << EOF
# /etc/nginx/vps.conf

stream {
    # 定义一个映射，将 SNI 中的服务器名映射到后端标识符
    map \$ssl_preread_server_name \$backend {
        hostnames;
        $substore_domain sub;
        $xui_domain xui;
        default hysteria;  # 默认后端
    }

    # 定义各个后端的上游服务器
    upstream sub {
        server 127.0.0.1:8444;  # $substore_domain 对应的后端
    }

    upstream xui {
        server 127.0.0.1:$port_xui;  # $xui_domain 对应的后端
    }

    upstream hysteria {
        server 127.0.0.1:8443;  # 默认后端
    }

    # 定义一个服务器块，监听指定端口并根据 SNI 分发流量
    server {
        listen 443;
        listen [::]:443;
        proxy_pass \${backend};
        ssl_preread on;
    }
}
EOF

    # 创建Sub-Store的nginx配置
    print_message "$YELLOW" "创建Sub-Store nginx配置..."
    cat > /etc/nginx/sites-available/sub-store << EOF
server {
    listen 8444 ssl http2;
    server_name $substore_domain;

    ssl_certificate /home/$username/$domain.cer;
    ssl_certificate_key /home/$username/$domain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /$api_key {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    # 启用站点
    ln -sf /etc/nginx/sites-available/sub-store /etc/nginx/sites-enabled/

    # 测试配置
    print_message "$YELLOW" "测试Nginx配置..."
    if nginx -t; then
        print_message "$GREEN" "Nginx配置测试通过"

        # 重启Nginx
        systemctl restart nginx
        if systemctl is-active --quiet nginx; then
            print_message "$GREEN" "Nginx分流配置完成"
            print_message "$YELLOW" "配置信息:"
            echo "- 主域名: $domain"
            echo "- X-UI域名: $xui_domain (端口: $port_xui)"
            echo "- Sub-Store域名: $substore_domain"
            echo "- 监听端口: 443"
            log_message "Nginx分流配置完成"
        else
            print_message "$RED" "Nginx启动失败"
            systemctl status nginx --no-pager -l | head -10
        fi
    else
        print_message "$RED" "Nginx配置测试失败"
        nginx -t
    fi
}

# 增强的fail2ban状态显示
show_fail2ban_status_enhanced() {
    print_message "$BLUE" "┌─────────────────────────────────────────────────────────────────────────────┐"
    print_message "$BLUE" "│                           fail2ban 状态概览                                │"
    print_message "$BLUE" "└─────────────────────────────────────────────────────────────────────────────┘"
    echo

    # 服务状态检查
    local service_status="🔴 已停止"
    local service_color="$RED"
    local health_score=0

    if systemctl is-active --quiet fail2ban; then
        service_status="🟢 运行中"
        service_color="$GREEN"
        health_score=30
    fi

    # Socket状态检查
    local socket_status="❌ 不可用"
    if [[ -S "/var/run/fail2ban/fail2ban.sock" ]]; then
        socket_status="✅ 正常"
        ((health_score += 20))
    fi

    # 连接状态检查
    local connection_status="❌ 无法连接"
    local total_banned=0
    local active_jails=0
    local today_bans=0

    if fail2ban-client status &>/dev/null; then
        connection_status="✅ 连接正常"
        ((health_score += 30))

        # 获取统计信息
        local jail_list=$(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' ' ')
        if [[ -n "$jail_list" ]]; then
            for jail in $jail_list; do
                jail=$(echo $jail | xargs)
                if [[ -n "$jail" ]]; then
                    ((active_jails++))
                    local banned_count=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned:" | awk '{print $3}' | grep -o '[0-9]*' || echo "0")
                    banned_count=${banned_count:-0}
                    total_banned=$((total_banned + banned_count))
                fi
            done
            ((health_score += 20))
        fi

        # 今日封禁统计
        today_bans=$(grep "$(date '+%Y-%m-%d')" /var/log/fail2ban.log 2>/dev/null | grep "Ban" | wc -l)
    fi

    # 健康度评估
    local health_indicator="🔴 异常"
    local health_color="$RED"
    if [[ $health_score -ge 80 ]]; then
        health_indicator="🟢 健康"
        health_color="$GREEN"
    elif [[ $health_score -ge 50 ]]; then
        health_indicator="🟡 警告"
        health_color="$YELLOW"
    fi

    # 状态概览显示
    print_message "$CYAN" "📊 服务状态概览"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"
    printf "│ 服务状态: %-20s │ Socket状态: %-20s │\n" "$service_status" "$socket_status"
    printf "│ 连接状态: %-20s │ 健康度: %-25s │\n" "$connection_status" "$health_indicator ($health_score/100)"
    echo "├─────────────────────────────────────────────────────────────────────────────┤"
    printf "│ 活动Jail: %-8s │ 当前封禁IP: %-8s │ 今日封禁: %-8s │\n" "$active_jails" "$total_banned" "$today_bans"
    echo "└─────────────────────────────────────────────────────────────────────────────┘"
    echo

    # 如果服务未运行，提供启动选项
    if ! systemctl is-active --quiet fail2ban; then
        print_message "$YELLOW" "⚠️  fail2ban服务未运行"
        echo "服务状态详情:"
        systemctl status fail2ban --no-pager -l | head -5
        echo
        if confirm_action "是否尝试启动fail2ban服务?"; then
            print_message "$YELLOW" "正在启动fail2ban服务..."
            if systemctl start fail2ban; then
                print_message "$GREEN" "✅ 服务启动成功"
                sleep 3
                # 递归调用显示更新后的状态
                show_fail2ban_status_enhanced
                return
            else
                print_message "$RED" "❌ 服务启动失败"
                print_message "$YELLOW" "错误日志:"
                journalctl -u fail2ban --no-pager -n 5
            fi
        fi
        return
    fi

    # 如果无法连接，等待socket
    if ! fail2ban-client status &>/dev/null; then
        print_message "$YELLOW" "⏳ 等待fail2ban服务完全启动..."
        if [[ ! -S "/var/run/fail2ban/fail2ban.sock" ]]; then
            wait_for_fail2ban_socket 30
        fi
        sleep 2
    fi

    # Jail状态详细显示
    if fail2ban-client status &>/dev/null; then
        print_message "$CYAN" "📋 Jail状态详情"
        echo "┌─────────────────┬──────────┬──────────┬──────────┬─────────────────────┐"
        echo "│ Jail名称        │ 状态     │ 封禁IP   │ 失败次数 │ 最后活动            │"
        echo "├─────────────────┼──────────┼──────────┼──────────┼─────────────────────┤"

        local jail_list=$(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' ' ')
        if [[ -n "$jail_list" ]]; then
            for jail in $jail_list; do
                jail=$(echo $jail | xargs)
                if [[ -n "$jail" ]]; then
                    local jail_info=$(fail2ban-client status "$jail" 2>/dev/null)
                    local banned_count=$(echo "$jail_info" | grep "Currently banned:" | awk '{print $3}' | grep -o '[0-9]*' || echo "0")
                    local failed_count=$(echo "$jail_info" | grep "Currently failed:" | awk '{print $3}' | grep -o '[0-9]*' || echo "0")

                    # 确保是数字
                    banned_count=${banned_count:-0}
                    failed_count=${failed_count:-0}

                    local status_icon="🟢"

                    # 根据状态设置图标
                    if [[ $banned_count -gt 0 ]] 2>/dev/null; then
                        status_icon="🟡"
                    fi
                    if [[ $failed_count -gt 10 ]] 2>/dev/null; then
                        status_icon="🔴"
                    fi

                    # 获取最后活动时间
                    local last_activity=$(grep "$jail" /var/log/fail2ban.log 2>/dev/null | tail -1 | awk '{print $1, $2}' || echo "无记录")

                    printf "│ %-15s │ %-8s │ %-8s │ %-8s │ %-19s │\n" \
                        "$jail" "$status_icon 活动" "$banned_count" "$failed_count" "$last_activity"
                fi
            done
        else
            printf "│ %-73s │\n" "没有活动的jail"
        fi
        echo "└─────────────────┴──────────┴──────────┴──────────┴─────────────────────┘"
        echo
    fi

    # 最近活动摘要
    print_message "$CYAN" "📝 最近活动摘要 (最近5条)"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"
    if [[ -f "/var/log/fail2ban.log" ]]; then
        local recent_activities=$(tail -5 /var/log/fail2ban.log 2>/dev/null | while read line; do
            if echo "$line" | grep -q "Ban"; then
                echo "🚫 $(echo $line | awk '{print $1, $2, $6, $7}')"
            elif echo "$line" | grep -q "Unban"; then
                echo "✅ $(echo $line | awk '{print $1, $2, $6, $7}')"
            elif echo "$line" | grep -q "Found"; then
                echo "⚠️  $(echo $line | awk '{print $1, $2, $6, $7, $8}')"
            fi
        done)

        if [[ -n "$recent_activities" ]]; then
            echo "$recent_activities" | while read activity; do
                printf "│ %-75s │\n" "$activity"
            done
        else
            printf "│ %-75s │\n" "暂无最近活动记录"
        fi
    else
        printf "│ %-75s │\n" "日志文件不存在"
    fi
    echo "└─────────────────────────────────────────────────────────────────────────────┘"
    echo

    # 快速操作提示
    print_message "$CYAN" "🔧 快速操作"
    echo "• 查看被封禁IP: 选择选项 2"
    echo "• 解封IP地址: 选择选项 3"
    echo "• 查看详细日志: 选择选项 4"
    echo "• 重启服务: 选择选项 5"
    echo "• 诊断问题: 选择选项 7"
}

# fail2ban管理
manage_fail2ban() {
    print_message "$BLUE" "=== fail2ban管理 ==="

    if ! command -v fail2ban-client &> /dev/null; then
        print_message "$RED" "fail2ban未安装，请先安装fail2ban (选项6)"
        return 1
    fi

    while true; do
        echo
        print_message "$YELLOW" "fail2ban管理选项:"
        echo "1. 查看fail2ban状态"
        echo "2. 查看被封禁的IP"
        echo "3. 解封IP地址"
        echo "4. 查看日志"
        echo "5. 重启fail2ban服务"
        echo "6. 测试配置"
        echo "7. 诊断和修复问题"
        echo "0. 返回主菜单"
        echo

        read -p "请选择操作 (0-7): " f2b_choice

        case $f2b_choice in
            1)
                show_fail2ban_status_enhanced
                ;;
            2)
                print_message "$YELLOW" "当前被封禁的IP地址:"

                # 检查fail2ban服务状态
                if ! systemctl is-active --quiet fail2ban; then
                    print_message "$RED" "fail2ban服务未运行，无法查看封禁IP"
                    continue
                fi

                # 检查是否能连接到fail2ban
                if ! fail2ban-client status &>/dev/null; then
                    print_message "$RED" "无法连接到fail2ban服务"
                    continue
                fi

                # 获取封禁IP列表
                banned_found=false
                for jail in $(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' ' '); do
                    jail=$(echo $jail | xargs)
                    if [[ -n "$jail" ]]; then
                        banned_ips=$(fail2ban-client status "$jail" | grep "Banned IP list:" | cut -d: -f2)
                        if [[ -n "$banned_ips" && "$banned_ips" != " " ]]; then
                            echo "$jail: $banned_ips"
                            banned_found=true
                        fi
                    fi
                done

                if [[ "$banned_found" == false ]]; then
                    print_message "$GREEN" "当前没有被封禁的IP地址"
                fi
                ;;
            3)
                # 检查fail2ban服务状态
                if ! systemctl is-active --quiet fail2ban; then
                    print_message "$RED" "fail2ban服务未运行，无法解封IP"
                    continue
                fi

                # 检查是否能连接到fail2ban
                if ! fail2ban-client status &>/dev/null; then
                    print_message "$RED" "无法连接到fail2ban服务"
                    continue
                fi

                read -p "请输入要解封的IP地址: " unban_ip
                if [[ -n "$unban_ip" ]]; then
                    print_message "$YELLOW" "可用的jail:"
                    if fail2ban-client status | grep "Jail list:" | cut -d: -f2; then
                        read -p "请输入jail名称 (如sshd): " jail_name
                        if [[ -n "$jail_name" ]]; then
                            if fail2ban-client set "$jail_name" unbanip "$unban_ip"; then
                                print_message "$GREEN" "IP $unban_ip 已从 $jail_name 解封"
                                log_message "手动解封IP: $unban_ip from $jail_name"
                            else
                                print_message "$RED" "解封失败，请检查IP和jail名称"
                            fi
                        fi
                    else
                        print_message "$RED" "无法获取jail列表"
                    fi
                fi
                ;;
            4)
                print_message "$YELLOW" "fail2ban日志 (最近20行):"
                tail -20 /var/log/fail2ban.log
                echo
                print_message "$YELLOW" "SSH失败登录 (最近10行):"
                grep "Failed password" /var/log/auth.log | tail -10
                ;;
            5)
                if confirm_action "是否重启fail2ban服务?"; then
                    print_message "$YELLOW" "正在重启fail2ban服务..."
                    systemctl restart fail2ban

                    # 等待服务启动
                    print_message "$YELLOW" "等待服务启动..."
                    for i in {1..30}; do
                        if systemctl is-active --quiet fail2ban; then
                            print_message "$GREEN" "✓ 服务已启动"
                            break
                        fi
                        sleep 1
                        echo -n "."
                    done
                    echo

                    # 等待socket文件创建
                    if systemctl is-active --quiet fail2ban; then
                        wait_for_fail2ban_socket 30

                        # 尝试获取状态
                        if fail2ban-client status &>/dev/null; then
                            print_message "$GREEN" "fail2ban服务已重启并正常运行"
                            fail2ban-client status
                        else
                            print_message "$YELLOW" "服务已重启，但socket可能仍在初始化中"
                            print_message "$YELLOW" "请稍后使用 'fail2ban-client status' 检查状态"
                        fi
                    else
                        print_message "$RED" "服务重启失败"
                        systemctl status fail2ban --no-pager -l | head -10
                    fi
                fi
                ;;
            6)
                print_message "$YELLOW" "测试fail2ban配置:"

                # 检查配置文件是否存在
                if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
                    print_message "$RED" "配置文件 /etc/fail2ban/jail.local 不存在"
                    continue
                fi

                # 测试配置文件语法
                if fail2ban-client -t; then
                    print_message "$GREEN" "✓ 配置文件语法正确"

                    # 显示配置摘要
                    print_message "$YELLOW" "配置摘要:"
                    echo "主配置文件: /etc/fail2ban/jail.local"
                    if grep -q "^\[sshd\]" /etc/fail2ban/jail.local; then
                        ssh_enabled=$(grep -A5 "^\[sshd\]" /etc/fail2ban/jail.local | grep "enabled" | cut -d= -f2 | xargs)
                        ssh_port=$(grep -A10 "^\[sshd\]" /etc/fail2ban/jail.local | grep "port" | cut -d= -f2 | xargs)
                        echo "- SSH保护: $ssh_enabled (端口: $ssh_port)"
                    fi
                    if grep -q "^\[ufw-block\]" /etc/fail2ban/jail.local; then
                        ufw_enabled=$(grep -A5 "^\[ufw-block\]" /etc/fail2ban/jail.local | grep "enabled" | cut -d= -f2 | xargs)
                        echo "- UFW阻止监控: $ufw_enabled"
                    fi
                else
                    print_message "$RED" "✗ 配置文件存在错误"
                    print_message "$YELLOW" "请检查配置文件语法"
                fi
                ;;
            7)
                print_message "$YELLOW" "fail2ban问题诊断和修复:"
                echo

                # 1. 检查服务状态
                print_message "$BLUE" "1. 检查服务状态"
                if systemctl is-active --quiet fail2ban; then
                    print_message "$GREEN" "✓ fail2ban服务正在运行"
                else
                    print_message "$RED" "✗ fail2ban服务未运行"
                    print_message "$YELLOW" "服务状态详情:"
                    systemctl status fail2ban --no-pager -l | head -15
                fi
                echo

                # 2. 检查socket文件
                print_message "$BLUE" "2. 检查socket文件"
                if [[ -S "/var/run/fail2ban/fail2ban.sock" ]]; then
                    print_message "$GREEN" "✓ Socket文件存在: /var/run/fail2ban/fail2ban.sock"
                    ls -la /var/run/fail2ban/fail2ban.sock
                else
                    print_message "$RED" "✗ Socket文件不存在: /var/run/fail2ban/fail2ban.sock"
                    if [[ -e "/var/run/fail2ban/fail2ban.sock" ]]; then
                        print_message "$YELLOW" "文件存在但不是socket类型:"
                        ls -la /var/run/fail2ban/fail2ban.sock
                    fi
                fi
                echo

                # 3. 检查配置文件
                print_message "$BLUE" "3. 检查配置文件"
                if [[ -f "/etc/fail2ban/jail.local" ]]; then
                    print_message "$GREEN" "✓ 配置文件存在: /etc/fail2ban/jail.local"
                    if fail2ban-client -t &>/dev/null; then
                        print_message "$GREEN" "✓ 配置文件语法正确"
                    else
                        print_message "$RED" "✗ 配置文件语法错误"
                        print_message "$YELLOW" "语法检查结果:"
                        fail2ban-client -t
                    fi
                else
                    print_message "$RED" "✗ 配置文件不存在: /etc/fail2ban/jail.local"
                fi
                echo

                # 4. 检查日志文件
                print_message "$BLUE" "4. 检查日志文件"
                if [[ -f "/var/log/fail2ban.log" ]]; then
                    print_message "$GREEN" "✓ 日志文件存在: /var/log/fail2ban.log"
                    print_message "$YELLOW" "最近的错误信息:"
                    grep -i "error\|failed\|exception" /var/log/fail2ban.log | tail -5
                else
                    print_message "$YELLOW" "⚠ 日志文件不存在: /var/log/fail2ban.log"
                fi
                echo

                # 5. 检查系统日志
                print_message "$BLUE" "5. 检查系统日志中的fail2ban信息"
                print_message "$YELLOW" "最近的fail2ban系统日志:"
                journalctl -u fail2ban --since "10 minutes ago" --no-pager -n 10
                echo

                # 6. 提供修复选项
                print_message "$BLUE" "6. 修复选项"
                if ! systemctl is-active --quiet fail2ban; then
                    if confirm_action "是否尝试启动fail2ban服务?"; then
                        print_message "$YELLOW" "正在启动fail2ban服务..."
                        systemctl start fail2ban
                        sleep 5
                        if systemctl is-active --quiet fail2ban; then
                            print_message "$GREEN" "✓ 服务启动成功"
                        else
                            print_message "$RED" "✗ 服务启动失败"
                            print_message "$YELLOW" "错误详情:"
                            journalctl -u fail2ban --no-pager -n 10
                        fi
                    fi
                fi

                if [[ ! -S "/var/run/fail2ban/fail2ban.sock" ]] && systemctl is-active --quiet fail2ban; then
                    if confirm_action "服务运行但socket文件缺失，是否重启服务?"; then
                        print_message "$YELLOW" "正在重启fail2ban服务..."
                        systemctl restart fail2ban
                        sleep 5
                        if [[ -S "/var/run/fail2ban/fail2ban.sock" ]]; then
                            print_message "$GREEN" "✓ Socket文件已创建"
                        else
                            print_message "$RED" "✗ Socket文件仍然缺失"
                        fi
                    fi
                fi

                if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
                    if confirm_action "配置文件缺失，是否重新创建?"; then
                        print_message "$YELLOW" "正在重新创建fail2ban配置..."
                        # 调用安装函数重新创建配置
                        install_fail2ban
                    fi
                fi
                ;;
            0)
                break
                ;;
            *)
                print_message "$RED" "无效选择"
                ;;
        esac

        echo
        read -p "按回车键继续..." -r
    done
}

# 安全配置验证
security_validation() {
    print_message "$BLUE" "=== 安全配置验证 ==="

    local validation_passed=true

    # SSH配置验证
    print_message "$YELLOW" "1. SSH配置验证"

    # 使用sshd -T检查有效SSH配置
    print_message "$YELLOW" "使用sshd -T检查有效配置..."

    # 检查SSH端口
    ssh_port=$(sshd -T 2>/dev/null | grep -i "^port" | awk '{print $2}')
    if [[ -n "$ssh_port" && "$ssh_port" != "22" ]]; then
        print_message "$GREEN" "✓ SSH端口已修改: $ssh_port"
    else
        print_message "$YELLOW" "⚠ SSH仍使用默认端口22"
    fi

    # 检查root登录配置
    root_login=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}')
    if [[ "$root_login" == "no" || "$root_login" == "prohibit-password" || "$root_login" == "without-password" ]]; then
        print_message "$GREEN" "✓ Root登录已限制: $root_login"
    else
        print_message "$RED" "✗ Root登录未限制: $root_login"
        validation_passed=false
    fi

    # 检查密码认证
    password_auth=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}')
    if [[ "$password_auth" == "no" ]]; then
        print_message "$GREEN" "✓ 密码认证已禁用"
    else
        print_message "$YELLOW" "⚠ 密码认证仍启用: $password_auth"
    fi

    # 检查密钥认证
    pubkey_auth=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication" | awk '{print $2}')
    if [[ "$pubkey_auth" == "yes" ]]; then
        print_message "$GREEN" "✓ 密钥认证已启用"
    else
        print_message "$YELLOW" "⚠ 密钥认证未启用: $pubkey_auth"
    fi

    # 检查SSH服务状态
    if systemctl is-active --quiet sshd; then
        print_message "$GREEN" "✓ SSH服务运行正常"
    else
        print_message "$RED" "✗ SSH服务未运行"
        validation_passed=false
    fi

    echo

    # 防火墙配置验证
    print_message "$YELLOW" "2. 防火墙配置验证"

    if command -v ufw &> /dev/null; then
        ufw_status=$(ufw status | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            print_message "$GREEN" "✓ UFW防火墙已启用"

            # 检查SSH端口是否开放
            if ufw status | grep -q "$ssh_port"; then
                print_message "$GREEN" "✓ SSH端口已在防火墙中开放"
            else
                print_message "$RED" "✗ SSH端口未在防火墙中开放"
                validation_passed=false
            fi
        else
            print_message "$YELLOW" "⚠ UFW防火墙未启用"
        fi
    else
        print_message "$YELLOW" "⚠ UFW未安装"
    fi

    echo

    # fail2ban验证
    print_message "$YELLOW" "3. fail2ban配置验证"

    if command -v fail2ban-client &> /dev/null; then
        if systemctl is-active --quiet fail2ban; then
            print_message "$GREEN" "✓ fail2ban服务运行正常"

            # 检查jail状态
            active_jails=$(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' ' ')
            if [[ -n "$active_jails" ]]; then
                print_message "$GREEN" "✓ 活动的jail: $active_jails"
            else
                print_message "$YELLOW" "⚠ 没有活动的jail"
            fi
        else
            print_message "$RED" "✗ fail2ban服务未运行"
            validation_passed=false
        fi
    else
        print_message "$YELLOW" "⚠ fail2ban未安装"
    fi

    echo

    # 用户配置验证
    print_message "$YELLOW" "4. 用户配置验证"

    # 检查sudo用户
    sudo_users=$(grep "^sudo:" /etc/group | cut -d: -f4)
    if [[ -n "$sudo_users" ]]; then
        print_message "$GREEN" "✓ Sudo用户: $sudo_users"
    else
        print_message "$YELLOW" "⚠ 没有配置sudo用户"
    fi

    # 检查空密码账户
    empty_password_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$empty_password_users" ]]; then
        print_message "$GREEN" "✓ 没有空密码账户"
    else
        print_message "$RED" "✗ 发现空密码账户: $empty_password_users"
        validation_passed=false
    fi

    echo

    # 系统更新验证
    print_message "$YELLOW" "5. 系统更新验证"

    # 检查可更新的软件包
    upgradable=$(apt list --upgradable 2>/dev/null | wc -l)
    if [[ "$upgradable" -le 1 ]]; then
        print_message "$GREEN" "✓ 系统已是最新版本"
    else
        print_message "$YELLOW" "⚠ 有 $((upgradable-1)) 个软件包可更新"
    fi

    echo

    # 总结
    if [[ "$validation_passed" == true ]]; then
        print_message "$GREEN" "🎉 安全配置验证通过！"
        log_message "安全配置验证通过"
    else
        print_message "$RED" "⚠️  发现安全配置问题，请检查上述标记为 ✗ 的项目"
        log_message "安全配置验证发现问题"
    fi

    # 提供修复建议
    if [[ "$validation_passed" != true ]]; then
        echo
        print_message "$YELLOW" "修复建议:"
        echo "1. 运行相应的安全加固模块"
        echo "2. 检查服务状态: systemctl status 服务名"
        echo "3. 查看日志: journalctl -u 服务名"
        echo "4. 重新运行验证确认修复"
    fi
}

# 配置vless+reality代理
install_vless_reality() {
    print_message "$BLUE" "=== 配置vless+reality代理 ==="

    # 检查系统要求
    if ! command -v curl &> /dev/null; then
        print_message "$YELLOW" "安装curl..."
        apt update && apt install -y curl
    fi

    # 检查是否已安装
    if [[ -f "/usr/local/bin/xray" ]] || [[ -f "/etc/systemd/system/xray.service" ]]; then
        print_message "$YELLOW" "检测到已安装的代理服务"
        if ! confirm_action "是否重新配置?"; then
            return 0
        fi
    fi

    print_message "$YELLOW" "vless+reality配置需要以下信息:"
    echo "1. 监听端口 (建议: 443)"
    echo "2. 伪装域名 (如: www.microsoft.com)"
    echo "3. 用户UUID (自动生成或手动输入)"
    echo "4. 传输协议 (TCP/gRPC)"
    echo

    if ! confirm_action "是否继续配置vless+reality?"; then
        return 0
    fi

    # 收集配置信息
    read -p "请输入监听端口 (默认443): " vless_port
    vless_port=${vless_port:-443}

    # 验证端口
    if [[ ! "$vless_port" =~ ^[0-9]+$ ]] || [[ "$vless_port" -lt 1 ]] || [[ "$vless_port" -gt 65535 ]]; then
        print_message "$RED" "无效的端口号"
        return 1
    fi

    read -p "请输入伪装域名 (默认: www.microsoft.com): " dest_domain
    dest_domain=${dest_domain:-"www.microsoft.com"}

    read -p "请输入用户UUID (留空自动生成): " user_uuid
    if [[ -z "$user_uuid" ]]; then
        # 生成UUID
        if command -v uuidgen &> /dev/null; then
            user_uuid=$(uuidgen)
        else
            user_uuid=$(cat /proc/sys/kernel/random/uuid)
        fi
    fi

    print_message "$YELLOW" "传输协议选择:"
    echo "1. TCP (推荐，兼容性好)"
    echo "2. gRPC (性能更好，但可能被检测)"
    read -p "请选择 (1-2): " transport_choice

    case $transport_choice in
        1) transport_type="tcp" ;;
        2) transport_type="grpc" ;;
        *) transport_type="tcp" ;;
    esac

    print_message "$YELLOW" "配置信息确认:"
    echo "监听端口: $vless_port"
    echo "伪装域名: $dest_domain"
    echo "用户UUID: $user_uuid"
    echo "传输协议: $transport_type"
    echo

    if ! confirm_action "确认配置信息?"; then
        return 0
    fi

    log_message "开始配置vless+reality代理"

    # 安装Xray
    print_message "$YELLOW" "安装Xray核心..."
    if ! install_xray_core; then
        print_message "$RED" "Xray安装失败"
        return 1
    fi

    # 生成配置文件
    print_message "$YELLOW" "生成配置文件..."
    if ! generate_vless_config "$vless_port" "$dest_domain" "$user_uuid" "$transport_type"; then
        print_message "$RED" "配置文件生成失败"
        return 1
    fi

    # 配置防火墙
    print_message "$YELLOW" "配置防火墙规则..."
    if command -v ufw &> /dev/null; then
        ufw allow "$vless_port"/tcp comment 'vless+reality'
        log_message "开放端口: $vless_port"
    fi

    # 启动服务
    print_message "$YELLOW" "启动vless+reality服务..."
    systemctl enable xray
    systemctl start xray

    if systemctl is-active --quiet xray; then
        print_message "$GREEN" "vless+reality服务启动成功!"
        log_message "vless+reality服务配置完成"

        # 生成客户端配置
        generate_client_config "$vless_port" "$dest_domain" "$user_uuid" "$transport_type"

        # 显示服务状态
        print_message "$YELLOW" "服务状态:"
        systemctl status xray --no-pager -l

    else
        print_message "$RED" "vless+reality服务启动失败"
        print_message "$YELLOW" "查看错误日志:"
        journalctl -u xray --no-pager -l
        return 1
    fi
}

# 安装Xray核心
install_xray_core() {
    # 下载并安装Xray
    local install_script="/tmp/install-xray.sh"

    if curl -L -o "$install_script" "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"; then
        chmod +x "$install_script"
        bash "$install_script"
        rm -f "$install_script"
        return 0
    else
        print_message "$RED" "下载Xray安装脚本失败"
        return 1
    fi
}

# 生成vless+reality配置
generate_vless_config() {
    local port=$1
    local dest_domain=$2
    local uuid=$3
    local transport=$4

    # 生成密钥对
    local key_pair=$(/usr/local/bin/xray x25519)
    local private_key=$(echo "$key_pair" | grep "Private key:" | cut -d' ' -f3)
    local public_key=$(echo "$key_pair" | grep "Public key:" | cut -d' ' -f3)

    # 获取目标网站证书信息
    local short_id=$(openssl rand -hex 8)

    # 创建配置目录
    mkdir -p /usr/local/etc/xray

    # 生成服务器配置
    cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "$transport",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "$dest_domain:443",
                    "xver": 0,
                    "serverNames": [
                        "$dest_domain"
                    ],
                    "privateKey": "$private_key",
                    "shortIds": [
                        "$short_id"
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF

    # 创建日志目录
    mkdir -p /var/log/xray
    chown nobody:nogroup /var/log/xray

    # 保存配置信息供客户端使用
    cat > /root/vless-reality-config.txt << EOF
# vless+reality配置信息
服务器地址: $(curl -s ifconfig.me || hostname -I | awk '{print $1}')
端口: $port
用户ID: $uuid
传输协议: $transport
伪装域名: $dest_domain
公钥: $public_key
短ID: $short_id
配置时间: $(date)
EOF

    log_message "vless+reality配置文件已生成"
    return 0
}

# 生成客户端配置
generate_client_config() {
    local port=$1
    local dest_domain=$2
    local uuid=$3
    local transport=$4

    local server_ip=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
    local public_key=$(grep "公钥:" /root/vless-reality-config.txt | cut -d' ' -f2)
    local short_id=$(grep "短ID:" /root/vless-reality-config.txt | cut -d' ' -f2)

    print_message "$GREEN" "客户端配置信息:"
    echo "=================================="
    echo "协议: VLESS"
    echo "地址: $server_ip"
    echo "端口: $port"
    echo "用户ID: $uuid"
    echo "流控: xtls-rprx-vision"
    echo "传输协议: $transport"
    echo "传输层安全: reality"
    echo "SNI: $dest_domain"
    echo "Fingerprint: chrome"
    echo "PublicKey: $public_key"
    echo "ShortId: $short_id"
    echo "SpiderX: /"
    echo "=================================="

    # 生成分享链接
    local vless_link="vless://$uuid@$server_ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$dest_domain&fp=chrome&pbk=$public_key&sid=$short_id&type=$transport#VPS-Reality"

    echo
    print_message "$YELLOW" "分享链接:"
    echo "$vless_link"

    # 保存到文件
    cat > /root/vless-client-config.txt << EOF
# vless+reality客户端配置

## 手动配置信息
协议: VLESS
地址: $server_ip
端口: $port
用户ID: $uuid
流控: xtls-rprx-vision
传输协议: $transport
传输层安全: reality
SNI: $dest_domain
Fingerprint: chrome
PublicKey: $public_key
ShortId: $short_id
SpiderX: /

## 分享链接
$vless_link

## 使用说明
1. 复制分享链接到支持vless+reality的客户端
2. 或者手动填入上述配置信息
3. 推荐客户端: v2rayN, Clash Meta, sing-box

配置生成时间: $(date)
EOF

    print_message "$GREEN" "客户端配置已保存到: /root/vless-client-config.txt"
    log_message "生成vless+reality客户端配置"
}

# sing-box安装
install_singbox() {
    print_message "$BLUE" "=== sing-box安装 ==="

    print_message "$YELLOW" "sing-box是一个现代化的代理工具，支持多种协议："
    echo "• 支持协议: VLESS, VMess, Trojan, Shadowsocks, Hysteria2等"
    echo "• 高性能: 基于Go语言开发，性能优异"
    echo "• 配置灵活: 支持复杂的路由规则和分流配置"
    echo "• 维护活跃: 持续更新，支持最新协议特性"
    echo

    if confirm_action "是否安装sing-box?"; then
        print_message "$YELLOW" "开始安装sing-box..."

        # 检查系统架构
        local arch=$(uname -m)
        print_message "$CYAN" "检测到系统架构: $arch"

        # 安装sing-box
        print_message "$YELLOW" "下载并安装sing-box..."
        if bash <(wget -qO- -o- https://github.com/233boy/sing-box/raw/main/install.sh); then
            print_message "$GREEN" "sing-box安装成功"

            # 检查安装状态
            if command -v sing-box &> /dev/null; then
                local version=$(sing-box version 2>/dev/null | head -1 || echo "未知版本")
                print_message "$GREEN" "安装版本: $version"

                # 检查服务状态
                if systemctl is-enabled sing-box &>/dev/null; then
                    print_message "$GREEN" "✓ sing-box服务已启用"
                    if systemctl is-active --quiet sing-box; then
                        print_message "$GREEN" "✓ sing-box服务正在运行"
                    else
                        print_message "$YELLOW" "⚠ sing-box服务未运行"
                    fi
                else
                    print_message "$YELLOW" "⚠ sing-box服务未启用"
                fi
            else
                print_message "$YELLOW" "⚠ sing-box命令未找到，可能需要重新加载环境"
            fi

            echo
            print_message "$CYAN" "📋 sing-box管理命令:"
            echo "• 查看状态: sing-box status"
            echo "• 启动服务: sing-box start"
            echo "• 停止服务: sing-box stop"
            echo "• 重启服务: sing-box restart"
            echo "• 查看配置: sing-box config"
            echo "• 查看日志: sing-box log"
            echo "• 更新程序: sing-box update"
            echo "• 卸载程序: sing-box uninstall"
            echo

            print_message "$YELLOW" "配置提示:"
            echo "1. 配置文件位置: /usr/local/etc/sing-box/config.json"
            echo "2. 可使用 'sing-box config' 命令进行配置"
            echo "3. 支持多种协议和复杂路由规则"
            echo "4. 建议配置TLS证书以提高安全性"
            echo

            if confirm_action "是否现在配置sing-box?"; then
                print_message "$YELLOW" "启动sing-box配置..."
                sing-box
            fi

            log_message "sing-box安装完成"
        else
            print_message "$RED" "sing-box安装失败"
            print_message "$YELLOW" "可能的原因:"
            echo "1. 网络连接问题"
            echo "2. 系统架构不支持"
            echo "3. 权限不足"
            echo
            print_message "$YELLOW" "请检查网络连接后重试，或访问官方文档:"
            echo "https://sing-box.sagernet.org/"
            return 1
        fi
    fi
}

# 代理服务管理
manage_proxy_service() {
    print_message "$BLUE" "=== 代理服务管理 ==="

    if [[ ! -f "/usr/local/bin/xray" ]]; then
        print_message "$RED" "未检测到Xray服务，请先配置vless+reality代理"
        return 1
    fi

    while true; do
        echo
        print_message "$YELLOW" "代理服务管理选项:"
        echo "1. 查看服务状态"
        echo "2. 查看客户端配置"
        echo "3. 重启代理服务"
        echo "4. 查看服务日志"
        echo "5. 更新用户配置"
        echo "6. 卸载代理服务"
        echo "0. 返回主菜单"
        echo

        read -p "请选择操作 (0-6): " proxy_choice

        case $proxy_choice in
            1)
                print_message "$YELLOW" "Xray服务状态:"
                systemctl status xray --no-pager
                echo
                print_message "$YELLOW" "监听端口:"
                ss -tlnp | grep xray || echo "未找到监听端口"
                ;;
            2)
                if [[ -f "/root/vless-client-config.txt" ]]; then
                    print_message "$YELLOW" "客户端配置信息:"
                    cat /root/vless-client-config.txt
                else
                    print_message "$RED" "未找到客户端配置文件"
                fi
                ;;
            3)
                if confirm_action "是否重启Xray服务?"; then
                    systemctl restart xray
                    sleep 2
                    if systemctl is-active --quiet xray; then
                        print_message "$GREEN" "Xray服务重启成功"
                    else
                        print_message "$RED" "Xray服务重启失败"
                        journalctl -u xray --no-pager -l | tail -10
                    fi
                fi
                ;;
            4)
                print_message "$YELLOW" "Xray服务日志 (最近20行):"
                journalctl -u xray --no-pager -l | tail -20
                echo
                if [[ -f "/var/log/xray/error.log" ]]; then
                    print_message "$YELLOW" "错误日志:"
                    tail -10 /var/log/xray/error.log
                fi
                ;;
            5)
                print_message "$YELLOW" "更新用户配置功能开发中..."
                print_message "$BLUE" "当前可以通过重新运行配置功能来更新"
                ;;
            6)
                print_message "$RED" "⚠️  警告: 这将完全卸载代理服务"
                if confirm_action "确认卸载Xray代理服务?"; then
                    systemctl stop xray
                    systemctl disable xray
                    rm -f /etc/systemd/system/xray.service
                    rm -rf /usr/local/bin/xray
                    rm -rf /usr/local/etc/xray
                    rm -rf /var/log/xray
                    rm -f /root/vless-*.txt
                    systemctl daemon-reload

                    # 移除防火墙规则
                    if command -v ufw &> /dev/null; then
                        print_message "$YELLOW" "是否移除相关防火墙规则?"
                        ufw status numbered | grep -E "(vless|reality|443)"
                        read -p "请输入要删除的规则编号 (多个用空格分隔，留空跳过): " rule_numbers
                        if [[ -n "$rule_numbers" ]]; then
                            for rule_num in $rule_numbers; do
                                ufw delete "$rule_num" 2>/dev/null || true
                            done
                        fi
                    fi

                    print_message "$GREEN" "Xray代理服务已卸载"
                    log_message "卸载vless+reality代理服务"
                    break
                fi
                ;;
            0)
                break
                ;;
            *)
                print_message "$RED" "无效选择"
                ;;
        esac

        echo
        read -p "按回车键继续..." -r
    done
}

# 一键全部执行
run_all_hardening() {
    print_message "$BLUE" "=== 一键安全加固 ==="
    print_message "$YELLOW" "将依次执行以下操作:"
    echo "1. 系统更新"
    echo "2. 创建非root用户"
    echo "3. SSH安全配置"
    echo "4. 防火墙配置"
    echo "5. 安装fail2ban"
    echo "6. 网络安全配置"
    echo "7. 系统监控配置"
    echo "8. 精简系统组件"
    echo "9. 安全扫描检查"
    echo "10. 备份配置"
    echo "11. fail2ban高级配置"
    echo "12. vless+reality代理配置"
    echo

    if confirm_action "是否继续一键执行所有安全加固措施?"; then
        log_message "开始一键安全加固"

        update_system
        create_user
        configure_ssh
        configure_firewall
        install_fail2ban
        configure_network_security
        configure_monitoring
        system_cleanup
        security_scan
        backup_recovery

        print_message "$GREEN" "安全加固完成!"

        # 询问是否配置代理服务
        echo
        if confirm_action "是否配置vless+reality代理服务?"; then
            install_vless_reality
        fi

        print_message "$GREEN" "一键部署完成!"
        print_message "$BLUE" "请检查配置并重新连接SSH"
        print_message "$YELLOW" "建议重启系统以确保所有配置生效"

        # 显示配置摘要
        echo
        print_message "$BLUE" "配置摘要:"
        echo "- SSH端口: $(get_ssh_port)"
        echo "- 防火墙: $(ufw status | head -1)"
        echo "- fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo "未安装")"
        if [[ -f "/usr/local/etc/xray/config.json" ]]; then
            echo "- vless+reality: 已配置"
            echo "- 客户端配置: /root/vless-client-config.txt"
        fi
        echo "- 备份目录: $BACKUP_DIR"
        echo "- 日志文件: $LOG_FILE"

        log_message "一键安全加固和代理配置完成"
    fi
}

# 安全状态概览
show_security_overview() {
    clear
    print_colored "$BLUE" "┌─────────────────────────────────────────────────────────────────────────────┐"
    print_colored "$BLUE" "│                          VPS 安全状态概览                                 │"
    print_colored "$BLUE" "└─────────────────────────────────────────────────────────────────────────────┘"
    echo

    # 系统信息面板
    print_colored "$CYAN" "📊 系统信息"
    IFS='|' read -r hostname uptime kernel os ip load_avg memory_usage disk_usage <<< "$(get_system_info)"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"
    printf "│ 主机名: %-20s │ 运行时间: %-30s │\n" "$hostname" "$uptime"
    printf "│ 系统: %-22s │ 内核: %-33s │\n" "$os" "$kernel"
    printf "│ 公网IP: %-20s │ 负载: %-8s 内存: %-6s%% 磁盘: %-6s%% │\n" "$ip" "$load_avg" "$memory_usage" "$disk_usage"
    echo "└─────────────────────────────────────────────────────────────────────────────┘"
    echo

    # 安全服务状态
    print_colored "$CYAN" "🔧 安全服务状态"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"

    # SSH状态
    local ssh_status="STOPPED"
    local ssh_details="服务未运行"
    if systemctl is-active --quiet sshd; then
        ssh_status="RUNNING"
        local ssh_port=$(sshd -T 2>/dev/null | grep -i "^port" | awk '{print $2}' || echo "22")
        local ssh_connections=$(ss -tn | grep ":$ssh_port " | wc -l)
        local failed_today=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l)
        ssh_details="端口:$ssh_port 连接:$ssh_connections 今日失败:$failed_today"
    fi
    printf "│ "
    draw_status_indicator "$ssh_status" "SSH服务"
    printf "  详情: %-40s │\n" "$ssh_details"

    # fail2ban状态
    local f2b_status="STOPPED"
    local f2b_details="服务未运行"
    if command -v fail2ban-client &> /dev/null; then
        if systemctl is-active --quiet fail2ban; then
            if fail2ban-client status &>/dev/null; then
                f2b_status="RUNNING"
                local active_jails=$(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' ' ' | wc -w)
                local banned_ips=0
                local today_bans=$(grep "$(date '+%Y-%m-%d')" /var/log/fail2ban.log 2>/dev/null | grep "Ban" | wc -l)
                f2b_details="活动jail:$active_jails 封禁IP:$banned_ips 今日封禁:$today_bans"
            else
                f2b_status="ERROR"
                f2b_details="无法连接到服务"
            fi
        else
            f2b_details="服务已安装但未运行"
        fi
    else
        f2b_details="未安装"
    fi
    printf "│ "
    draw_status_indicator "$f2b_status" "fail2ban"
    printf "  详情: %-40s │\n" "$f2b_details"

    # 防火墙状态
    local ufw_status="STOPPED"
    local ufw_details="防火墙未启用"
    if command -v ufw &> /dev/null; then
        local ufw_status_output=$(ufw status 2>/dev/null | head -1)
        if echo "$ufw_status_output" | grep -q "Status: active"; then
            ufw_status="RUNNING"
            local ufw_rules=$(ufw status numbered 2>/dev/null | grep -c "^\[")
            ufw_details="已启用 规则数:$ufw_rules"
        else
            ufw_details="已安装但未启用"
        fi
    else
        ufw_details="未安装"
    fi
    printf "│ "
    draw_status_indicator "$ufw_status" "防火墙(UFW)"
    printf "  详情: %-40s │\n" "$ufw_details"

    echo "└─────────────────────────────────────────────────────────────────────────────┘"
    echo

    # 快速操作提示
    print_colored "$CYAN" "🔧 快速操作"
    echo "• 安全加固: 选择选项 21 (一键全部执行)"
    echo "• fail2ban管理: 选择选项 12"
    echo "• 防火墙配置: 选择选项 5"
    echo "• SSH安全配置: 选择选项 4"
    echo "• 安全扫描: 选择选项 10"
    echo
    read -p "按回车键返回主菜单..." -r
}

# 主菜单
show_menu() {
    clear
    print_message "$BLUE" "=================================="
    print_message "$BLUE" "       VPS安全加固脚本"
    print_message "$BLUE" "=================================="
    echo
    echo "🔍 0. 安全状态概览"
    echo ""
    echo "🛡️  安全加固功能:"
    echo "1. 显示系统信息"
    echo "2. 系统更新"
    echo "3. 创建非root用户"
    echo "4. SSH安全配置"
    echo "5. 防火墙配置"
    echo "6. 安装fail2ban"
    echo "7. 网络安全配置"
    echo "8. 系统监控配置"
    echo "9. 精简系统组件"
    echo "10. 安全扫描与检查"
    echo "11. 备份与恢复配置"
    echo "12. fail2ban管理"
    echo "13. 安全配置验证"
    echo ""
    echo "🚀 代理服务功能:"
    echo "14. 证书管理 (Cloudflare)"
    echo "15. Hysteria2服务"
    echo "16. 3X-UI面板"
    echo "17. Sub-Store服务"
    echo "18. Nginx分流配置"
    echo "19. 配置vless+reality代理"
    echo "20. sing-box安装"
    echo "21. 代理服务管理"
    echo ""
    echo "⚡ 22. 一键全部执行"
    echo "❌ 99. 退出"
    echo
}

# 主程序
main() {
    check_root
    check_system
    create_backup_dir
    
    log_message "VPS安全加固脚本启动"
    
    while true; do
        show_menu
        read -p "请选择操作 (0-22, 99): " choice

        case $choice in
            0) show_security_overview ;;
            1) show_system_info ;;
            2) update_system ;;
            3) create_user ;;
            4) configure_ssh ;;
            5) configure_firewall ;;
            6) install_fail2ban ;;
            7) configure_network_security ;;
            8) configure_monitoring ;;
            9) system_cleanup ;;
            10) security_scan ;;
            11) backup_recovery ;;
            12) manage_fail2ban ;;
            13) security_validation ;;
            14) manage_certificates ;;
            15) install_hysteria2 ;;
            16) install_xui ;;
            17) install_substore ;;
            18) configure_nginx ;;
            19) install_vless_reality ;;
            20) install_singbox ;;
            21) manage_proxy_service ;;
            22) run_all_hardening ;;
            99)
                print_message "$GREEN" "感谢使用VPS安全加固脚本!"
                print_message "$BLUE" "备份文件位置: $BACKUP_DIR"
                print_message "$BLUE" "日志文件位置: $LOG_FILE"
                exit 0
                ;;
            *) print_message "$RED" "无效选择，请重新输入" ;;
        esac
        
        echo
        read -p "按回车键继续..." -r
    done
}

# 脚本入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
