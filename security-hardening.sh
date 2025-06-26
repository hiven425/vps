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
NC='\033[0m' # No Color

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
    
    read -p "请输入新用户名: " username
    if [[ -z "$username" ]]; then
        print_message "$RED" "用户名不能为空"
        return 1
    fi
    
    if id "$username" &>/dev/null; then
        print_message "$YELLOW" "用户 $username 已存在"
        return 0
    fi
    
    if confirm_action "创建用户 $username 并添加到sudo组?"; then
        adduser "$username"
        usermod -aG sudo "$username"
        log_message "创建用户 $username 并添加到sudo组"
        
        # 设置SSH目录
        user_home="/home/$username"
        mkdir -p "$user_home/.ssh"
        chmod 700 "$user_home/.ssh"
        chown "$username:$username" "$user_home/.ssh"
        
        print_message "$GREEN" "用户 $username 创建成功"
        print_message "$YELLOW" "请记住为该用户配置SSH密钥"
    fi
}

# SSH安全配置
configure_ssh() {
    print_message "$BLUE" "=== SSH安全配置 ==="
    
    backup_file "/etc/ssh/sshd_config"
    
    # 修改SSH端口
    read -p "请输入新的SSH端口 (默认22): " ssh_port
    ssh_port=${ssh_port:-22}
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || [[ "$ssh_port" -lt 1 ]] || [[ "$ssh_port" -gt 65535 ]]; then
        print_message "$RED" "无效的端口号"
        return 1
    fi
    
    if confirm_action "将SSH端口修改为 $ssh_port ?"; then
        sed -i "s/^#*Port .*/Port $ssh_port/" /etc/ssh/sshd_config
        log_message "SSH端口修改为 $ssh_port"
    fi
    
    # 配置root登录策略
    print_message "$YELLOW" "Root登录配置选项:"
    echo "1. 完全禁用root登录 (PermitRootLogin no)"
    echo "2. 仅允许密钥认证 (PermitRootLogin prohibit-password) - 推荐"
    echo "3. 保持当前设置"
    read -p "请选择 (1-3): " root_choice

    case $root_choice in
        1)
            if confirm_action "完全禁用root登录? (确保已创建sudo用户)"; then
                sed -i "s/^#*PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
                log_message "完全禁用root用户SSH登录"
            fi
            ;;
        2)
            if confirm_action "设置root仅允许密钥认证? (推荐设置)"; then
                sed -i "s/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/" /etc/ssh/sshd_config
                log_message "设置root仅允许密钥认证"
            fi
            ;;
        3)
            print_message "$YELLOW" "保持当前root登录设置"
            ;;
        *)
            print_message "$RED" "无效选择，保持当前设置"
            ;;
    esac
    
    # 禁用密码认证
    if confirm_action "是否禁用密码认证，仅允许密钥认证? (确保已配置SSH密钥)"; then
        sed -i "s/^#*PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
        sed -i "s/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
        log_message "禁用密码认证，启用密钥认证"
    fi
    
    # 其他SSH安全配置
    if confirm_action "是否应用高级SSH安全配置?"; then
        # 获取当前用户和新创建的用户
        current_user=$(whoami)

        # 询问允许的用户
        read -p "请输入允许SSH登录的用户名 (多个用户用空格分隔，默认: $current_user): " allowed_users
        allowed_users=${allowed_users:-$current_user}

        cat >> /etc/ssh/sshd_config << EOF

# 高级安全加固配置
Protocol 2
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
MaxStartups 10:30:100
MaxSessions 4
AllowUsers $allowed_users

# 禁用不安全的认证方式
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes

# 禁用不安全的功能
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed

# 强化加密算法
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
EOF
        log_message "应用高级SSH安全配置"
        print_message "$GREEN" "已应用高级SSH安全配置"
        print_message "$YELLOW" "允许登录的用户: $allowed_users"
    fi
    
    # 测试SSH配置
    print_message "$YELLOW" "测试SSH配置语法..."
    if sshd -t; then
        print_message "$GREEN" "SSH配置语法正确"
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
        ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
        ufw allow "$ssh_port"/tcp comment 'SSH'

        # 允许HTTP和HTTPS
        if confirm_action "是否允许HTTP(80)和HTTPS(443)端口?"; then
            ufw allow 80/tcp comment 'HTTP'
            ufw allow 443/tcp comment 'HTTPS'
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
            ufw --force enable
            log_message "防火墙已启用"

            # 显示防火墙状态
            print_message "$GREEN" "防火墙规则:"
            ufw status numbered
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
        backup_file "/etc/fail2ban/jail.local"

        # 获取SSH端口
        ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")

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
enabled = true
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

[nginx-limit-req]
enabled = false
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 3
EOF

        log_message "配置fail2ban规则"

        # 创建ufw-block过滤器
        cat > /etc/fail2ban/filter.d/ufw-block.conf << 'EOF'
[Definition]
failregex = ^.*\[UFW BLOCK\].*SRC=<HOST>.*$
ignoreregex =
EOF
        log_message "创建ufw-block过滤器"

        # 创建ufw action (如果不存在)
        if [[ ! -f /etc/fail2ban/action.d/ufw.conf ]]; then
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

        # 启动fail2ban
        systemctl enable fail2ban
        systemctl restart fail2ban
        log_message "启动fail2ban服务"

        # 等待服务启动
        sleep 3

        print_message "$GREEN" "fail2ban状态:"
        fail2ban-client status

        print_message "$YELLOW" "fail2ban配置说明:"
        echo "- SSH保护: 3次失败后封禁1小时"
        echo "- UFW阻止: 5次触发后永久封禁"
        echo "- 查看状态: fail2ban-client status"
        echo "- 解封IP: fail2ban-client set jail名 unbanip IP地址"
    fi
}

# 网络安全配置
configure_network_security() {
    print_message "$BLUE" "=== 网络安全配置 ==="

    if confirm_action "是否配置网络安全参数?"; then
        backup_file "/etc/sysctl.conf"

        # 网络安全参数
        cat >> /etc/sysctl.conf << EOF

# 网络安全配置
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
        sysctl -p
        log_message "应用网络安全配置"
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
        echo "0. 返回主菜单"
        echo

        read -p "请选择操作 (0-6): " f2b_choice

        case $f2b_choice in
            1)
                print_message "$YELLOW" "fail2ban总体状态:"
                fail2ban-client status
                echo
                print_message "$YELLOW" "各jail详细状态:"
                for jail in $(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' ' '); do
                    jail=$(echo $jail | xargs)  # 去除空格
                    if [[ -n "$jail" ]]; then
                        echo "--- $jail ---"
                        fail2ban-client status "$jail"
                        echo
                    fi
                done
                ;;
            2)
                print_message "$YELLOW" "当前被封禁的IP地址:"
                for jail in $(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' ' '); do
                    jail=$(echo $jail | xargs)
                    if [[ -n "$jail" ]]; then
                        banned_ips=$(fail2ban-client status "$jail" | grep "Banned IP list:" | cut -d: -f2)
                        if [[ -n "$banned_ips" && "$banned_ips" != " " ]]; then
                            echo "$jail: $banned_ips"
                        fi
                    fi
                done
                ;;
            3)
                read -p "请输入要解封的IP地址: " unban_ip
                if [[ -n "$unban_ip" ]]; then
                    print_message "$YELLOW" "可用的jail:"
                    fail2ban-client status | grep "Jail list:" | cut -d: -f2
                    read -p "请输入jail名称 (如sshd): " jail_name
                    if [[ -n "$jail_name" ]]; then
                        if fail2ban-client set "$jail_name" unbanip "$unban_ip"; then
                            print_message "$GREEN" "IP $unban_ip 已从 $jail_name 解封"
                            log_message "手动解封IP: $unban_ip from $jail_name"
                        else
                            print_message "$RED" "解封失败，请检查IP和jail名称"
                        fi
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
                    systemctl restart fail2ban
                    sleep 3
                    print_message "$GREEN" "fail2ban服务已重启"
                    fail2ban-client status
                fi
                ;;
            6)
                print_message "$YELLOW" "测试fail2ban配置:"
                fail2ban-client -t
                if [[ $? -eq 0 ]]; then
                    print_message "$GREEN" "配置文件语法正确"
                else
                    print_message "$RED" "配置文件存在错误"
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

    # 检查SSH端口
    ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ -n "$ssh_port" && "$ssh_port" != "22" ]]; then
        print_message "$GREEN" "✓ SSH端口已修改: $ssh_port"
    else
        print_message "$YELLOW" "⚠ SSH仍使用默认端口22"
    fi

    # 检查root登录配置
    root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ "$root_login" == "no" || "$root_login" == "prohibit-password" ]]; then
        print_message "$GREEN" "✓ Root登录已限制: $root_login"
    else
        print_message "$RED" "✗ Root登录未限制"
        validation_passed=false
    fi

    # 检查密码认证
    password_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ "$password_auth" == "no" ]]; then
        print_message "$GREEN" "✓ 密码认证已禁用"
    else
        print_message "$YELLOW" "⚠ 密码认证仍启用"
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

        print_message "$GREEN" "一键安全加固完成!"
        print_message "$BLUE" "请检查配置并重新连接SSH"
        print_message "$YELLOW" "建议重启系统以确保所有配置生效"
        log_message "一键安全加固完成"
    fi
}

# 主菜单
show_menu() {
    clear
    print_message "$BLUE" "=================================="
    print_message "$BLUE" "       VPS安全加固脚本"
    print_message "$BLUE" "=================================="
    echo
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
    echo "14. 一键全部执行"
    echo "0. 退出"
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
        read -p "请选择操作 (0-14): " choice
        
        case $choice in
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
            14) run_all_hardening ;;
            0)
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
