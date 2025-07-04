#!/bin/bash

# 服务器安全加固专用脚本
# 专注于Linux服务器的核心安全防护和加固
# Version: 1.0.0

set -euo pipefail

#region //基础配置和工具函数

# 脚本信息
SCRIPT_NAME="Server Security Hardening"
SCRIPT_VERSION="1.0.0"
SCRIPT_AUTHOR="Security Team"

# 日志配置
LOG_DIR="/var/log/security-hardening"
LOG_FILE="$LOG_DIR/server-hardening.log"
BACKUP_DIR="/etc/security-backup/$(date +%Y%m%d_%H%M%S)"

# 颜色定义
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BLUE='\033[34m'
    PURPLE='\033[35m'
    CYAN='\033[36m'
    WHITE='\033[0m'
    BOLD='\033[1m'
else
    RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' WHITE='' BOLD=''
fi

# 初始化日志目录
init_logging() {
    mkdir -p "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
}

# 日志记录函数
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

log_info() {
    log_message "INFO" "$1"
    echo -e "${BLUE}[INFO]${WHITE} $1"
}

log_success() {
    log_message "SUCCESS" "$1"
    echo -e "${GREEN}[SUCCESS]${WHITE} $1"
}

log_warning() {
    log_message "WARNING" "$1"
    echo -e "${YELLOW}[WARNING]${WHITE} $1"
}

log_error() {
    log_message "ERROR" "$1"
    echo -e "${RED}[ERROR]${WHITE} $1" >&2
}

log_critical() {
    log_message "CRITICAL" "$1"
    echo -e "${RED}${BOLD}[CRITICAL]${WHITE} $1" >&2
}

# 备份函数
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$BACKUP_DIR/$(basename "$file").backup"
        log_info "已备份文件: $file"
    fi
}

# 确认函数
confirm_action() {
    local message="$1"
    local timeout="${2:-30}"
    
    echo -e "${YELLOW}$message${WHITE}"
    echo -n "确认继续？(y/N): "
    
    local response
    if read -r -t "$timeout" response; then
        [[ "$response" =~ ^[Yy]$ ]]
    else
        log_warning "操作超时，默认取消"
        return 1
    fi
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查系统信息
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="$NAME"
        OS_VERSION="$VERSION"
    else
        OS_NAME=$(uname -s)
        OS_VERSION=$(uname -r)
    fi
    
    log_info "检测到系统: $OS_NAME $OS_VERSION"
}

#endregion

#region //权限和环境检查

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_critical "此脚本需要root权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 系统兼容性检查
check_system_compatibility() {
    log_info "检查系统兼容性..."
    
    # 检查systemd
    if ! command_exists systemctl; then
        log_error "系统不支持systemd"
        return 1
    fi
    
    # 检查基本命令
    local required_commands=("awk" "sed" "grep" "find" "chmod" "chown")
    for cmd in "${required_commands[@]}"; do
        if ! command_exists "$cmd"; then
            log_error "缺少必需命令: $cmd"
            return 1
        fi
    done
    
    log_success "系统兼容性检查通过"
}

#endregion

#region //SSH安全加固

# SSH安全配置
harden_ssh() {
    log_info "开始SSH安全加固..."
    
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_config_dir="/etc/ssh/sshd_config.d"
    local hardening_config="$ssh_config_dir/99-security-hardening.conf"
    
    # 备份原始配置
    backup_file "$ssh_config"
    
    # 创建配置目录
    mkdir -p "$ssh_config_dir"
    chmod 755 "$ssh_config_dir"
    
    # 获取SSH端口配置
    local ssh_port
    echo -e "${CYAN}SSH端口配置${WHITE}"
    echo "当前SSH端口: $(grep -E '^#?Port' "$ssh_config" | awk '{print $2}' | head -1 || echo '22')"
    read -p "请输入新的SSH端口 (1024-65535) [默认: 22022]: " ssh_port
    ssh_port=${ssh_port:-22022}
    
    # 验证端口
    if ! [[ "$ssh_port" =~ ^[0-9]+$ ]] || [ "$ssh_port" -lt 1024 ] || [ "$ssh_port" -gt 65535 ]; then
        log_error "无效的端口号: $ssh_port"
        return 1
    fi
    
    # Root登录配置
    echo -e "${CYAN}Root登录配置${WHITE}"
    echo "1. no - 完全禁止Root登录"
    echo "2. prohibit-password - 仅允许密钥登录"
    echo "3. yes - 允许密码登录 (不推荐)"
    read -p "请选择Root登录方式 [1-3, 默认: 2]: " root_choice
    
    local permit_root_login
    case "${root_choice:-2}" in
        1) permit_root_login="no" ;;
        2) permit_root_login="prohibit-password" ;;
        3) permit_root_login="yes" ;;
        *) permit_root_login="prohibit-password" ;;
    esac
    
    # 生成安全配置
    cat > "$hardening_config" << EOF
# SSH安全加固配置
# 生成时间: $(date)
# 由服务器安全加固脚本生成

# 基础安全设置
Port $ssh_port
Protocol 2
PermitRootLogin $permit_root_login

# 认证设置
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# 安全限制
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 30

# 连接保活
ClientAliveInterval 300
ClientAliveCountMax 2

# 功能控制
X11Forwarding no
AllowTcpForwarding yes
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# 性能和安全优化
UseDNS no
TCPKeepAlive yes
Compression no

# 现代加密算法
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256

# 日志设置
SyslogFacility AUTH
LogLevel VERBOSE
EOF
    
    # 设置文件权限
    chmod 644 "$hardening_config"
    
    # 验证配置
    if sshd -t; then
        log_success "SSH配置验证通过"
        
        # 生成SSH密钥
        generate_ssh_keys
        
        # 重启SSH服务确认
        if confirm_action "是否立即重启SSH服务？(建议先测试新端口连接)"; then
            systemctl restart sshd || systemctl restart ssh
            log_success "SSH服务已重启"
        else
            log_warning "请手动重启SSH服务: systemctl restart sshd"
        fi
        
        echo -e "${GREEN}重要提醒:${WHITE}"
        echo "1. 新SSH端口: $ssh_port"
        echo "2. 请确保防火墙已开放新端口"
        echo "3. 建议在断开前先测试新端口连接"
        
    else
        log_error "SSH配置验证失败"
        rm -f "$hardening_config"
        return 1
    fi
}

# 生成SSH密钥
generate_ssh_keys() {
    local key_dir="/root/.ssh"
    local key_type="ed25519"
    
    if [[ ! -d "$key_dir" ]]; then
        mkdir -p "$key_dir"
        chmod 700 "$key_dir"
    fi
    
    local private_key="$key_dir/id_$key_type"
    local public_key="$private_key.pub"
    
    if [[ -f "$private_key" ]]; then
        log_warning "SSH密钥已存在: $private_key"
        return 0
    fi
    
    log_info "生成SSH密钥..."
    ssh-keygen -t "$key_type" -f "$private_key" -N "" -C "Generated by Server Hardening $(date +%Y%m%d)"
    
    chmod 600 "$private_key"
    chmod 644 "$public_key"
    
    log_success "SSH密钥生成完成"
    echo -e "${CYAN}公钥内容:${WHITE}"
    cat "$public_key"
}

#endregion

#region //防火墙配置

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    # 检查防火墙工具
    if command_exists ufw; then
        configure_ufw
    elif command_exists firewall-cmd; then
        configure_firewalld
    else
        configure_iptables
    fi
}

# UFW防火墙配置
configure_ufw() {
    log_info "配置UFW防火墙..."
    
    # 重置防火墙规则
    if confirm_action "是否重置现有的UFW规则？"; then
        ufw --force reset
    fi
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 获取SSH端口
    local ssh_port=$(grep -E '^Port' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo '22')
    
    # 基础规则
    ufw allow "$ssh_port/tcp" comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # 启用防火墙
    ufw --force enable
    
    # 配置额外安全规则
    configure_ufw_advanced_rules
    
    log_success "UFW防火墙配置完成"
    ufw status verbose
}

# UFW高级规则配置
configure_ufw_advanced_rules() {
    log_info "配置UFW高级安全规则..."
    
    # 限制SSH连接频率
    local ssh_port=$(grep -E '^Port' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo '22')
    ufw limit "$ssh_port/tcp"
    
    # 拒绝常见攻击端口
    local malicious_ports=(21 23 25 53 135 139 445 1433 3389 5432)
    for port in "${malicious_ports[@]}"; do
        ufw deny "$port" comment "Block malicious port $port"
    done
    
    # 允许环回接口
    ufw allow in on lo
    ufw allow out on lo
    
    log_success "UFW高级规则配置完成"
}

# iptables防火墙配置（备用方案）
configure_iptables() {
    log_info "配置iptables防火墙..."
    
    # 清空现有规则
    if confirm_action "是否清空现有的iptables规则？"; then
        iptables -F
        iptables -X
        iptables -Z
    fi
    
    # 设置默认策略
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 允许环回
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # 允许已建立的连接
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # 获取SSH端口
    local ssh_port=$(grep -E '^Port' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo '22')
    
    # 允许SSH（带限制）
    iptables -A INPUT -p tcp --dport "$ssh_port" -m limit --limit 4/min --limit-burst 3 -j ACCEPT
    
    # 允许HTTP/HTTPS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # 保存规则
    if command_exists iptables-save; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules
    fi
    
    log_success "iptables防火墙配置完成"
}

#endregion

#region //系统安全加固

# 系统安全参数优化
harden_system_parameters() {
    log_info "优化系统安全参数..."
    
    local sysctl_config="/etc/sysctl.d/99-security-hardening.conf"
    backup_file "$sysctl_config"
    
    cat > "$sysctl_config" << EOF
# 系统安全加固参数
# 生成时间: $(date)

# 网络安全
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# IPv6安全
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 内核安全
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1

# 内存保护
vm.mmap_min_addr = 65536

# 文件系统安全
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    # 应用配置
    sysctl -p "$sysctl_config"
    
    log_success "系统安全参数优化完成"
}

# 用户账户安全加固
harden_user_accounts() {
    log_info "加固用户账户安全..."
    
    # 备份配置文件
    backup_file "/etc/login.defs"
    backup_file "/etc/pam.d/common-password"
    
    # 设置密码策略
    configure_password_policy
    
    # 禁用不必要的用户账户
    disable_unnecessary_accounts
    
    # 设置用户会话超时
    configure_session_timeout
    
    log_success "用户账户安全加固完成"
}

# 配置密码策略
configure_password_policy() {
    log_info "配置密码安全策略..."
    
    # 修改login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t12/' /etc/login.defs
    
    # 配置PAM密码复杂度
    if [[ -f /etc/pam.d/common-password ]]; then
        # Ubuntu/Debian
        sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
        sed -i '/password.*pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' /etc/pam.d/common-password
    elif [[ -f /etc/pam.d/system-auth ]]; then
        # CentOS/RHEL
        sed -i '/pam_pwquality.so/d' /etc/pam.d/system-auth
        sed -i '/password.*pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' /etc/pam.d/system-auth
    fi
    
    log_success "密码策略配置完成"
}

# 禁用不必要的用户账户
disable_unnecessary_accounts() {
    log_info "检查并禁用不必要的用户账户..."
    
    local system_users=("games" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats")
    
    for user in "${system_users[@]}"; do
        if id "$user" >/dev/null 2>&1; then
            usermod -L "$user" 2>/dev/null && log_info "已锁定用户: $user"
            usermod -s /usr/sbin/nologin "$user" 2>/dev/null
        fi
    done
    
    log_success "用户账户检查完成"
}

# 配置会话超时
configure_session_timeout() {
    log_info "配置用户会话超时..."
    
    # 设置shell超时
    echo "TMOUT=1800" >> /etc/profile.d/timeout.sh
    chmod 644 /etc/profile.d/timeout.sh
    
    log_success "会话超时配置完成"
}

# 文件系统安全加固
harden_filesystem() {
    log_info "文件系统安全加固..."
    
    # 设置重要文件权限
    set_critical_file_permissions
    
    # 删除不安全的文件
    remove_insecure_files
    
    # 配置文件系统挂载选项
    configure_mount_options
    
    log_success "文件系统安全加固完成"
}

# 设置关键文件权限
set_critical_file_permissions() {
    log_info "设置关键文件权限..."
    
    # 系统配置文件
    chmod 644 /etc/passwd
    chmod 600 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    
    # SSH配置
    chmod 600 /etc/ssh/ssh_host_*_key
    chmod 644 /etc/ssh/ssh_host_*_key.pub
    chmod 644 /etc/ssh/sshd_config
    
    # sudo配置
    chmod 440 /etc/sudoers
    
    # 日志文件
    chmod 640 /var/log/auth.log 2>/dev/null || true
    chmod 640 /var/log/secure 2>/dev/null || true
    
    log_success "关键文件权限设置完成"
}

# 删除不安全的文件
remove_insecure_files() {
    log_info "检查并删除不安全的文件..."
    
    # 查找并处理世界可写文件
    local world_writable=$(find / -type f -perm -002 2>/dev/null | grep -v -E '^/(proc|sys|dev)' | head -10)
    if [[ -n "$world_writable" ]]; then
        log_warning "发现世界可写文件:"
        echo "$world_writable"
    fi
    
    # 查找SUID文件
    local suid_files=$(find /usr /bin /sbin -type f -perm -4000 2>/dev/null)
    if [[ -n "$suid_files" ]]; then
        log_info "SUID文件列表:"
        echo "$suid_files"
    fi
    
    log_success "文件安全检查完成"
}

# 配置挂载选项
configure_mount_options() {
    log_info "检查文件系统挂载选项..."
    
    # 检查/tmp挂载选项
    if mount | grep -q '/tmp'; then
        log_info "/tmp挂载点存在"
    else
        log_warning "/tmp未单独挂载，建议配置独立分区"
    fi
    
    log_success "挂载选项检查完成"
}

#endregion

#region //服务安全管理

# 禁用不必要的服务
disable_unnecessary_services() {
    log_info "禁用不必要的服务..."
    
    # 定义常见的不安全服务
    local unnecessary_services=(
        "telnet"
        "rsh"
        "rlogin"
        "rexec"
        "ftp"
        "tftp"
        "finger"
        "echo"
        "discard"
        "chargen"
        "daytime"
        "time"
        "avahi-daemon"
        "cups"
        "bluetooth"
    )
    
    for service in "${unnecessary_services[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            systemctl disable "$service" >/dev/null 2>&1
            systemctl stop "$service" >/dev/null 2>&1
            log_info "已禁用服务: $service"
        fi
    done
    
    log_success "不必要服务禁用完成"
}

# 安全服务配置
configure_security_services() {
    log_info "配置安全相关服务..."
    
    # 配置fail2ban
    configure_fail2ban
    
    # 配置auditd
    configure_auditd
    
    # 配置rsyslog
    configure_rsyslog
    
    log_success "安全服务配置完成"
}

# 配置fail2ban
configure_fail2ban() {
    log_info "配置fail2ban..."
    
    # 安装fail2ban
    if ! command_exists fail2ban-client; then
        if command_exists apt-get; then
            apt-get update && apt-get install -y fail2ban
        elif command_exists yum; then
            yum install -y fail2ban
        elif command_exists dnf; then
            dnf install -y fail2ban
        else
            log_warning "无法自动安装fail2ban"
            return 1
        fi
    fi
    
    # 配置fail2ban
    local fail2ban_config="/etc/fail2ban/jail.local"
    backup_file "$fail2ban_config"
    
    local ssh_port=$(grep -E '^Port' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo '22')
    
    cat > "$fail2ban_config" << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
banaction = iptables-multiport
protocol = tcp
chain = INPUT
action_ = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mw = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
            %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]
action = %(action_)s

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[sshd-ddos]
enabled = true
port = $ssh_port
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 7200
findtime = 300
EOF
    
    # 启动fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "fail2ban配置完成"
}

# 配置auditd
configure_auditd() {
    log_info "配置系统审计..."
    
    # 安装auditd
    if ! command_exists auditctl; then
        if command_exists apt-get; then
            apt-get install -y auditd audispd-plugins
        elif command_exists yum; then
            yum install -y audit audit-libs
        elif command_exists dnf; then
            dnf install -y audit audit-libs
        else
            log_warning "无法自动安装auditd"
            return 1
        fi
    fi
    
    # 配置审计规则
    local audit_rules="/etc/audit/rules.d/99-security-hardening.rules"
    backup_file "$audit_rules"
    
    cat > "$audit_rules" << EOF
# 系统安全审计规则
# 生成时间: $(date)

# 删除所有现有规则
-D

# 缓冲区大小
-b 8192

# 失败时的动作
-f 1

# 监控关键文件修改
-w /etc/passwd -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/shadow -p wa -k password_modification
-w /etc/sudoers -p wa -k sudo_modification
-w /etc/ssh/sshd_config -p wa -k ssh_modification

# 监控系统调用
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# 监控网络配置
-w /etc/hosts -p wa -k network_modification
-w /etc/network/ -p wa -k network_modification

# 监控登录事件
-w /var/log/lastlog -p wa -k login_events
-w /var/log/faillog -p wa -k login_events

# 监控权限修改
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod

# 使规则不可修改
-e 2
EOF
    
    # 重启auditd
    systemctl enable auditd
    systemctl restart auditd
    
    log_success "系统审计配置完成"
}

# 配置rsyslog
configure_rsyslog() {
    log_info "配置系统日志..."
    
    if ! command_exists rsyslogd; then
        log_warning "rsyslog未安装，跳过配置"
        return 0
    fi
    
    # 配置日志文件权限
    local rsyslog_config="/etc/rsyslog.d/99-security-hardening.conf"
    
    cat > "$rsyslog_config" << EOF
# 安全日志配置
# 生成时间: $(date)

# 设置文件权限
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022

# 安全相关日志单独记录
auth,authpriv.*                 /var/log/auth.log
kern.*                          /var/log/kern.log
mail.*                          /var/log/mail.log

# 禁止普通用户访问某些日志
& stop
EOF
    
    # 重启rsyslog
    systemctl restart rsyslog
    
    log_success "系统日志配置完成"
}

#endregion

#region //网络安全配置

# 网络安全加固
harden_network_security() {
    log_info "网络安全加固..."
    
    # 禁用不必要的网络协议
    disable_network_protocols
    
    # 配置网络访问控制
    configure_network_access_control
    
    # 配置DNS安全
    configure_dns_security
    
    log_success "网络安全加固完成"
}

# 禁用不必要的网络协议
disable_network_protocols() {
    log_info "禁用不必要的网络协议..."
    
    local blacklist_config="/etc/modprobe.d/blacklist-security.conf"
    
    cat > "$blacklist_config" << EOF
# 禁用不安全的网络协议
# 生成时间: $(date)

# 禁用不常用的网络协议
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc

# 禁用不安全的文件系统
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf
EOF
    
    log_success "网络协议配置完成"
}

# 配置网络访问控制
configure_network_access_control() {
    log_info "配置网络访问控制..."
    
    # 配置hosts.allow和hosts.deny
    local hosts_allow="/etc/hosts.allow"
    local hosts_deny="/etc/hosts.deny"
    
    backup_file "$hosts_allow"
    backup_file "$hosts_deny"
    
    # 基本的访问控制
    echo "# 允许本地访问" > "$hosts_allow"
    echo "ALL: 127.0.0.1" >> "$hosts_allow"
    echo "ALL: ::1" >> "$hosts_allow"
    
    echo "# 默认拒绝所有" > "$hosts_deny"
    echo "ALL: ALL" >> "$hosts_deny"
    
    log_success "网络访问控制配置完成"
}

# 配置DNS安全
configure_dns_security() {
    log_info "配置DNS安全..."
    
    # 配置安全的DNS服务器
    local resolv_conf="/etc/resolv.conf"
    backup_file "$resolv_conf"
    
    cat > "$resolv_conf" << EOF
# 安全DNS配置
# 生成时间: $(date)

# Cloudflare DNS (支持DNS over HTTPS)
nameserver 1.1.1.1
nameserver 1.0.0.1

# Quad9 DNS (恶意软件过滤)
nameserver 9.9.9.9
nameserver 149.112.112.112

# 选项
options timeout:2
options attempts:3
options rotate
EOF
    
    log_success "DNS安全配置完成"
}

#endregion

#region //系统监控和告警

# 配置系统监控
configure_monitoring() {
    log_info "配置系统监控..."
    
    # 配置系统资源监控
    configure_resource_monitoring
    
    # 配置安全事件监控
    configure_security_monitoring
    
    # 配置日志监控
    configure_log_monitoring
    
    log_success "系统监控配置完成"
}

# 配置资源监控
configure_resource_monitoring() {
    log_info "配置资源监控..."
    
    # 创建监控脚本
    local monitor_script="/usr/local/bin/system-monitor.sh"
    
    cat > "$monitor_script" << 'EOF'
#!/bin/bash

# 系统资源监控脚本
LOG_FILE="/var/log/system-monitor.log"

# 记录系统状态
log_system_status() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # CPU使用率
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    # 内存使用率
    local mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    
    # 磁盘使用率
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    
    # 记录到日志
    echo "[$timestamp] CPU: ${cpu_usage}%, Memory: ${mem_usage}%, Disk: ${disk_usage}%" >> "$LOG_FILE"
    
    # 检查告警条件
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        logger -p user.warning "High CPU usage: ${cpu_usage}%"
    fi
    
    if (( $(echo "$mem_usage > 80" | bc -l) )); then
        logger -p user.warning "High memory usage: ${mem_usage}%"
    fi
    
    if [ "$disk_usage" -gt 80 ]; then
        logger -p user.warning "High disk usage: ${disk_usage}%"
    fi
}

log_system_status
EOF
    
    chmod +x "$monitor_script"
    
    # 添加到cron任务
    local cron_entry="*/5 * * * * /usr/local/bin/system-monitor.sh"
    (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
    
    log_success "资源监控配置完成"
}

# 配置安全事件监控
configure_security_monitoring() {
    log_info "配置安全事件监控..."
    
    # 创建安全监控脚本
    local security_monitor="/usr/local/bin/security-monitor.sh"
    
    cat > "$security_monitor" << 'EOF'
#!/bin/bash

# 安全事件监控脚本
ALERT_LOG="/var/log/security-alerts.log"

# 检查登录失败
check_failed_logins() {
    local failed_count=$(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    if [ "$failed_count" -gt 10 ]; then
        echo "[$(date)] Alert: $failed_count failed login attempts today" >> "$ALERT_LOG"
        logger -p authpriv.warning "High number of failed login attempts: $failed_count"
    fi
}

# 检查新的网络连接
check_network_connections() {
    local connection_count=$(ss -tuln | grep LISTEN | wc -l)
    if [ "$connection_count" -gt 20 ]; then
        echo "[$(date)] Alert: $connection_count listening ports detected" >> "$ALERT_LOG"
    fi
}

# 检查系统完整性
check_system_integrity() {
    # 检查关键文件修改时间
    local passwd_mtime=$(stat -c %Y /etc/passwd)
    local shadow_mtime=$(stat -c %Y /etc/shadow)
    local current_time=$(date +%s)
    
    # 如果在最近1小时内修改过
    if [ $((current_time - passwd_mtime)) -lt 3600 ]; then
        echo "[$(date)] Alert: /etc/passwd was recently modified" >> "$ALERT_LOG"
    fi
    
    if [ $((current_time - shadow_mtime)) -lt 3600 ]; then
        echo "[$(date)] Alert: /etc/shadow was recently modified" >> "$ALERT_LOG"
    fi
}

check_failed_logins
check_network_connections
check_system_integrity
EOF
    
    chmod +x "$security_monitor"
    
    # 添加到cron任务
    local cron_entry="0 */1 * * * /usr/local/bin/security-monitor.sh"
    (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
    
    log_success "安全事件监控配置完成"
}

# 配置日志监控
configure_log_monitoring() {
    log_info "配置日志监控..."
    
    # 配置logrotate
    local logrotate_config="/etc/logrotate.d/security-hardening"
    
    cat > "$logrotate_config" << EOF
/var/log/security-hardening/* {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root root
}

/var/log/security-alerts.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root root
}
EOF
    
    log_success "日志监控配置完成"
}

#endregion

#region //安全检查和报告

# 执行安全检查
perform_security_check() {
    log_info "执行安全检查..."
    
    local check_report="/tmp/security_check_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "服务器安全检查报告"
        echo "===================="
        echo "检查时间: $(date)"
        echo "主机名: $(hostname)"
        echo "系统: $(uname -a)"
        echo ""
        
        # SSH安全检查
        echo "SSH安全检查:"
        echo "============"
        if sshd -t 2>/dev/null; then
            echo "✓ SSH配置语法正确"
        else
            echo "✗ SSH配置语法错误"
        fi
        
        local ssh_port=$(grep -E '^Port' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo '22')
        echo "SSH端口: $ssh_port"
        
        local root_login=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo 'unknown')
        echo "Root登录: $root_login"
        echo ""
        
        # 防火墙检查
        echo "防火墙检查:"
        echo "=========="
        if command_exists ufw; then
            ufw status
        elif command_exists firewall-cmd; then
            firewall-cmd --state
        else
            echo "防火墙状态: 未知"
        fi
        echo ""
        
        # 服务检查
        echo "关键服务状态:"
        echo "============"
        for service in sshd fail2ban auditd rsyslog; do
            local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            echo "$service: $status"
        done
        echo ""
        
        # 系统资源
        echo "系统资源:"
        echo "========"
        echo "负载: $(uptime | cut -d',' -f4-)"
        echo "内存: $(free -h | grep Mem | awk '{print $3"/"$2}')"
        echo "磁盘: $(df -h / | tail -1 | awk '{print $3"/"$2" ("$5")"}')"
        echo ""
        
        # 安全事件
        echo "最近的安全事件:"
        echo "=============="
        if [[ -f /var/log/security-alerts.log ]]; then
            tail -5 /var/log/security-alerts.log
        else
            echo "无安全告警日志"
        fi
        
    } > "$check_report"
    
    log_success "安全检查完成，报告保存到: $check_report"
    
    # 显示摘要
    echo -e "${CYAN}安全检查摘要:${WHITE}"
    grep -E "(✓|✗)" "$check_report"
}

# 生成安全基线报告
generate_security_baseline() {
    log_info "生成安全基线报告..."
    
    local baseline_report="/tmp/security_baseline_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "$baseline_report" << EOF
{
  "report_info": {
    "generated": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "system": "$(uname -a)",
    "script_version": "$SCRIPT_VERSION"
  },
  "ssh_security": {
    "config_valid": $(sshd -t 2>/dev/null && echo "true" || echo "false"),
    "port": "$(grep -E '^Port' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo '22')",
    "root_login": "$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo 'unknown')",
    "password_auth": "$(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config.d/99-security-hardening.conf 2>/dev/null | awk '{print $2}' || echo 'unknown')"
  },
  "firewall": {
    "ufw_active": $(command_exists ufw && ufw status | grep -q "Status: active" && echo "true" || echo "false"),
    "iptables_rules": $(iptables -L | wc -l)
  },
  "services": {
    "ssh_active": "$(systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo 'inactive')",
    "fail2ban_active": "$(systemctl is-active fail2ban 2>/dev/null || echo 'inactive')",
    "auditd_active": "$(systemctl is-active auditd 2>/dev/null || echo 'inactive')"
  },
  "system_security": {
    "kernel_version": "$(uname -r)",
    "last_update": "$(stat -c %y /var/log/dpkg.log 2>/dev/null || stat -c %y /var/log/yum.log 2>/dev/null || echo 'unknown')",
    "user_count": $(cut -d: -f1 /etc/passwd | wc -l),
    "sudo_users": $(grep -c sudo /etc/group)
  }
}
EOF
    
    log_success "安全基线报告生成: $baseline_report"
}

#endregion

#region //主菜单和控制流程

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${PURPLE}${BOLD}╔════════════════════════════════════════════════════════════╗${WHITE}"
    echo -e "${PURPLE}${BOLD}║                  服务器安全加固工具                           ║${WHITE}"
    echo -e "${PURPLE}${BOLD}║                     Version $SCRIPT_VERSION                          ║${WHITE}"
    echo -e "${PURPLE}${BOLD}╚════════════════════════════════════════════════════════════╝${WHITE}"
    echo ""
    echo -e "${CYAN}🔒 核心安全加固${WHITE}"
    echo "1. SSH安全配置"
    echo "2. 防火墙配置"
    echo "3. 系统参数加固"
    echo "4. 用户账户安全"
    echo "5. 文件系统安全"
    echo ""
    echo -e "${CYAN}🛡️  服务安全管理${WHITE}"
    echo "6. 禁用不必要服务"
    echo "7. 配置安全服务"
    echo "8. 网络安全配置"
    echo ""
    echo -e "${CYAN}📊 监控和检查${WHITE}"
    echo "9. 配置系统监控"
    echo "10. 执行安全检查"
    echo "11. 生成安全报告"
    echo ""
    echo -e "${CYAN}🚀 一键操作${WHITE}"
    echo "12. 完整安全加固"
    echo "13. 快速安全检查"
    echo ""
    echo "0. 退出"
    echo ""
}

# 主控制函数
main_control() {
    while true; do
        show_main_menu
        
        read -p "请选择操作 [0-13]: " choice
        
        case "$choice" in
            1)
                echo -e "${CYAN}=== SSH安全配置 ===${WHITE}"
                harden_ssh
                ;;
            2)
                echo -e "${CYAN}=== 防火墙配置 ===${WHITE}"
                configure_firewall
                ;;
            3)
                echo -e "${CYAN}=== 系统参数加固 ===${WHITE}"
                harden_system_parameters
                ;;
            4)
                echo -e "${CYAN}=== 用户账户安全 ===${WHITE}"
                harden_user_accounts
                ;;
            5)
                echo -e "${CYAN}=== 文件系统安全 ===${WHITE}"
                harden_filesystem
                ;;
            6)
                echo -e "${CYAN}=== 禁用不必要服务 ===${WHITE}"
                disable_unnecessary_services
                ;;
            7)
                echo -e "${CYAN}=== 配置安全服务 ===${WHITE}"
                configure_security_services
                ;;
            8)
                echo -e "${CYAN}=== 网络安全配置 ===${WHITE}"
                harden_network_security
                ;;
            9)
                echo -e "${CYAN}=== 配置系统监控 ===${WHITE}"
                configure_monitoring
                ;;
            10)
                echo -e "${CYAN}=== 执行安全检查 ===${WHITE}"
                perform_security_check
                ;;
            11)
                echo -e "${CYAN}=== 生成安全报告 ===${WHITE}"
                generate_security_baseline
                ;;
            12)
                echo -e "${CYAN}=== 完整安全加固 ===${WHITE}"
                perform_complete_hardening
                ;;
            13)
                echo -e "${CYAN}=== 快速安全检查 ===${WHITE}"
                quick_security_check
                ;;
            0)
                echo -e "${GREEN}感谢使用服务器安全加固工具！${WHITE}"
                exit 0
                ;;
            *)
                log_error "无效选择: $choice"
                ;;
        esac
        
        echo ""
        echo "按任意键继续..."
        read -n 1 -s
    done
}

# 完整安全加固
perform_complete_hardening() {
    log_info "开始完整服务器安全加固..."
    
    if ! confirm_action "这将对服务器进行全面的安全加固，可能需要重启某些服务。确认继续？"; then
        log_info "用户取消操作"
        return 0
    fi
    
    local start_time=$(date +%s)
    
    # 执行所有加固步骤
    log_info "步骤 1/9: SSH安全配置"
    harden_ssh
    
    log_info "步骤 2/9: 防火墙配置"
    configure_firewall
    
    log_info "步骤 3/9: 系统参数优化"
    harden_system_parameters
    
    log_info "步骤 4/9: 用户账户安全"
    harden_user_accounts
    
    log_info "步骤 5/9: 文件系统安全"
    harden_filesystem
    
    log_info "步骤 6/9: 禁用不必要服务"
    disable_unnecessary_services
    
    log_info "步骤 7/9: 配置安全服务"
    configure_security_services
    
    log_info "步骤 8/9: 网络安全配置"
    harden_network_security
    
    log_info "步骤 9/9: 配置监控"
    configure_monitoring
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "完整安全加固完成！用时: ${duration}秒"
    
    # 生成最终报告
    echo -e "${GREEN}${BOLD}安全加固完成摘要:${WHITE}"
    echo "1. ✓ SSH安全配置已优化"
    echo "2. ✓ 防火墙规则已配置"
    echo "3. ✓ 系统安全参数已优化"
    echo "4. ✓ 用户账户已加固"
    echo "5. ✓ 文件系统权限已设置"
    echo "6. ✓ 不必要服务已禁用"
    echo "7. ✓ 安全服务已配置"
    echo "8. ✓ 网络安全已加固"
    echo "9. ✓ 监控告警已部署"
    echo ""
    echo -e "${YELLOW}重要提醒:${WHITE}"
    echo "1. 配置备份保存在: $BACKUP_DIR"
    echo "2. 系统日志位置: $LOG_FILE"
    echo "3. 建议重启服务器以确保所有更改生效"
    echo "4. 请保存好SSH密钥和新端口信息"
}

# 快速安全检查
quick_security_check() {
    log_info "执行快速安全检查..."
    
    local issues=0
    
    echo -e "${CYAN}快速安全检查结果:${WHITE}"
    echo "===================="
    
    # SSH检查
    if sshd -t 2>/dev/null; then
        echo -e "${GREEN}✓${WHITE} SSH配置语法正确"
    else
        echo -e "${RED}✗${WHITE} SSH配置语法错误"
        ((issues++))
    fi
    
    # 防火墙检查
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✓${WHITE} UFW防火墙已启用"
    elif iptables -L | grep -q "Chain INPUT"; then
        echo -e "${YELLOW}⚠${WHITE} 使用iptables防火墙"
    else
        echo -e "${RED}✗${WHITE} 防火墙未配置"
        ((issues++))
    fi
    
    # 关键服务检查
    for service in sshd fail2ban; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            echo -e "${GREEN}✓${WHITE} $service 服务正在运行"
        else
            echo -e "${RED}✗${WHITE} $service 服务未运行"
            ((issues++))
        fi
    done
    
    # 文件权限检查
    if [[ $(stat -c '%a' /etc/shadow) == "600" ]]; then
        echo -e "${GREEN}✓${WHITE} /etc/shadow 权限正确"
    else
        echo -e "${RED}✗${WHITE} /etc/shadow 权限异常"
        ((issues++))
    fi
    
    echo "===================="
    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}快速检查通过！未发现安全问题。${WHITE}"
    else
        echo -e "${RED}${BOLD}发现 $issues 个安全问题，建议进行详细检查。${WHITE}"
    fi
}

#endregion

#region //主程序入口

# 主程序
main() {
    # 显示脚本信息
    echo -e "${PURPLE}${BOLD}$SCRIPT_NAME v$SCRIPT_VERSION${WHITE}"
    echo -e "${CYAN}专注于Linux服务器核心安全防护${WHITE}"
    echo ""
    
    # 环境检查
    check_root
    init_logging
    detect_system
    check_system_compatibility
    
    log_info "服务器安全加固工具启动"
    log_info "系统信息: $OS_NAME $OS_VERSION"
    
    # 启动主菜单
    main_control
}

# 脚本入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

#endregion