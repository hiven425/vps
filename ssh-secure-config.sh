#!/bin/bash

# SSH安全配置脚本
# 专门处理SSH端口修改和安全配置，包括云服务商配置冲突处理

set -euo pipefail

# 颜色定义
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
PURPLE='\033[35m'
CYAN='\033[36m'
WHITE='\033[0m'
BOLD='\033[1m'

# 配置变量
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
CUSTOM_CONFIG="$SSH_CONFIG_DIR/99-secure-ssh.conf"
BACKUP_DIR="/etc/ssh/backup-$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/ssh-config.log"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${WHITE} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${WHITE} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${WHITE} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${WHITE} $1" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

# 检查权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 创建备份目录
create_backup() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    log_info "备份目录已创建: $BACKUP_DIR"
}

# 备份现有SSH配置
backup_ssh_configs() {
    log_info "备份现有SSH配置..."
    
    # 备份主配置文件
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup"
        log_success "已备份主配置文件"
    fi
    
    # 备份sshd_config.d目录下的所有配置文件
    if [[ -d "$SSH_CONFIG_DIR" ]]; then
        cp -r "$SSH_CONFIG_DIR" "$BACKUP_DIR/sshd_config.d.backup"
        log_success "已备份配置目录"
    fi
}

# 检查并处理云服务商配置冲突
handle_cloud_configs() {
    log_info "检查云服务商配置文件..."
    
    if [[ ! -d "$SSH_CONFIG_DIR" ]]; then
        log_warning "sshd_config.d目录不存在，将创建"
        mkdir -p "$SSH_CONFIG_DIR"
        chmod 755 "$SSH_CONFIG_DIR"
    fi
    
    local cloud_configs_found=()
    local common_cloud_configs=(
        "50-cloud-init.conf"        # CloudCone, DigitalOcean等
        "60-cloudimg-settings.conf" # AWS EC2
        "cloud-init-ssh.conf"       # 通用cloud-init
        "azure.conf"                # Azure
        "google.conf"               # Google Cloud
        "vultr.conf"                # Vultr
        "linode.conf"               # Linode
    )
    
    # 检查已知的云服务商配置文件
    for config in "${common_cloud_configs[@]}"; do
        local config_path="$SSH_CONFIG_DIR/$config"
        if [[ -f "$config_path" ]]; then
            cloud_configs_found+=("$config")
            log_warning "发现云服务商配置文件: $config"
        fi
    done
    
    # 检查其他可能的配置文件
    if [[ -d "$SSH_CONFIG_DIR" ]]; then
        while IFS= read -r -d '' file; do
            local filename=$(basename "$file")
            # 跳过我们自己的配置文件
            if [[ "$filename" != "99-secure-ssh.conf" ]] && [[ "$filename" != "99-security-hardening.conf" ]]; then
                if [[ ! " ${cloud_configs_found[*]} " =~ " ${filename} " ]]; then
                    cloud_configs_found+=("$filename")
                    log_warning "发现其他配置文件: $filename"
                fi
            fi
        done < <(find "$SSH_CONFIG_DIR" -name "*.conf" -print0 2>/dev/null)
    fi
    
    # 处理发现的配置文件
    if [[ ${#cloud_configs_found[@]} -gt 0 ]]; then
        echo -e "${CYAN}发现以下配置文件可能会与我们的安全配置冲突:${WHITE}"
        for config in "${cloud_configs_found[@]}"; do
            echo "  - $config"
        done
        echo ""
        
        # 显示这些文件的内容
        for config in "${cloud_configs_found[@]}"; do
            local config_path="$SSH_CONFIG_DIR/$config"
            echo -e "${CYAN}=== $config 内容 ===${WHITE}"
            cat "$config_path"
            echo ""
        done
        
        read -p "是否要备份并重命名这些配置文件以避免冲突？(y/N): " handle_conflicts
        
        if [[ "$handle_conflicts" =~ ^[Yy]$ ]]; then
            for config in "${cloud_configs_found[@]}"; do
                local config_path="$SSH_CONFIG_DIR/$config"
                local backup_path="$SSH_CONFIG_DIR/${config}.disabled"
                
                mv "$config_path" "$backup_path"
                log_success "已重命名: $config -> ${config}.disabled"
            done
        else
            log_warning "保留现有配置文件，可能存在冲突"
        fi
    else
        log_success "未发现云服务商配置冲突"
    fi
}

# 获取当前SSH配置
get_current_ssh_config() {
    echo -e "${CYAN}=== 当前SSH配置状态 ===${WHITE}"
    
    # 显示当前生效的配置
    echo "当前SSH端口: $(sshd -T | grep -i '^port ' | awk '{print $2}')"
    echo "Root登录设置: $(sshd -T | grep -i '^permitrootlogin ' | awk '{print $2}')"
    echo "密码认证: $(sshd -T | grep -i '^passwordauthentication ' | awk '{print $2}')"
    echo "公钥认证: $(sshd -T | grep -i '^pubkeyauthentication ' | awk '{print $2}')"
    echo ""
}

# 验证端口号
validate_port() {
    local port="$1"
    
    # 检查是否为数字
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # 检查端口范围
    if [[ $port -lt 1 || $port -gt 65535 ]]; then
        return 1
    fi
    
    # 检查端口是否被占用
    if ss -tuln | grep -q ":$port "; then
        log_warning "端口 $port 可能已被占用"
        ss -tuln | grep ":$port "
        return 1
    fi
    
    # 检查常见端口冲突
    case $port in
        22) log_warning "端口22是SSH默认端口" ;;
        80) log_warning "端口80通常用于HTTP服务" ;;
        443) log_warning "端口443通常用于HTTPS服务" ;;
        25|465|587) log_warning "端口$port通常用于邮件服务" ;;
        53) log_warning "端口53通常用于DNS服务" ;;
        3306) log_warning "端口3306通常用于MySQL服务" ;;
        5432) log_warning "端口5432通常用于PostgreSQL服务" ;;
    esac
    
    return 0
}

# 获取用户输入的SSH配置
get_ssh_preferences() {
    echo -e "${CYAN}=== SSH安全配置向导 ===${WHITE}"
    
    # SSH端口配置
    while true; do
        local current_port=$(sshd -T | grep -i '^port ' | awk '{print $2}')
        read -p "请输入新的SSH端口 (1024-65535) [当前: $current_port]: " new_port
        
        # 如果用户直接回车，使用当前端口
        if [[ -z "$new_port" ]]; then
            new_port="$current_port"
        fi
        
        if validate_port "$new_port"; then
            SSH_PORT="$new_port"
            break
        else
            log_error "无效的端口号: $new_port，请重新输入"
        fi
    done
    
    # Root登录配置
    echo ""
    echo -e "${CYAN}Root登录配置:${WHITE}"
    echo "1. no - 完全禁止Root登录 (最安全)"
    echo "2. prohibit-password - 仅允许密钥登录 (推荐)"
    echo "3. without-password - 仅允许密钥登录 (别名)"
    echo "4. yes - 允许密码登录 (不推荐)"
    
    while true; do
        read -p "请选择Root登录方式 [1-4, 默认: 2]: " root_choice
        
        case "${root_choice:-2}" in
            1) ROOT_LOGIN="no"; break ;;
            2) ROOT_LOGIN="prohibit-password"; break ;;
            3) ROOT_LOGIN="without-password"; break ;;
            4) 
                log_warning "允许Root密码登录存在安全风险！"
                read -p "确认要允许Root密码登录吗？(y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    ROOT_LOGIN="yes"
                    break
                fi
                ;;
            *) log_error "无效选择，请输入1-4" ;;
        esac
    done
    
    # 密码认证配置
    echo ""
    echo -e "${CYAN}密码认证配置:${WHITE}"
    echo "1. no - 禁用密码认证，仅使用密钥 (推荐)"
    echo "2. yes - 允许密码认证"
    
    while true; do
        read -p "请选择密码认证方式 [1-2, 默认: 1]: " pwd_choice
        
        case "${pwd_choice:-1}" in
            1) PASSWORD_AUTH="no"; break ;;
            2) 
                log_warning "允许密码认证可能存在暴力破解风险！"
                read -p "确认要允许密码认证吗？(y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    PASSWORD_AUTH="yes"
                    break
                fi
                ;;
            *) log_error "无效选择，请输入1-2" ;;
        esac
    done
}

# 生成安全的SSH配置
generate_ssh_config() {
    log_info "生成SSH安全配置文件..."
    
    cat > "$CUSTOM_CONFIG" << EOF
# SSH安全配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 配置说明: 此文件优先级高于主配置文件和其他配置文件
#
# 重要提醒:
# 1. 此配置禁用了密码认证，请确保已配置SSH密钥
# 2. 修改了SSH端口，请更新防火墙规则
# 3. 重启SSH服务前请先测试配置有效性

# === 基本连接设置 ===
Port $SSH_PORT
Protocol 2
AddressFamily any

# === 认证设置 ===
# 公钥认证
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# 密码认证设置
PasswordAuthentication $PASSWORD_AUTH
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Root登录设置
PermitRootLogin $ROOT_LOGIN

# 基础安全设置
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes

# === 连接安全限制 ===
# 认证尝试限制
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60

# 登录时间限制
LoginGraceTime 60

# 连接保活设置
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes

# === 功能控制 ===
# X11转发 (根据需要启用)
X11Forwarding no
X11DisplayOffset 10
X11UseLocalhost yes

# 端口转发
AllowTcpForwarding yes
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# === 性能优化 ===
UseDNS no
GSSAPIAuthentication no
Compression no

# === 现代加密算法 (仅允许安全算法) ===
# 密钥交换算法
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512

# 加密算法
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# MAC算法
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# 主机密钥算法
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256

# === 日志设置 ===
SyslogFacility AUTH
LogLevel INFO

# === 其他安全设置 ===
# 严格模式
StrictModes yes

# 打印信息
PrintMotd no
PrintLastLog yes

# Banner (可选)
# Banner /etc/ssh/banner

EOF
    
    # 设置文件权限
    chmod 644 "$CUSTOM_CONFIG"
    chown root:root "$CUSTOM_CONFIG"
    
    log_success "SSH配置文件已生成: $CUSTOM_CONFIG"
}

# 验证SSH配置
test_ssh_config() {
    log_info "验证SSH配置语法..."
    
    if sshd -t; then
        log_success "SSH配置语法验证通过"
        return 0
    else
        log_error "SSH配置语法验证失败"
        echo "错误详情:"
        sshd -t
        return 1
    fi
}

# 显示配置变更
show_config_changes() {
    echo -e "${CYAN}=== SSH配置变更摘要 ===${WHITE}"
    
    local old_port=$(grep -E '^port ' "$BACKUP_DIR/sshd_config.d.backup/99-security-hardening.conf" 2>/dev/null | awk '{print $2}' || echo "22")
    local new_port="$SSH_PORT"
    
    echo "端口变更: $old_port -> $new_port"
    echo "Root登录: $ROOT_LOGIN"
    echo "密码认证: $PASSWORD_AUTH"
    echo "配置文件: $CUSTOM_CONFIG"
    echo "备份位置: $BACKUP_DIR"
    echo ""
}

# 更新防火墙规则
update_firewall() {
    log_info "更新防火墙规则..."
    
    # 检查UFW
    if command -v ufw >/dev/null 2>&1; then
        log_info "检测到UFW防火墙"
        
        # 添加新端口规则
        if ufw allow "$SSH_PORT/tcp" comment "SSH"; then
            log_success "已添加UFW规则: 允许端口 $SSH_PORT"
        else
            log_warning "添加UFW规则失败"
        fi
        
        # 显示当前状态
        echo "当前UFW状态:"
        ufw status numbered
        
    # 检查firewalld
    elif command -v firewall-cmd >/dev/null 2>&1; then
        log_info "检测到firewalld防火墙"
        
        # 添加新端口规则
        if firewall-cmd --permanent --add-port="$SSH_PORT/tcp"; then
            firewall-cmd --reload
            log_success "已添加firewalld规则: 允许端口 $SSH_PORT"
        else
            log_warning "添加firewalld规则失败"
        fi
        
    # 检查iptables
    elif command -v iptables >/dev/null 2>&1; then
        log_info "检测到iptables防火墙"
        log_warning "请手动添加iptables规则: iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT"
        
    else
        log_warning "未检测到防火墙，请手动配置防火墙规则允许端口 $SSH_PORT"
    fi
}

# 重启SSH服务
restart_ssh_service() {
    echo -e "${YELLOW}=== SSH服务重启 ===${WHITE}"
    echo "配置已完成，需要重启SSH服务使配置生效。"
    echo ""
    echo -e "${RED}重要警告:${WHITE}"
    echo "1. 重启SSH服务前，请确保已配置好SSH密钥"
    echo "2. 建议在另一个终端测试新配置: ssh -p $SSH_PORT user@hostname"
    echo "3. 如果配置有问题，可以通过控制台或其他方式访问服务器"
    echo "4. 备份文件位于: $BACKUP_DIR"
    echo ""
    
    read -p "确认重启SSH服务？(y/N): " confirm_restart
    
    if [[ "$confirm_restart" =~ ^[Yy]$ ]]; then
        log_info "重启SSH服务..."
        
        # 检测SSH服务名称
        local ssh_service
        if systemctl list-unit-files | grep -q "^sshd.service"; then
            ssh_service="sshd"
        elif systemctl list-unit-files | grep -q "^ssh.service"; then
            ssh_service="ssh"
        else
            log_error "无法检测SSH服务名称"
            return 1
        fi
        
        if systemctl restart "$ssh_service"; then
            log_success "SSH服务重启成功"
            
            # 检查服务状态
            if systemctl is-active "$ssh_service" >/dev/null; then
                log_success "SSH服务运行正常"
            else
                log_error "SSH服务重启后状态异常"
                systemctl status "$ssh_service"
            fi
        else
            log_error "SSH服务重启失败"
            return 1
        fi
    else
        log_warning "SSH服务未重启，请手动重启: systemctl restart sshd"
        echo "或者: systemctl restart ssh"
    fi
}

# 测试新SSH连接
test_ssh_connection() {
    echo -e "${CYAN}=== SSH连接测试指南 ===${WHITE}"
    echo ""
    echo "在断开当前连接前，请在新终端中测试SSH连接:"
    echo ""
    echo -e "${GREEN}测试命令示例:${WHITE}"
    echo "ssh -p $SSH_PORT root@$(hostname -I | awk '{print $1}')"
    echo "或者:"
    echo "ssh -p $SSH_PORT your_username@your_server_ip"
    echo ""
    echo -e "${YELLOW}连接测试检查项:${WHITE}"
    echo "1. 能否成功连接到新端口"
    echo "2. 密钥认证是否正常工作"
    echo "3. Root登录权限是否符合预期"
    echo "4. 新配置是否生效"
    echo ""
    echo -e "${RED}如果连接失败:${WHITE}"
    echo "1. 检查防火墙是否允许新端口"
    echo "2. 确认SSH密钥配置正确"
    echo "3. 可以通过控制台访问服务器进行修复"
    echo "4. 配置备份位于: $BACKUP_DIR"
}

# 生成SSH密钥 (如果需要)
generate_ssh_key() {
    if [[ "$PASSWORD_AUTH" == "no" ]]; then
        echo -e "${CYAN}=== SSH密钥检查 ===${WHITE}"
        
        # 检查是否已有密钥
        if [[ -f ~/.ssh/id_ed25519 ]] || [[ -f ~/.ssh/id_rsa ]]; then
            log_success "检测到现有SSH密钥"
            return 0
        fi
        
        read -p "未检测到SSH密钥，是否生成新的密钥？(y/N): " generate_key
        
        if [[ "$generate_key" =~ ^[Yy]$ ]]; then
            log_info "生成ED25519密钥..."
            
            # 创建.ssh目录
            mkdir -p ~/.ssh
            chmod 700 ~/.ssh
            
            # 生成密钥
            ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -C "Generated for SSH security $(date +%Y%m%d)"
            
            # 设置权限
            chmod 600 ~/.ssh/id_ed25519
            chmod 644 ~/.ssh/id_ed25519.pub
            
            log_success "SSH密钥生成完成"
            echo ""
            echo -e "${CYAN}公钥内容 (请添加到目标服务器的 ~/.ssh/authorized_keys):${WHITE}"
            cat ~/.ssh/id_ed25519.pub
        fi
    fi
}

# 主函数
main() {
    echo -e "${PURPLE}${BOLD}=== SSH安全配置脚本 ===${WHITE}"
    echo "专门处理SSH端口修改和安全配置"
    echo "包括云服务商配置冲突处理"
    echo ""
    
    # 检查权限
    check_root
    
    # 创建备份
    create_backup
    
    # 备份现有配置
    backup_ssh_configs
    
    # 检查当前配置
    get_current_ssh_config
    
    # 处理云服务商配置冲突
    handle_cloud_configs
    
    # 获取用户配置偏好
    get_ssh_preferences
    
    # 生成SSH密钥 (如果需要)
    generate_ssh_key
    
    # 生成新的SSH配置
    generate_ssh_config
    
    # 验证配置
    if ! test_ssh_config; then
        log_error "配置验证失败，正在恢复备份..."
        rm -f "$CUSTOM_CONFIG"
        exit 1
    fi
    
    # 显示配置变更
    show_config_changes
    
    # 更新防火墙规则
    update_firewall
    
    # 重启SSH服务
    restart_ssh_service
    
    # 显示测试指南
    test_ssh_connection
    
    echo ""
    log_success "SSH配置完成！"
    echo -e "${GREEN}重要信息:${WHITE}"
    echo "• SSH端口: $SSH_PORT"
    echo "• Root登录: $ROOT_LOGIN" 
    echo "• 密码认证: $PASSWORD_AUTH"
    echo "• 配置文件: $CUSTOM_CONFIG"
    echo "• 备份位置: $BACKUP_DIR"
}

# 运行主函数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi