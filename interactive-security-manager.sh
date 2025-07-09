#!/bin/bash

# Linux VPS 交互式安全管理脚本
# 版本: 2.0.0
# 作者: 系统安全专家
# 功能: 模块化安全加固、交互式管理、一键部署
# 特性: 用户友好、健壮性设计、动态端口检测
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
readonly SCRIPT_VERSION="2.0.0"
readonly CONFIG_DIR="/etc/security-manager"
readonly CONFIG_FILE="${CONFIG_DIR}/config.conf"
readonly BACKUP_DIR="/root/security-backups"
readonly SSH_CUSTOM_CONFIG="/etc/ssh/sshd_config.d/99-security.conf"
readonly FAIL2BAN_CONFIG="/etc/fail2ban/jail.local"

# 配置变量
ROOT_LOGIN_POLICY="prohibit-password"  # 默认允许root密钥登录
NEW_SSH_PORT=""
CURRENT_SSH_PORT=""

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

# 动态检测当前SSH端口
detect_current_ssh_port() {
    local port=""
    
    # 方法1: 使用 sshd -T 获取当前生效配置
    if command -v sshd &> /dev/null; then
        port=$(sshd -T 2>/dev/null | grep -i '^port' | awk '{print $2}')
    fi
    
    # 方法2: 检查自定义配置文件
    if [[ -z "$port" && -f "$SSH_CUSTOM_CONFIG" ]]; then
        port=$(grep -E "^Port " "$SSH_CUSTOM_CONFIG" 2>/dev/null | awk '{print $2}')
    fi
    
    # 方法3: 检查主配置文件
    if [[ -z "$port" ]]; then
        port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    fi
    
    # 默认端口
    if [[ -z "$port" ]]; then
        port="22"
    fi
    
    echo "$port"
}

# 端口验证函数
validate_port() {
    local port=$1
    
    # 检查是否为纯数字
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # 检查端口范围
    if [[ $port -lt 1024 || $port -gt 65535 ]]; then
        return 1
    fi
    
    # 检查端口是否已被占用
    if ss -tlun | grep -q ":$port "; then
        return 1
    fi
    
    return 0
}

# 获取SSH服务名称
get_ssh_service_name() {
    if systemctl list-unit-files | grep -q "^sshd.service"; then
        echo "sshd"
    elif systemctl list-unit-files | grep -q "^ssh.service"; then
        echo "ssh"
    else
        log_error "未找到SSH服务"
        return 1
    fi
}

# 创建备份
create_backup() {
    local backup_name="backup_$(date +%Y%m%d_%H%M%S)"
    local backup_path="${BACKUP_DIR}/${backup_name}"
    
    log_info "创建配置备份..."
    mkdir -p "$backup_path"
    
    # 备份关键配置文件
    [[ -f "/etc/ssh/sshd_config" ]] && cp "/etc/ssh/sshd_config" "$backup_path/"
    [[ -f "$SSH_CUSTOM_CONFIG" ]] && cp "$SSH_CUSTOM_CONFIG" "$backup_path/"
    [[ -f "/etc/fail2ban/jail.conf" ]] && cp "/etc/fail2ban/jail.conf" "$backup_path/"
    [[ -f "$FAIL2BAN_CONFIG" ]] && cp "$FAIL2BAN_CONFIG" "$backup_path/"
    
    log_success "备份已创建: $backup_path"
}

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    Linux VPS 安全管理脚本 v${SCRIPT_VERSION}              ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  1. 安全加固 SSH 服务                                            ║${NC}"
    echo -e "${WHITE}║  2. 安装并配置 Fail2ban                                          ║${NC}"
    echo -e "${WHITE}║  3. 配置 UFW 防火墙                                              ║${NC}"
    echo -e "${WHITE}║  4. [一键执行] 完成以上所有初始安全设置                          ║${NC}"
    echo -e "${WHITE}║  5. [管理] 管理 Fail2ban (查看状态/解封IP)                       ║${NC}"
    echo -e "${WHITE}║  6. [管理] 管理 UFW 防火墙 (查看/添加/删除规则)                  ║${NC}"
    echo -e "${WHITE}║  0. 退出脚本                                                     ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# 处理云服务商SSH配置
handle_cloud_ssh_configs() {
    log_info "检查并处理云服务商SSH配置文件..."
    
    # 查找云服务商配置文件
    local cloud_configs=$(find /etc/ssh/sshd_config.d/ -name "*cloud*" -o -name "*50-*" 2>/dev/null)
    
    if [[ -n "$cloud_configs" ]]; then
        log_warn "发现云服务商SSH配置文件，正在备份..."
        
        while IFS= read -r config_file; do
            if [[ -f "$config_file" ]]; then
                local backup_name="${config_file}.backup"
                log_info "备份 $config_file -> $backup_name"
                mv "$config_file" "$backup_name"
            fi
        done <<< "$cloud_configs"
        
        log_success "云服务商配置文件已备份"
    else
        log_info "未发现云服务商SSH配置文件"
    fi
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

# SSH安全加固
harden_ssh() {
    echo ""
    echo -e "${CYAN}=== SSH 安全加固 ===${NC}"
    echo ""
    
    # 创建备份
    create_backup
    
    # 获取当前SSH端口
    CURRENT_SSH_PORT=$(detect_current_ssh_port)
    log_info "当前SSH端口: $CURRENT_SSH_PORT"
    
    # 获取新端口
    while true; do
        read -p "请输入新的SSH端口 (1024-65535) [默认: 22222]: " NEW_SSH_PORT
        NEW_SSH_PORT=${NEW_SSH_PORT:-22222}
        
        if validate_port "$NEW_SSH_PORT"; then
            log_success "新SSH端口设置为: $NEW_SSH_PORT"
            break
        else
            if [[ ! "$NEW_SSH_PORT" =~ ^[0-9]+$ ]]; then
                log_error "端口必须是数字"
            elif [[ $NEW_SSH_PORT -lt 1024 || $NEW_SSH_PORT -gt 65535 ]]; then
                log_error "端口必须在 1024-65535 范围内"
            else
                log_error "端口 $NEW_SSH_PORT 已被占用"
            fi
            log_info "请重新输入一个有效的端口号"
        fi
    done
    
    # 处理云服务商配置
    handle_cloud_ssh_configs
    
    # 检查SSH密钥配置
    check_ssh_keys
    
    # 生成SSH安全配置
    log_info "生成SSH安全配置..."
    mkdir -p /etc/ssh/sshd_config.d/
    
    cat > "$SSH_CUSTOM_CONFIG" << EOF
# SSH安全加固配置 - 由安全管理脚本生成
# 生成时间: $(date)

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
    
    chmod 644 "$SSH_CUSTOM_CONFIG"
    
    # 测试SSH配置
    log_info "测试SSH配置文件语法..."
    if sshd -t; then
        log_success "SSH配置文件语法正确"
    else
        log_error "SSH配置文件语法错误，恢复备份..."
        rm -f "$SSH_CUSTOM_CONFIG"
        return 1
    fi
    
    # 重启SSH服务
    log_info "重启SSH服务..."
    local ssh_service=$(get_ssh_service_name)
    
    if systemctl reload "$ssh_service"; then
        sleep 2
        if ss -tlnp | grep -q ":$NEW_SSH_PORT "; then
            log_success "SSH服务重启成功，新端口已生效"
        else
            log_warn "端口可能未生效，尝试完全重启..."
            systemctl restart "$ssh_service"
            sleep 2
        fi
    else
        log_error "SSH服务重启失败"
        return 1
    fi
    
    # 保存配置
    mkdir -p "$CONFIG_DIR"
    echo "SSH_PORT=$NEW_SSH_PORT" > "$CONFIG_FILE"
    
    # 最终确认和警告
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                        SSH 加固完成！                           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}配置摘要:${NC}"
    echo "- SSH端口: $CURRENT_SSH_PORT → $NEW_SSH_PORT"
    echo "- 密码认证: 已禁用"
    echo "- 密钥认证: 已启用"
    if [[ "$ROOT_LOGIN_POLICY" == "prohibit-password" ]]; then
        echo "- Root登录: 仅限密钥"
    else
        echo "- Root登录: 已禁用"
    fi
    echo ""
    
    echo -e "${RED}重要警告:${NC}"
    echo -e "${RED}1. SSH端口已更改为 $NEW_SSH_PORT${NC}"
    echo -e "${RED}2. 请立即测试新端口连接: ssh -p $NEW_SSH_PORT user@server${NC}"
    echo -e "${RED}3. 请确保防火墙允许端口 $NEW_SSH_PORT${NC}"
    echo -e "${RED}4. 在断开当前连接前，请务必测试新端口！${NC}"
    echo ""
    
    read -p "按回车键继续..."
}

# 安装并配置Fail2ban
install_fail2ban() {
    echo ""
    echo -e "${CYAN}=== 安装并配置 Fail2ban ===${NC}"
    echo ""
    
    # 检查是否已安装
    if command -v fail2ban-server &> /dev/null; then
        log_info "Fail2ban已安装，跳过安装步骤"
    else
        log_info "安装Fail2ban..."
        
        if command -v apt &> /dev/null; then
            apt update -y
            apt install -y fail2ban
        elif command -v yum &> /dev/null; then
            yum install -y epel-release
            yum install -y fail2ban
        else
            log_error "不支持的包管理器"
            return 1
        fi
        
        log_success "Fail2ban安装完成"
    fi
    
    # 动态检测SSH端口
    local ssh_port="${NEW_SSH_PORT:-$(detect_current_ssh_port)}"
    log_info "检测到SSH端口: $ssh_port"
    
    # 生成Fail2ban配置
    log_info "生成Fail2ban配置..."
    cat > "$FAIL2BAN_CONFIG" << EOF
# Fail2ban自定义配置 - 由安全管理脚本生成
# 生成时间: $(date)

[DEFAULT]
# 忽略的IP地址
ignoreip = 127.0.0.1/8 ::1

# 封禁时间 (秒) - 10分钟
bantime = 600

# 查找时间窗口 (秒) - 5分钟
findtime = 300

# 最大重试次数
maxretry = 5

[sshd]
# 启用SSH保护
enabled = true

# 监控的SSH端口
port = $ssh_port

# 过滤器
filter = sshd

# 日志文件位置
logpath = /var/log/auth.log

# SSH特定设置
maxretry = 5
findtime = 300
bantime = 600
EOF
    
    chmod 644 "$FAIL2BAN_CONFIG"
    
    # 启动Fail2ban服务
    log_info "启动Fail2ban服务..."
    systemctl start fail2ban
    systemctl enable fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        log_success "Fail2ban服务启动成功"
        
        # 显示状态
        echo ""
        log_info "Fail2ban状态:"
        fail2ban-client status
        
        echo ""
        log_info "SSH保护状态:"
        fail2ban-client status sshd 2>/dev/null || log_info "SSH规则将在首次检测到失败登录时激活"
    else
        log_error "Fail2ban服务启动失败"
        return 1
    fi
    
    echo ""
    log_success "Fail2ban配置完成"
    echo "- SSH端口: $ssh_port"
    echo "- 最大重试: 5次"
    echo "- 封禁时间: 10分钟"
    echo "- 查找窗口: 5分钟"
    echo ""
    
    read -p "按回车键继续..."
}

# 配置UFW防火墙
configure_ufw() {
    echo ""
    echo -e "${CYAN}=== 配置 UFW 防火墙 ===${NC}"
    echo ""
    
    # 检查UFW是否安装
    if ! command -v ufw &> /dev/null; then
        log_info "安装UFW..."
        
        if command -v apt &> /dev/null; then
            apt install -y ufw
        elif command -v yum &> /dev/null; then
            yum install -y ufw
        else
            log_error "不支持的包管理器"
            return 1
        fi
        
        log_success "UFW安装完成"
    else
        log_info "UFW已安装"
    fi
    
    # 动态检测SSH端口
    local ssh_port="${NEW_SSH_PORT:-$(detect_current_ssh_port)}"
    log_info "检测到SSH端口: $ssh_port"
    
    # 显示即将执行的操作
    echo ""
    echo -e "${YELLOW}即将执行的防火墙配置:${NC}"
    echo "1. 允许SSH端口: $ssh_port/tcp"
    echo "2. 允许HTTP端口: 80/tcp"
    echo "3. 允许HTTPS端口: 443/tcp"
    echo "4. 设置默认策略: 拒绝入站，允许出站"
    echo "5. 启用UFW防火墙"
    echo ""
    
    # 用户确认
    echo -e "${RED}警告: 启用防火墙可能会断开未授权的连接！${NC}"
    echo -e "${RED}请确保SSH端口 $ssh_port 正确无误！${NC}"
    echo ""
    
    read -p "确认要继续配置防火墙吗? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "防火墙配置已取消"
        return 0
    fi
    
    # 执行防火墙配置
    log_info "配置UFW防火墙..."
    
    # 重要：先允许SSH端口
    log_info "步骤1: 允许SSH端口 $ssh_port"
    ufw allow "$ssh_port/tcp"
    
    # 设置默认策略
    log_info "步骤2: 设置默认策略"
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许常用端口
    log_info "步骤3: 允许HTTP和HTTPS端口"
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # 询问是否需要其他端口
    echo ""
    read -p "是否需要开放其他端口? (y/n): " add_ports
    if [[ "$add_ports" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "请输入端口号 (直接回车结束): " port
            if [[ -z "$port" ]]; then
                break
            fi
            
            if [[ "$port" =~ ^[0-9]+$ ]] && [[ $port -ge 1 && $port -le 65535 ]]; then
                read -p "协议 (tcp/udp) [默认tcp]: " protocol
                protocol=${protocol:-tcp}
                ufw allow "$port/$protocol"
                log_info "已添加端口: $port/$protocol"
            else
                log_error "无效的端口号"
            fi
        done
    fi
    
    # 启用防火墙
    log_info "步骤4: 启用UFW防火墙"
    ufw --force enable
    
    # 设置开机自启
    systemctl enable ufw
    
    # 显示状态
    echo ""
    log_success "UFW防火墙配置完成"
    echo ""
    log_info "防火墙状态:"
    ufw status verbose
    
    echo ""
    read -p "按回车键继续..."
}

# 一键执行所有安全设置
run_all_hardening() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    一键安全加固开始                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_info "开始执行完整的安全加固流程..."
    log_info "执行顺序: SSH加固 → UFW防火墙 → Fail2ban"
    echo ""
    
    # 第一步：SSH加固
    log_info "步骤 1/3: SSH 安全加固"
    if ! harden_ssh; then
        log_error "SSH加固失败，停止执行"
        return 1
    fi
    
    # 第二步：UFW防火墙
    log_info "步骤 2/3: UFW 防火墙配置"
    if ! configure_ufw; then
        log_error "UFW配置失败，停止执行"
        return 1
    fi
    
    # 第三步：Fail2ban
    log_info "步骤 3/3: Fail2ban 配置"
    if ! install_fail2ban; then
        log_error "Fail2ban配置失败，停止执行"
        return 1
    fi
    
    # 完成总结
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    一键安全加固完成！                            ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_success "所有安全设置已完成"
    echo ""
    echo -e "${CYAN}配置摘要:${NC}"
    
    local ssh_port="${NEW_SSH_PORT:-$(detect_current_ssh_port)}"
    echo "- SSH端口: $ssh_port (密钥认证)"
    if [[ "$ROOT_LOGIN_POLICY" == "prohibit-password" ]]; then
        echo "- Root登录: 仅限密钥"
    else
        echo "- Root登录: 已禁用"
    fi
    echo "- UFW防火墙: 已启用"
    echo "- Fail2ban: 已启用"
    echo ""
    
    echo -e "${RED}重要提醒:${NC}"
    echo -e "${RED}1. 请立即测试SSH连接: ssh -p $ssh_port user@server${NC}"
    echo -e "${RED}2. 确保拥有SSH密钥文件${NC}"
    echo -e "${RED}3. 在断开连接前务必测试新端口！${NC}"
    echo ""
    
    read -p "按回车键继续..."
}

# 管理Fail2ban
manage_fail2ban() {
    while true; do
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    Fail2ban 管理菜单                            ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${WHITE}║  1. 查看 Fail2ban 服务状态                                       ║${NC}"
        echo -e "${WHITE}║  2. 查看所有被封禁的 IP                                          ║${NC}"
        echo -e "${WHITE}║  3. 解封一个指定的 IP                                            ║${NC}"
        echo -e "${WHITE}║  0. 返回主菜单                                                   ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "请选择 [1-3,0]: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}=== Fail2ban 服务状态 ===${NC}"
                echo ""
                
                if systemctl is-active --quiet fail2ban; then
                    log_success "Fail2ban服务运行正常"
                    echo ""
                    
                    log_info "整体状态:"
                    fail2ban-client status
                    
                    echo ""
                    log_info "SSH保护详情:"
                    fail2ban-client status sshd 2>/dev/null || log_warn "SSH规则未激活"
                else
                    log_error "Fail2ban服务未运行"
                    read -p "是否要启动Fail2ban服务? (y/n): " start_service
                    if [[ "$start_service" =~ ^[Yy]$ ]]; then
                        systemctl start fail2ban
                        log_success "Fail2ban服务已启动"
                    fi
                fi
                
                echo ""
                read -p "按回车键继续..."
                ;;
            2)
                echo ""
                echo -e "${CYAN}=== 被封禁的 IP 地址 ===${NC}"
                echo ""
                
                if systemctl is-active --quiet fail2ban; then
                    local banned_ips=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:" | cut -d: -f2 | xargs)
                    
                    if [[ -n "$banned_ips" && "$banned_ips" != "" ]]; then
                        log_info "当前被封禁的IP地址:"
                        echo "$banned_ips" | tr ' ' '\n' | nl -w3 -s'. '
                    else
                        log_info "当前没有被封禁的IP地址"
                    fi
                else
                    log_error "Fail2ban服务未运行"
                fi
                
                echo ""
                read -p "按回车键继续..."
                ;;
            3)
                echo ""
                echo -e "${CYAN}=== 解封 IP 地址 ===${NC}"
                echo ""
                
                if ! systemctl is-active --quiet fail2ban; then
                    log_error "Fail2ban服务未运行"
                    read -p "按回车键继续..."
                    continue
                fi
                
                # 显示当前被封禁的IP
                local banned_ips=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:" | cut -d: -f2 | xargs)
                
                if [[ -n "$banned_ips" && "$banned_ips" != "" ]]; then
                    log_info "当前被封禁的IP地址:"
                    echo "$banned_ips" | tr ' ' '\n' | nl -w3 -s'. '
                    echo ""
                else
                    log_info "当前没有被封禁的IP地址"
                    read -p "按回车键继续..."
                    continue
                fi
                
                # 获取要解封的IP
                read -p "请输入要解封的IP地址: " ip_to_unban
                
                # 验证IP地址格式
                if [[ ! "$ip_to_unban" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                    log_error "无效的IP地址格式"
                    read -p "按回车键继续..."
                    continue
                fi
                
                # 确认操作
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
                
                echo ""
                read -p "按回车键继续..."
                ;;
            0)
                return 0
                ;;
            *)
                log_error "无效选择，请输入 1-3 或 0"
                sleep 2
                ;;
        esac
    done
}

# 管理UFW防火墙
manage_ufw() {
    while true; do
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    UFW 防火墙管理菜单                           ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${WHITE}║  1. 查看 UFW 状态和规则                                          ║${NC}"
        echo -e "${WHITE}║  2. 允许一个新端口                                              ║${NC}"
        echo -e "${WHITE}║  3. 删除一条现有规则                                            ║${NC}"
        echo -e "${WHITE}║  0. 返回主菜单                                                   ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "请选择 [1-3,0]: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}=== UFW 防火墙状态 ===${NC}"
                echo ""
                
                if command -v ufw &> /dev/null; then
                    ufw status verbose
                else
                    log_error "UFW未安装"
                fi
                
                echo ""
                read -p "按回车键继续..."
                ;;
            2)
                echo ""
                echo -e "${CYAN}=== 添加防火墙规则 ===${NC}"
                echo ""
                
                # 获取端口号
                read -p "请输入要允许的端口号 (1-65535): " port
                
                # 验证端口号
                if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 || $port -gt 65535 ]]; then
                    log_error "无效的端口号"
                    read -p "按回车键继续..."
                    continue
                fi
                
                # 获取协议
                read -p "协议 (tcp/udp) [默认tcp]: " protocol
                protocol=${protocol:-tcp}
                
                # 验证协议
                if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
                    log_error "无效的协议，只支持tcp或udp"
                    read -p "按回车键继续..."
                    continue
                fi
                
                # 预览规则
                echo ""
                echo -e "${YELLOW}即将添加规则: 允许 $port/$protocol${NC}"
                read -p "确认要添加这条规则吗? (y/n): " confirm
                
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    if ufw allow "$port/$protocol"; then
                        log_success "规则已成功添加: $port/$protocol"
                    else
                        log_error "添加规则失败"
                    fi
                else
                    log_info "添加规则已取消"
                fi
                
                echo ""
                read -p "按回车键继续..."
                ;;
            3)
                echo ""
                echo -e "${CYAN}=== 删除防火墙规则 ===${NC}"
                echo ""
                
                # 显示编号规则
                log_info "当前防火墙规则:"
                ufw status numbered
                
                echo ""
                read -p "请输入要删除的规则编号: " rule_number
                
                # 验证编号
                if [[ ! "$rule_number" =~ ^[0-9]+$ ]]; then
                    log_error "无效的规则编号"
                    read -p "按回车键继续..."
                    continue
                fi
                
                # 获取规则详情 - 更健壮的检测方法
                local rule_info=$(ufw status numbered | awk "/\\[ *$rule_number\\]/ {print \$0}")
                
                if [[ -z "$rule_info" ]]; then
                    log_error "规则编号 $rule_number 不存在"
                    log_info "当前可用的规则编号:"
                    ufw status numbered | grep "\\[" | awk '{print $1}' | tr -d '[]'
                    read -p "按回车键继续..."
                    continue
                fi
                
                # 确认删除
                echo ""
                echo -e "${YELLOW}即将删除规则: $rule_info${NC}"
                echo -e "${RED}警告: 删除规则可能会影响网络连接！${NC}"
                read -p "确认要删除这条规则吗? (y/n): " confirm
                
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    if echo "y" | ufw delete "$rule_number"; then
                        log_success "规则已成功删除"
                    else
                        log_error "删除规则失败"
                    fi
                else
                    log_info "删除规则已取消"
                fi
                
                echo ""
                read -p "按回车键继续..."
                ;;
            0)
                return 0
                ;;
            *)
                log_error "无效选择，请输入 1-3 或 0"
                sleep 2
                ;;
        esac
    done
}

# 主函数
main() {
    # 检查权限和系统
    check_root
    check_system
    
    # 主循环
    while true; do
        show_main_menu
        read -p "请选择 [1-6,0]: " choice
        
        case $choice in
            1)
                harden_ssh
                ;;
            2)
                install_fail2ban
                ;;
            3)
                configure_ufw
                ;;
            4)
                run_all_hardening
                ;;
            5)
                manage_fail2ban
                ;;
            6)
                manage_ufw
                ;;
            0)
                echo ""
                log_info "感谢使用Linux VPS安全管理脚本！"
                echo ""
                exit 0
                ;;
            *)
                log_error "无效选择，请输入 1-6 或 0"
                sleep 2
                ;;
        esac
    done
}

# 运行主程序
main "$@"