#!/bin/bash

# ========================================
# VPS 安全加固脚本 v1.0
# 作者: VPS Security Team
# 描述: 全面的VPS安全加固工具，提供系统安全配置和管理功能
# 使用: bash vps-security.sh
# ========================================

set -euo pipefail

# ========================================
# 全局变量和配置
# ========================================

SCRIPT_VERSION="1.0"
SCRIPT_NAME="VPS Security Hardening Tool"
CONFIG_DIR="/etc/vps-security"
CONFIG_FILE="$CONFIG_DIR/config.ini"
BACKUP_DIR="$CONFIG_DIR/backups"
LOG_FILE="$CONFIG_DIR/security.log"

# ========================================
# 颜色定义
# ========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ========================================
# 日志和输出函数
# ========================================

log_info() {
    local message="$1"
    echo -e "${BLUE}[INFO]${NC} $message"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $message" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    local message="$1"
    echo -e "${GREEN}[SUCCESS]${NC} $message"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $message" >> "$LOG_FILE" 2>/dev/null || true
}

log_warn() {
    local message="$1"
    echo -e "${YELLOW}[WARNING]${NC} $message"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $message" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    local message="$1"
    echo -e "${RED}[ERROR]${NC} $message" >&2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $message" >> "$LOG_FILE" 2>/dev/null || true
}

log_debug() {
    local message="$1"
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $message"
        echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# ========================================
# 系统检测和验证函数
# ========================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        log_info "请使用: sudo bash $0"
        exit 1
    fi
}

check_system() {
    log_info "检测系统环境..."
    
    # 检测操作系统
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        log_info "检测到系统: $PRETTY_NAME"
    else
        log_error "无法检测操作系统版本"
        exit 1
    fi
    
    # 检查支持的系统
    case $OS in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            SERVICE_MANAGER="systemctl"
            ;;
        centos|rhel|fedora)
            PACKAGE_MANAGER="yum"
            SERVICE_MANAGER="systemctl"
            ;;
        *)
            log_warn "未完全测试的系统: $OS"
            log_warn "脚本可能无法正常工作"
            read -p "是否继续? (y/N): " continue_anyway
            if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    log_success "系统检测完成"
}

check_internet() {
    log_info "检查网络连接..."
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log_success "网络连接正常"
        return 0
    else
        log_error "网络连接失败，请检查网络设置"
        return 1
    fi
}

# ========================================
# 配置文件管理
# ========================================

init_config() {
    log_info "初始化配置目录..."
    
    # 创建配置目录
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # 设置权限
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$BACKUP_DIR"
    
    # 创建日志文件
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    
    # 创建默认配置文件
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
# VPS Security Configuration
[SYSTEM]
OS=$OS
OS_VERSION=$OS_VERSION
SCRIPT_VERSION=$SCRIPT_VERSION
INSTALL_DATE=$(date '+%Y-%m-%d %H:%M:%S')

[SSH]
SSH_PORT=22
SSH_KEY_TYPE=rsa
SSH_KEY_BITS=4096
ROOT_LOGIN=yes
PASSWORD_AUTH=yes

[FIREWALL]
UFW_ENABLED=no
DEFAULT_POLICY=deny

[FAIL2BAN]
FAIL2BAN_ENABLED=no
MAX_RETRY=5
BAN_TIME=600

[USER]
ADMIN_USER=
ADMIN_USER_CREATED=no
EOF
        chmod 600 "$CONFIG_FILE"
        log_success "配置文件已创建: $CONFIG_FILE"
    fi
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # 读取配置文件
        while IFS='=' read -r key value; do
            # 跳过注释和空行
            [[ $key =~ ^[[:space:]]*# ]] && continue
            [[ $key =~ ^[[:space:]]*$ ]] && continue
            [[ $key =~ ^\[.*\]$ ]] && continue
            
            # 去除空格并导出变量
            key=$(echo "$key" | tr -d '[:space:]')
            value=$(echo "$value" | tr -d '[:space:]')
            if [[ -n "$key" && -n "$value" ]]; then
                export "$key"="$value"
            fi
        done < "$CONFIG_FILE"
        return 0
    else
        log_warn "配置文件不存在，将使用默认配置"
        return 1
    fi
}

save_config() {
    log_info "保存配置..."
    # 这里将在后续实现具体的配置保存逻辑
    log_success "配置已保存"
}

# ========================================
# 备份和恢复函数
# ========================================

backup_file() {
    local file_path="$1"
    local backup_name="$2"
    
    if [[ -f "$file_path" ]]; then
        local backup_path="$BACKUP_DIR/${backup_name}_$(date +%Y%m%d_%H%M%S).backup"
        cp "$file_path" "$backup_path"
        log_success "已备份: $file_path -> $backup_path"
        echo "$backup_path"
    else
        log_warn "文件不存在，无法备份: $file_path"
        return 1
    fi
}

# ========================================
# 错误处理和清理函数
# ========================================

cleanup() {
    log_info "执行清理操作..."
    # 清理临时文件等
}

error_exit() {
    local error_message="$1"
    log_error "$error_message"
    cleanup
    exit 1
}

# 设置错误处理
trap 'error_exit "脚本执行过程中发生错误，行号: $LINENO"' ERR
trap cleanup EXIT

# ========================================
# 工具函数
# ========================================

check_command() {
    local cmd="$1"
    if command -v "$cmd" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

install_package() {
    local package="$1"
    log_info "安装软件包: $package"
    
    case $PACKAGE_MANAGER in
        apt)
            apt update -qq
            apt install -y "$package"
            ;;
        yum)
            yum install -y "$package"
            ;;
        *)
            log_error "不支持的包管理器: $PACKAGE_MANAGER"
            return 1
            ;;
    esac
    
    log_success "软件包安装完成: $package"
}

service_control() {
    local action="$1"
    local service="$2"
    
    case $SERVICE_MANAGER in
        systemctl)
            systemctl "$action" "$service"
            ;;
        *)
            log_error "不支持的服务管理器: $SERVICE_MANAGER"
            return 1
            ;;
    esac
}

# ========================================
# 主程序初始化
# ========================================

init_script() {
    log_info "初始化 $SCRIPT_NAME v$SCRIPT_VERSION"
    
    # 检查系统环境
    check_root
    check_system
    
    # 初始化配置
    init_config
    load_config
    
    # 检查网络连接
    if ! check_internet; then
        log_warn "网络连接异常，某些功能可能无法正常使用"
    fi
    
    log_success "脚本初始化完成"
}

# ========================================
# 主菜单和交互界面
# ========================================

show_main_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    VPS 安全加固工具 v${SCRIPT_VERSION}                        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  ✓ 模块化设计  ✓ 智能检测  ✓ 安全备份  ✓ 用户友好        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  🚀 1. 一键安全加固 (推荐新手)                                   ║${NC}"
    echo -e "${WHITE}║  🔧 2. 系统基础设置                                              ║${NC}"
    echo -e "${WHITE}║  👤 3. 用户管理                                                  ║${NC}"
    echo -e "${WHITE}║  🔐 4. SSH 安全配置                                              ║${NC}"
    echo -e "${WHITE}║  🛡️ 5. 防火墙管理                                                ║${NC}"
    echo -e "${WHITE}║  🚫 6. 入侵防护 (Fail2Ban)                                       ║${NC}"
    echo -e "${WHITE}║  📊 7. 安全状态检查                                              ║${NC}"
    echo -e "${WHITE}║  ⚙️ 8. 高级选项                                                  ║${NC}"
    echo -e "${WHITE}║  📋 9. 查看配置                                                  ║${NC}"
    echo -e "${WHITE}║  🚪 0. 退出                                                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_system_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 系统基础设置 ===${NC}"
        echo ""
        echo "1. 更新系统软件包"
        echo "2. 设置系统时区"
        echo "3. 安装基础安全软件"
        echo "4. 系统参数优化"
        echo "5. 返回主菜单"
        echo ""

        read -p "请选择 [1-5]: " choice

        case $choice in
            1) system_update ;;
            2) set_timezone ;;
            3) install_security_packages ;;
            4) optimize_system ;;
            5) return 0 ;;
            *) log_error "无效选择，请重新输入" ; sleep 2 ;;
        esac
    done
}

show_user_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 用户管理 ===${NC}"
        echo ""
        echo "1. 创建管理员用户"
        echo "2. 配置用户权限"
        echo "3. 设置密码策略"
        echo "4. 查看用户信息"
        echo "5. 返回主菜单"
        echo ""

        read -p "请选择 [1-5]: " choice

        case $choice in
            1) create_admin_user ;;
            2) configure_user_permissions ;;
            3) set_password_policy ;;
            4) show_user_info ;;
            5) return 0 ;;
            *) log_error "无效选择，请重新输入" ; sleep 2 ;;
        esac
    done
}

show_ssh_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== SSH 安全配置 ===${NC}"
        echo ""
        echo "1. 修改 SSH 端口"
        echo "2. 生成/导入 SSH 密钥"
        echo "3. 禁用密码登录"
        echo "4. 禁用 root 登录"
        echo "5. SSH 配置优化"
        echo "6. 查看 SSH 状态"
        echo "7. 返回主菜单"
        echo ""

        read -p "请选择 [1-7]: " choice

        case $choice in
            1) change_ssh_port ;;
            2) manage_ssh_keys ;;
            3) disable_password_auth ;;
            4) disable_root_login ;;
            5) optimize_ssh_config ;;
            6) show_ssh_status ;;
            7) return 0 ;;
            *) log_error "无效选择，请重新输入" ; sleep 2 ;;
        esac
    done
}

show_firewall_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 防火墙管理 ===${NC}"
        echo ""
        echo "1. 启用/禁用防火墙"
        echo "2. 配置基础规则"
        echo "3. 管理端口规则"
        echo "4. 查看防火墙状态"
        echo "5. 重置防火墙规则"
        echo "6. 返回主菜单"
        echo ""

        read -p "请选择 [1-6]: " choice

        case $choice in
            1) toggle_firewall ;;
            2) configure_basic_rules ;;
            3) manage_port_rules ;;
            4) show_firewall_status ;;
            5) reset_firewall ;;
            6) return 0 ;;
            *) log_error "无效选择，请重新输入" ; sleep 2 ;;
        esac
    done
}

show_fail2ban_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 入侵防护 (Fail2Ban) ===${NC}"
        echo ""
        echo "1. 安装/配置 Fail2Ban"
        echo "2. 管理防护规则"
        echo "3. 查看封禁状态"
        echo "4. 解封 IP 地址"
        echo "5. 查看日志"
        echo "6. 返回主菜单"
        echo ""

        read -p "请选择 [1-6]: " choice

        case $choice in
            1) setup_fail2ban ;;
            2) manage_fail2ban_rules ;;
            3) show_ban_status ;;
            4) unban_ip ;;
            5) show_fail2ban_logs ;;
            6) return 0 ;;
            *) log_error "无效选择，请重新输入" ; sleep 2 ;;
        esac
    done
}

# ========================================
# 占位符函数 (将在后续任务中实现)
# ========================================

# ========================================
# 一键安全加固功能
# ========================================

one_click_hardening() {
    log_info "一键安全加固向导..."

    echo ""
    echo "=== VPS 一键安全加固向导 ==="
    echo ""
    log_info "此向导将自动配置以下安全设置:"
    echo "  ✓ 系统更新和基础软件安装"
    echo "  ✓ 创建管理员用户"
    echo "  ✓ SSH安全配置 (端口、密钥、禁用root)"
    echo "  ✓ 防火墙配置"
    echo "  ✓ 入侵防护 (Fail2Ban)"
    echo "  ✓ 系统参数优化"
    echo ""

    log_warn "注意: 此操作将修改系统关键配置，请确保您了解这些更改"
    echo ""

    read -p "是否继续一键安全加固? (y/N): " confirm_hardening

    if [[ ! "$confirm_hardening" =~ ^[Yy]$ ]]; then
        log_info "取消一键安全加固"
        return 0
    fi

    # 收集用户配置参数
    if ! collect_hardening_parameters; then
        log_error "参数收集失败，取消加固"
        return 1
    fi

    # 执行安全加固流程
    execute_hardening_process

    read -p "按回车键返回主菜单..."
}

collect_hardening_parameters() {
    log_info "收集配置参数..."

    echo ""
    echo "=== 配置参数收集 ==="
    echo ""

    # 1. 管理员用户配置
    echo "1. 管理员用户配置"
    echo "----------------------------------------"

    # 检查是否已有管理员用户
    load_config
    if [[ "$ADMIN_USER_CREATED" == "yes" && -n "$ADMIN_USER" ]]; then
        log_info "检测到已存在管理员用户: $ADMIN_USER"
        read -p "是否创建新的管理员用户? (y/N): " create_new_user

        if [[ "$create_new_user" =~ ^[Yy]$ ]]; then
            get_admin_user_info
        else
            HARDENING_ADMIN_USER="$ADMIN_USER"
        fi
    else
        get_admin_user_info
    fi

    # 2. SSH配置
    echo ""
    echo "2. SSH安全配置"
    echo "----------------------------------------"

    local current_ssh_port=$(get_current_ssh_port)
    log_info "当前SSH端口: $current_ssh_port"

    read -p "新的SSH端口 [2222]: " new_ssh_port
    HARDENING_SSH_PORT=${new_ssh_port:-2222}

    if ! validate_ssh_port "$HARDENING_SSH_PORT"; then
        log_error "无效的SSH端口: $HARDENING_SSH_PORT"
        return 1
    fi

    echo ""
    echo "SSH密钥配置:"
    echo "1. 生成新的SSH密钥对"
    echo "2. 导入现有公钥"
    echo "3. 跳过SSH密钥配置"

    read -p "请选择 [1]: " ssh_key_choice
    HARDENING_SSH_KEY_CHOICE=${ssh_key_choice:-1}

    if [[ "$HARDENING_SSH_KEY_CHOICE" == "2" ]]; then
        echo ""
        echo "请粘贴SSH公钥内容:"
        read -r HARDENING_SSH_PUBLIC_KEY

        if [[ -z "$HARDENING_SSH_PUBLIC_KEY" || ! "$HARDENING_SSH_PUBLIC_KEY" =~ ^ssh- ]]; then
            log_error "无效的SSH公钥格式"
            return 1
        fi
    fi

    # 3. 防火墙配置
    echo ""
    echo "3. 防火墙配置"
    echo "----------------------------------------"

    echo "是否开放以下常用端口?"

    HARDENING_OPEN_HTTP=false
    read -p "开放HTTP端口 (80)? (y/N): " open_http
    if [[ "$open_http" =~ ^[Yy]$ ]]; then
        HARDENING_OPEN_HTTP=true
    fi

    HARDENING_OPEN_HTTPS=false
    read -p "开放HTTPS端口 (443)? (y/N): " open_https
    if [[ "$open_https" =~ ^[Yy]$ ]]; then
        HARDENING_OPEN_HTTPS=true
    fi

    # 4. 系统优化
    echo ""
    echo "4. 系统优化配置"
    echo "----------------------------------------"

    HARDENING_OPTIMIZE_SYSTEM=true
    read -p "是否进行系统参数优化? (Y/n): " optimize_system
    if [[ "$optimize_system" =~ ^[Nn]$ ]]; then
        HARDENING_OPTIMIZE_SYSTEM=false
    fi

    # 5. 确认配置
    echo ""
    echo "=== 配置确认 ==="
    echo "管理员用户: $HARDENING_ADMIN_USER"
    echo "SSH端口: $HARDENING_SSH_PORT"
    echo "SSH密钥: $(get_ssh_key_choice_text)"
    echo "开放HTTP: $HARDENING_OPEN_HTTP"
    echo "开放HTTPS: $HARDENING_OPEN_HTTPS"
    echo "系统优化: $HARDENING_OPTIMIZE_SYSTEM"
    echo ""

    read -p "确认以上配置并开始加固? (Y/n): " confirm_config
    if [[ "$confirm_config" =~ ^[Nn]$ ]]; then
        log_info "取消配置"
        return 1
    fi

    return 0
}

get_admin_user_info() {
    while true; do
        read -p "请输入管理员用户名: " admin_username

        if [[ -z "$admin_username" ]]; then
            log_error "用户名不能为空"
            continue
        fi

        if ! validate_username "$admin_username"; then
            log_error "用户名格式无效"
            continue
        fi

        if id "$admin_username" &>/dev/null; then
            log_error "用户 $admin_username 已存在"
            continue
        fi

        HARDENING_ADMIN_USER="$admin_username"
        break
    done

    # 获取密码
    while true; do
        read -s -p "请输入用户密码: " admin_password1
        echo ""
        read -s -p "请再次输入密码确认: " admin_password2
        echo ""

        if [[ "$admin_password1" != "$admin_password2" ]]; then
            log_error "两次输入的密码不一致"
            continue
        fi

        if [[ ${#admin_password1} -lt 8 ]]; then
            log_error "密码长度至少8位"
            continue
        fi

        HARDENING_ADMIN_PASSWORD="$admin_password1"
        break
    done
}

get_ssh_key_choice_text() {
    case "$HARDENING_SSH_KEY_CHOICE" in
        1) echo "生成新密钥对" ;;
        2) echo "导入现有公钥" ;;
        3) echo "跳过配置" ;;
        *) echo "未知" ;;
    esac
}

execute_hardening_process() {
    log_info "开始执行安全加固流程..."

    local total_steps=8
    local current_step=0

    echo ""
    echo "=== 安全加固执行流程 ==="
    echo ""

    # 步骤1: 系统更新
    ((current_step++))
    log_info "步骤 $current_step/$total_steps: 系统更新和基础软件安装"
    if ! hardening_step_system_update; then
        log_error "系统更新失败"
        return 1
    fi

    # 步骤2: 创建管理员用户
    ((current_step++))
    log_info "步骤 $current_step/$total_steps: 创建管理员用户"
    if ! hardening_step_create_admin_user; then
        log_error "创建管理员用户失败"
        return 1
    fi

    # 步骤3: SSH安全配置
    ((current_step++))
    log_info "步骤 $current_step/$total_steps: SSH安全配置"
    if ! hardening_step_configure_ssh; then
        log_error "SSH配置失败"
        return 1
    fi

    # 步骤4: 防火墙配置
    ((current_step++))
    log_info "步骤 $current_step/$total_steps: 防火墙配置"
    if ! hardening_step_configure_firewall; then
        log_error "防火墙配置失败"
        return 1
    fi

    # 步骤5: 入侵防护配置
    ((current_step++))
    log_info "步骤 $current_step/$total_steps: 入侵防护配置"
    if ! hardening_step_configure_fail2ban; then
        log_error "入侵防护配置失败"
        return 1
    fi

    # 步骤6: 系统优化
    if [[ "$HARDENING_OPTIMIZE_SYSTEM" == true ]]; then
        ((current_step++))
        log_info "步骤 $current_step/$total_steps: 系统参数优化"
        if ! hardening_step_optimize_system; then
            log_warn "系统优化失败，但继续执行"
        fi
    fi

    # 步骤7: 配置验证
    ((current_step++))
    log_info "步骤 $current_step/$total_steps: 配置验证"
    if ! hardening_step_verify_config; then
        log_warn "配置验证发现问题，请检查"
    fi

    # 步骤8: 生成报告
    ((current_step++))
    log_info "步骤 $current_step/$total_steps: 生成安全报告"
    hardening_step_generate_report

    log_success "安全加固流程完成！"

    # 显示重要信息
    show_hardening_summary
}

# ========================================
# 一键加固执行步骤
# ========================================

hardening_step_system_update() {
    log_info "更新系统软件包..."

    case $PACKAGE_MANAGER in
        apt)
            apt update -qq && apt upgrade -y
            ;;
        yum)
            yum update -y
            ;;
        *)
            log_warn "不支持的包管理器，跳过系统更新"
            return 0
            ;;
    esac

    log_info "安装基础安全软件..."
    local packages=("curl" "wget" "unzip" "htop" "net-tools" "ufw" "fail2ban")

    for pkg in "${packages[@]}"; do
        if ! install_package "$pkg"; then
            log_warn "软件包安装失败: $pkg"
        fi
    done

    log_success "系统更新和软件安装完成"
    return 0
}

hardening_step_create_admin_user() {
    # 如果用户已存在，跳过创建
    if id "$HARDENING_ADMIN_USER" &>/dev/null; then
        log_info "用户 $HARDENING_ADMIN_USER 已存在，跳过创建"
        return 0
    fi

    log_info "创建管理员用户: $HARDENING_ADMIN_USER"

    # 创建用户
    if ! useradd -m -s /bin/bash "$HARDENING_ADMIN_USER"; then
        log_error "用户创建失败"
        return 1
    fi

    # 设置密码
    if ! echo "$HARDENING_ADMIN_USER:$HARDENING_ADMIN_PASSWORD" | chpasswd; then
        log_error "密码设置失败"
        return 1
    fi

    # 添加到sudo组
    if ! usermod -aG sudo "$HARDENING_ADMIN_USER"; then
        log_error "添加sudo权限失败"
        return 1
    fi

    # 创建SSH目录
    local user_home="/home/$HARDENING_ADMIN_USER"
    local ssh_dir="$user_home/.ssh"

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$HARDENING_ADMIN_USER:$HARDENING_ADMIN_USER" "$ssh_dir"

    # 配置SSH密钥
    case "$HARDENING_SSH_KEY_CHOICE" in
        1)
            # 生成新密钥对
            log_info "生成SSH密钥对..."
            local key_file="$ssh_dir/id_rsa"

            if sudo -u "$HARDENING_ADMIN_USER" ssh-keygen -t rsa -b 4096 -C "$HARDENING_ADMIN_USER@$(hostname)" -f "$key_file" -N ""; then
                # 设置authorized_keys
                cat "$key_file.pub" > "$ssh_dir/authorized_keys"
                chmod 600 "$ssh_dir/authorized_keys"
                chown "$HARDENING_ADMIN_USER:$HARDENING_ADMIN_USER" "$ssh_dir/authorized_keys"

                # 保存私钥供用户下载
                HARDENING_PRIVATE_KEY_PATH="$key_file"
                log_success "SSH密钥对生成完成"
            else
                log_error "SSH密钥生成失败"
                return 1
            fi
            ;;
        2)
            # 导入现有公钥
            log_info "导入SSH公钥..."
            echo "$HARDENING_SSH_PUBLIC_KEY" > "$ssh_dir/authorized_keys"
            chmod 600 "$ssh_dir/authorized_keys"
            chown "$HARDENING_ADMIN_USER:$HARDENING_ADMIN_USER" "$ssh_dir/authorized_keys"
            log_success "SSH公钥导入完成"
            ;;
        3)
            log_info "跳过SSH密钥配置"
            ;;
    esac

    # 更新配置
    sed -i "s/^ADMIN_USER=.*/ADMIN_USER=$HARDENING_ADMIN_USER/" "$CONFIG_FILE" 2>/dev/null || true
    sed -i "s/^ADMIN_USER_CREATED=.*/ADMIN_USER_CREATED=yes/" "$CONFIG_FILE" 2>/dev/null || true

    log_success "管理员用户创建完成"
    return 0
}

hardening_step_configure_ssh() {
    log_info "配置SSH安全设置..."

    # 备份SSH配置
    backup_file "/etc/ssh/sshd_config" "sshd_config"

    local ssh_config="/etc/ssh/sshd_config"

    # 修改SSH端口
    if grep -q "^Port " "$ssh_config"; then
        sed -i "s/^Port .*/Port $HARDENING_SSH_PORT/" "$ssh_config"
    else
        echo "Port $HARDENING_SSH_PORT" >> "$ssh_config"
    fi

    # 禁用root登录
    if grep -q "^PermitRootLogin" "$ssh_config"; then
        sed -i "s/^PermitRootLogin.*/PermitRootLogin prohibit-password/" "$ssh_config"
    else
        echo "PermitRootLogin prohibit-password" >> "$ssh_config"
    fi

    # 如果配置了SSH密钥，禁用密码认证
    if [[ "$HARDENING_SSH_KEY_CHOICE" != "3" ]]; then
        log_info "禁用SSH密码认证..."

        if grep -q "^PasswordAuthentication" "$ssh_config"; then
            sed -i "s/^PasswordAuthentication.*/PasswordAuthentication no/" "$ssh_config"
        else
            echo "PasswordAuthentication no" >> "$ssh_config"
        fi

        if grep -q "^ChallengeResponseAuthentication" "$ssh_config"; then
            sed -i "s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/" "$ssh_config"
        else
            echo "ChallengeResponseAuthentication no" >> "$ssh_config"
        fi
    fi

    # 应用其他安全配置
    local security_configs=(
        "Protocol 2"
        "LoginGraceTime 60"
        "MaxAuthTries 3"
        "MaxSessions 10"
        "PermitEmptyPasswords no"
        "X11Forwarding no"
        "StrictModes yes"
        "IgnoreRhosts yes"
        "HostbasedAuthentication no"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
    )

    for config in "${security_configs[@]}"; do
        local key=$(echo "$config" | awk '{print $1}')
        local value=$(echo "$config" | cut -d' ' -f2-)

        if grep -q "^$key " "$ssh_config"; then
            sed -i "s/^$key .*/$config/" "$ssh_config"
        else
            echo "$config" >> "$ssh_config"
        fi
    done

    # 测试SSH配置
    if ! sshd -t; then
        log_error "SSH配置语法错误，恢复原配置"
        restore_ssh_config
        return 1
    fi

    # 重启SSH服务
    local ssh_service=$(detect_ssh_service)
    if ! systemctl restart "$ssh_service"; then
        log_error "SSH服务重启失败，恢复原配置"
        restore_ssh_config
        systemctl restart "$ssh_service"
        return 1
    fi

    # 更新配置文件
    sed -i "s/^SSH_PORT=.*/SSH_PORT=$HARDENING_SSH_PORT/" "$CONFIG_FILE" 2>/dev/null || true
    sed -i "s/^ROOT_LOGIN=.*/ROOT_LOGIN=prohibit-password/" "$CONFIG_FILE" 2>/dev/null || true

    if [[ "$HARDENING_SSH_KEY_CHOICE" != "3" ]]; then
        sed -i "s/^PASSWORD_AUTH=.*/PASSWORD_AUTH=no/" "$CONFIG_FILE" 2>/dev/null || true
    fi

    log_success "SSH安全配置完成"
    return 0
}

hardening_step_configure_firewall() {
    log_info "配置UFW防火墙..."

    # 确保UFW已安装
    if ! command -v ufw &> /dev/null; then
        if ! install_package "ufw"; then
            log_error "UFW安装失败"
            return 1
        fi
    fi

    # 重置防火墙规则
    ufw --force reset

    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing

    # 添加SSH端口
    ufw allow "$HARDENING_SSH_PORT/tcp" comment "SSH"

    # 添加HTTP/HTTPS端口
    if [[ "$HARDENING_OPEN_HTTP" == true ]]; then
        ufw allow 80/tcp comment "HTTP"
    fi

    if [[ "$HARDENING_OPEN_HTTPS" == true ]]; then
        ufw allow 443/tcp comment "HTTPS"
    fi

    # 启用防火墙
    if ! ufw --force enable; then
        log_error "防火墙启用失败"
        return 1
    fi

    # 更新配置
    sed -i "s/^UFW_ENABLED=.*/UFW_ENABLED=yes/" "$CONFIG_FILE" 2>/dev/null || true

    log_success "防火墙配置完成"
    return 0
}

hardening_step_configure_fail2ban() {
    log_info "配置Fail2Ban入侵防护..."

    # 确保Fail2Ban已安装
    if ! command -v fail2ban-server &> /dev/null; then
        if ! install_package "fail2ban"; then
            log_error "Fail2Ban安装失败"
            return 1
        fi
    fi

    # 备份原配置
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        backup_file "/etc/fail2ban/jail.local" "jail.local"
    fi

    # 创建Fail2Ban配置
    cat > /etc/fail2ban/jail.local << EOF
# Fail2Ban配置 - 一键安全加固生成
# 生成时间: $(date)

[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 3600
findtime = 600
maxretry = 5
backend = auto
action = %(action_)s

[sshd]
enabled = true
port = $HARDENING_SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1800
findtime = 300

[sshd-ddos]
enabled = true
port = $HARDENING_SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 3600
findtime = 300
EOF

    # 如果开放了Web端口，添加Web防护
    if [[ "$HARDENING_OPEN_HTTP" == true || "$HARDENING_OPEN_HTTPS" == true ]]; then
        cat >> /etc/fail2ban/jail.local << EOF

# Web服务防护
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 3
bantime = 3600
EOF
    fi

    # 启动并启用Fail2Ban服务
    systemctl enable fail2ban
    if ! systemctl restart fail2ban; then
        log_error "Fail2Ban服务启动失败"
        return 1
    fi

    # 更新配置
    sed -i "s/^FAIL2BAN_ENABLED=.*/FAIL2BAN_ENABLED=yes/" "$CONFIG_FILE" 2>/dev/null || true

    log_success "Fail2Ban配置完成"
    return 0
}

hardening_step_optimize_system() {
    log_info "优化系统参数..."

    # 备份原配置
    backup_file "/etc/sysctl.conf" "sysctl"

    # 添加系统优化参数
    cat >> /etc/sysctl.conf << EOF

# VPS Security - 一键加固系统优化
# 生成时间: $(date)

# 网络优化
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# 内存管理优化
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# 文件系统优化
fs.file-max = 65535
fs.inotify.max_user_watches = 524288

# 安全参数
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOF

    # 应用配置
    if sysctl -p; then
        log_success "系统参数优化完成"
        return 0
    else
        log_error "系统参数优化失败"
        return 1
    fi
}

hardening_step_verify_config() {
    log_info "验证配置..."

    local issues=0

    # 验证SSH服务
    local ssh_service=$(detect_ssh_service)
    if ! systemctl is-active --quiet "$ssh_service"; then
        log_error "SSH服务未运行"
        ((issues++))
    fi

    # 验证SSH端口
    if ! netstat -tlnp 2>/dev/null | grep -q ":$HARDENING_SSH_PORT.*sshd" && ! ss -tlnp 2>/dev/null | grep -q ":$HARDENING_SSH_PORT.*sshd"; then
        log_error "SSH端口 $HARDENING_SSH_PORT 未监听"
        ((issues++))
    fi

    # 验证防火墙
    if [[ "$(get_firewall_status)" != "active" ]]; then
        log_error "防火墙未启用"
        ((issues++))
    fi

    # 验证Fail2Ban
    if [[ "$(get_fail2ban_status)" != "active" ]]; then
        log_error "Fail2Ban服务未运行"
        ((issues++))
    fi

    # 验证管理员用户
    if ! id "$HARDENING_ADMIN_USER" &>/dev/null; then
        log_error "管理员用户不存在"
        ((issues++))
    elif ! groups "$HARDENING_ADMIN_USER" | grep -q sudo; then
        log_error "管理员用户无sudo权限"
        ((issues++))
    fi

    if [[ $issues -eq 0 ]]; then
        log_success "配置验证通过"
        return 0
    else
        log_warn "配置验证发现 $issues 个问题"
        return 1
    fi
}

hardening_step_generate_report() {
    log_info "生成安全加固报告..."

    local report_file="$CONFIG_DIR/hardening_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "========================================"
        echo "VPS 一键安全加固报告"
        echo "========================================"
        echo "加固时间: $(date)"
        echo "主机名: $(hostname)"
        echo "系统信息: $(uname -a)"
        echo ""

        echo "=== 加固配置摘要 ==="
        echo "管理员用户: $HARDENING_ADMIN_USER"
        echo "SSH端口: $HARDENING_SSH_PORT"
        echo "SSH密钥: $(get_ssh_key_choice_text)"
        echo "Root登录: 仅允许密钥"
        echo "密码认证: $(if [[ "$HARDENING_SSH_KEY_CHOICE" != "3" ]]; then echo "已禁用"; else echo "已启用"; fi)"
        echo "防火墙: 已启用"
        echo "入侵防护: 已启用"
        echo "系统优化: $HARDENING_OPTIMIZE_SYSTEM"
        echo ""

        echo "=== 开放端口 ==="
        echo "SSH: $HARDENING_SSH_PORT/tcp"
        if [[ "$HARDENING_OPEN_HTTP" == true ]]; then
            echo "HTTP: 80/tcp"
        fi
        if [[ "$HARDENING_OPEN_HTTPS" == true ]]; then
            echo "HTTPS: 443/tcp"
        fi
        echo ""

        echo "=== 服务状态 ==="
        local ssh_service=$(detect_ssh_service)
        echo "SSH服务: $(systemctl is-active "$ssh_service")"
        echo "UFW防火墙: $(get_firewall_status)"
        echo "Fail2Ban: $(get_fail2ban_status)"
        echo ""

        echo "=== 重要提醒 ==="
        echo "1. 请立即测试新的SSH连接:"
        echo "   ssh -p $HARDENING_SSH_PORT $HARDENING_ADMIN_USER@$(hostname -I | awk '{print $1}')"
        echo ""

        if [[ "$HARDENING_SSH_KEY_CHOICE" == "1" && -n "$HARDENING_PRIVATE_KEY_PATH" ]]; then
            echo "2. SSH私钥位置: $HARDENING_PRIVATE_KEY_PATH"
            echo "   请立即下载并妥善保管私钥文件"
            echo ""
        fi

        echo "3. 防火墙已启用，只允许配置的端口访问"
        echo "4. Fail2Ban已启用，会自动封禁暴力破解IP"
        echo "5. 建议定期更新系统和检查安全状态"
        echo ""

        echo "=== 后续建议 ==="
        echo "1. 定期运行安全状态检查"
        echo "2. 监控系统日志和Fail2Ban日志"
        echo "3. 定期更新系统和软件包"
        echo "4. 定期备份重要数据和配置"
        echo "5. 考虑配置自动更新和监控"
        echo ""

        echo "========================================"
        echo "加固完成时间: $(date)"
        echo "========================================"

    } > "$report_file"

    log_success "安全加固报告已生成: $report_file"
}

show_hardening_summary() {
    echo ""
    echo "========================================"
    echo "🎉 VPS 安全加固完成！"
    echo "========================================"
    echo ""

    log_success "安全加固已成功完成，以下是重要信息:"
    echo ""

    echo "📋 配置摘要:"
    echo "  管理员用户: $HARDENING_ADMIN_USER"
    echo "  SSH端口: $HARDENING_SSH_PORT"
    echo "  防火墙: 已启用"
    echo "  入侵防护: 已启用"
    echo ""

    echo "🔑 连接信息:"
    echo "  新的SSH连接命令:"
    echo "  ssh -p $HARDENING_SSH_PORT $HARDENING_ADMIN_USER@$(hostname -I | awk '{print $1}')"
    echo ""

    if [[ "$HARDENING_SSH_KEY_CHOICE" == "1" && -n "$HARDENING_PRIVATE_KEY_PATH" ]]; then
        echo "🔐 SSH私钥:"
        echo "  私钥文件位置: $HARDENING_PRIVATE_KEY_PATH"
        echo "  请立即下载并保存私钥文件！"
        echo ""

        read -p "是否现在显示私钥内容? (Y/n): " show_private_key
        if [[ ! "$show_private_key" =~ ^[Nn]$ ]]; then
            echo ""
            echo "=== SSH私钥内容 (请复制保存) ==="
            cat "$HARDENING_PRIVATE_KEY_PATH"
            echo "=== 私钥内容结束 ==="
            echo ""
        fi
    fi

    echo "⚠️  重要提醒:"
    echo "  1. 请在断开当前连接前，先测试新的SSH连接"
    echo "  2. 确保能够使用新端口和用户正常登录"
    echo "  3. 如果无法连接，请通过VPS控制台恢复配置"
    echo ""

    echo "📊 安全状态:"
    echo "  - SSH端口已修改 ✓"
    echo "  - Root登录已限制 ✓"
    if [[ "$HARDENING_SSH_KEY_CHOICE" != "3" ]]; then
        echo "  - 密码登录已禁用 ✓"
    fi
    echo "  - 防火墙已启用 ✓"
    echo "  - 入侵防护已启用 ✓"
    if [[ "$HARDENING_OPTIMIZE_SYSTEM" == true ]]; then
        echo "  - 系统参数已优化 ✓"
    fi
    echo ""

    echo "🛠️  后续操作:"
    echo "  - 使用菜单选项 7 进行安全状态检查"
    echo "  - 使用菜单选项 6 管理Fail2Ban规则"
    echo "  - 定期检查系统更新和日志"
    echo ""

    log_info "安全加固流程全部完成！"
}

# ========================================
# 系统基础设置模块
# ========================================

system_update() {
    log_info "开始系统更新..."

    case $PACKAGE_MANAGER in
        apt)
            log_info "更新软件包列表..."
            apt update -qq

            log_info "升级系统软件包..."
            apt upgrade -y

            log_info "清理不需要的软件包..."
            apt autoremove -y
            apt autoclean
            ;;
        yum)
            log_info "更新系统软件包..."
            yum update -y

            log_info "清理缓存..."
            yum clean all
            ;;
        *)
            log_error "不支持的包管理器: $PACKAGE_MANAGER"
            return 1
            ;;
    esac

    log_success "系统更新完成"
    read -p "按回车键继续..."
}

set_timezone() {
    log_info "设置系统时区..."

    # 显示当前时区
    current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "未知")
    log_info "当前时区: $current_tz"

    echo ""
    echo "常用时区选项:"
    echo "1. Asia/Shanghai (中国标准时间)"
    echo "2. Asia/Tokyo (日本标准时间)"
    echo "3. America/New_York (美国东部时间)"
    echo "4. America/Los_Angeles (美国西部时间)"
    echo "5. Europe/London (英国时间)"
    echo "6. UTC (协调世界时)"
    echo "7. 自定义时区"
    echo "8. 保持当前设置"
    echo ""

    read -p "请选择时区 [1-8]: " tz_choice

    case $tz_choice in
        1) new_tz="Asia/Shanghai" ;;
        2) new_tz="Asia/Tokyo" ;;
        3) new_tz="America/New_York" ;;
        4) new_tz="America/Los_Angeles" ;;
        5) new_tz="Europe/London" ;;
        6) new_tz="UTC" ;;
        7)
            read -p "请输入时区 (如: Asia/Shanghai): " new_tz
            if [[ ! -f "/usr/share/zoneinfo/$new_tz" ]]; then
                log_error "无效的时区: $new_tz"
                read -p "按回车键继续..."
                return 1
            fi
            ;;
        8)
            log_info "保持当前时区设置"
            read -p "按回车键继续..."
            return 0
            ;;
        *)
            log_error "无效选择"
            read -p "按回车键继续..."
            return 1
            ;;
    esac

    # 设置时区
    if command -v timedatectl &> /dev/null; then
        timedatectl set-timezone "$new_tz"
    else
        echo "$new_tz" > /etc/timezone
        ln -sf "/usr/share/zoneinfo/$new_tz" /etc/localtime
    fi

    # 验证设置
    new_current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)
    if [[ "$new_current_tz" == "$new_tz" ]]; then
        log_success "时区已设置为: $new_tz"
        log_info "当前时间: $(date)"
    else
        log_error "时区设置失败"
    fi

    read -p "按回车键继续..."
}

install_security_packages() {
    log_info "安装基础安全软件包..."

    # 定义需要安装的软件包
    local packages=()

    case $PACKAGE_MANAGER in
        apt)
            packages=(
                "curl"
                "wget"
                "unzip"
                "htop"
                "iotop"
                "net-tools"
                "ufw"
                "fail2ban"
                "logwatch"
                "rkhunter"
                "chkrootkit"
                "aide"
            )
            ;;
        yum)
            packages=(
                "curl"
                "wget"
                "unzip"
                "htop"
                "iotop"
                "net-tools"
                "firewalld"
                "fail2ban"
                "logwatch"
                "rkhunter"
                "chkrootkit"
                "aide"
            )
            ;;
        *)
            log_error "不支持的包管理器: $PACKAGE_MANAGER"
            read -p "按回车键继续..."
            return 1
            ;;
    esac

    # 显示将要安装的软件包
    echo ""
    echo "将要安装的软件包:"
    for pkg in "${packages[@]}"; do
        echo "  - $pkg"
    done
    echo ""

    read -p "是否继续安装? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "取消安装"
        read -p "按回车键继续..."
        return 0
    fi

    # 安装软件包
    local failed_packages=()
    for pkg in "${packages[@]}"; do
        log_info "安装: $pkg"
        if ! install_package "$pkg"; then
            failed_packages+=("$pkg")
            log_warn "软件包安装失败: $pkg"
        fi
    done

    # 报告结果
    if [[ ${#failed_packages[@]} -eq 0 ]]; then
        log_success "所有安全软件包安装完成"
    else
        log_warn "以下软件包安装失败:"
        for pkg in "${failed_packages[@]}"; do
            echo "  - $pkg"
        done
    fi

    read -p "按回车键继续..."
}

optimize_system() {
    log_info "系统参数优化..."

    echo ""
    echo "系统优化选项:"
    echo "1. 优化网络参数"
    echo "2. 优化内存管理"
    echo "3. 优化文件系统"
    echo "4. 全部优化"
    echo "5. 跳过优化"
    echo ""

    read -p "请选择 [1-5]: " opt_choice

    case $opt_choice in
        1|4) optimize_network_params ;;
    esac

    case $opt_choice in
        2|4) optimize_memory_params ;;
    esac

    case $opt_choice in
        3|4) optimize_filesystem_params ;;
    esac

    case $opt_choice in
        5)
            log_info "跳过系统优化"
            ;;
    esac

    if [[ "$opt_choice" != "5" ]]; then
        log_success "系统优化完成"
    fi

    read -p "按回车键继续..."
}

optimize_network_params() {
    log_info "优化网络参数..."

    # 备份原配置
    backup_file "/etc/sysctl.conf" "sysctl"

    # 添加网络优化参数
    cat >> /etc/sysctl.conf << EOF

# VPS Security - Network Optimization
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
EOF

    # 应用配置
    sysctl -p

    log_success "网络参数优化完成"
}

optimize_memory_params() {
    log_info "优化内存管理参数..."

    cat >> /etc/sysctl.conf << EOF

# VPS Security - Memory Optimization
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

    sysctl -p
    log_success "内存参数优化完成"
}

optimize_filesystem_params() {
    log_info "优化文件系统参数..."

    cat >> /etc/sysctl.conf << EOF

# VPS Security - Filesystem Optimization
fs.file-max = 65535
fs.inotify.max_user_watches = 524288
EOF

    sysctl -p
    log_success "文件系统参数优化完成"
}

# ========================================
# 用户管理模块
# ========================================

validate_username() {
    local username="$1"

    # 检查用户名格式
    if [[ ! "$username" =~ ^[a-z][a-z0-9_-]{2,31}$ ]]; then
        return 1
    fi

    # 检查是否为系统保留用户名
    local reserved_users=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "uuidd" "dnsmasq" "landscape" "pollinate" "sshd" "ubuntu" "admin")

    for reserved in "${reserved_users[@]}"; do
        if [[ "$username" == "$reserved" ]]; then
            return 1
        fi
    done

    return 0
}

create_admin_user() {
    log_info "创建管理员用户..."

    # 检查是否已经创建过管理员用户
    load_config
    if [[ "$ADMIN_USER_CREATED" == "yes" && -n "$ADMIN_USER" ]]; then
        log_info "管理员用户已存在: $ADMIN_USER"
        echo ""
        echo "1. 创建新的管理员用户"
        echo "2. 修改现有用户权限"
        echo "3. 返回上级菜单"
        echo ""

        read -p "请选择 [1-3]: " choice
        case $choice in
            1) ;; # 继续创建新用户
            2) configure_user_permissions; return ;;
            3) return ;;
            *) log_error "无效选择"; read -p "按回车键继续..."; return ;;
        esac
    fi

    # 获取用户名
    while true; do
        echo ""
        read -p "请输入新用户名 (3-32字符，小写字母开头): " new_username

        if [[ -z "$new_username" ]]; then
            log_error "用户名不能为空"
            continue
        fi

        if ! validate_username "$new_username"; then
            log_error "用户名格式无效或为系统保留用户名"
            log_info "用户名要求: 3-32字符，小写字母开头，可包含数字、下划线、连字符"
            continue
        fi

        # 检查用户是否已存在
        if id "$new_username" &>/dev/null; then
            log_error "用户 $new_username 已存在"
            continue
        fi

        break
    done

    # 获取密码
    while true; do
        echo ""
        read -s -p "请输入用户密码 (至少8位): " password1
        echo ""
        read -s -p "请再次输入密码确认: " password2
        echo ""

        if [[ "$password1" != "$password2" ]]; then
            log_error "两次输入的密码不一致"
            continue
        fi

        if [[ ${#password1} -lt 8 ]]; then
            log_error "密码长度至少8位"
            continue
        fi

        break
    done

    # 创建用户
    log_info "创建用户: $new_username"
    if useradd -m -s /bin/bash "$new_username"; then
        log_success "用户创建成功"
    else
        log_error "用户创建失败"
        read -p "按回车键继续..."
        return 1
    fi

    # 设置密码
    if echo "$new_username:$password1" | chpasswd; then
        log_success "密码设置成功"
    else
        log_error "密码设置失败"
        read -p "按回车键继续..."
        return 1
    fi

    # 添加到sudo组
    log_info "添加用户到sudo组..."
    if usermod -aG sudo "$new_username"; then
        log_success "用户已添加到sudo组"
    else
        log_error "添加sudo权限失败"
    fi

    # 创建SSH目录
    log_info "配置SSH目录..."
    user_home="/home/$new_username"
    ssh_dir="$user_home/.ssh"

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$new_username:$new_username" "$ssh_dir"

    # 更新配置
    ADMIN_USER="$new_username"
    ADMIN_USER_CREATED="yes"

    # 保存配置 (这里需要实现save_config函数的具体逻辑)
    sed -i "s/^ADMIN_USER=.*/ADMIN_USER=$new_username/" "$CONFIG_FILE"
    sed -i "s/^ADMIN_USER_CREATED=.*/ADMIN_USER_CREATED=yes/" "$CONFIG_FILE"

    log_success "管理员用户创建完成: $new_username"
    log_info "用户可以使用 'sudo' 命令获取管理员权限"

    # 询问是否立即配置SSH密钥
    echo ""
    read -p "是否为新用户配置SSH密钥? (Y/n): " setup_ssh
    if [[ ! "$setup_ssh" =~ ^[Nn]$ ]]; then
        setup_user_ssh_key "$new_username"
    fi

    read -p "按回车键继续..."
}

setup_user_ssh_key() {
    local username="$1"
    local user_home="/home/$username"
    local ssh_dir="$user_home/.ssh"

    log_info "为用户 $username 配置SSH密钥..."

    echo ""
    echo "SSH密钥配置选项:"
    echo "1. 生成新的SSH密钥对"
    echo "2. 导入现有公钥"
    echo "3. 跳过SSH密钥配置"
    echo ""

    read -p "请选择 [1-3]: " ssh_choice

    case $ssh_choice in
        1)
            # 生成新密钥对
            log_info "生成SSH密钥对..."

            read -p "请输入密钥注释 (如邮箱地址): " key_comment
            key_comment=${key_comment:-"$username@$(hostname)"}

            # 生成密钥
            ssh_key_path="$ssh_dir/id_rsa"
            if sudo -u "$username" ssh-keygen -t rsa -b 4096 -C "$key_comment" -f "$ssh_key_path" -N ""; then
                log_success "SSH密钥对生成成功"

                # 设置authorized_keys
                cat "$ssh_key_path.pub" > "$ssh_dir/authorized_keys"
                chmod 600 "$ssh_dir/authorized_keys"
                chown "$username:$username" "$ssh_dir/authorized_keys"

                log_success "公钥已添加到authorized_keys"

                # 显示私钥
                echo ""
                log_info "请保存以下私钥到本地计算机:"
                echo "----------------------------------------"
                cat "$ssh_key_path"
                echo "----------------------------------------"
                echo ""
                log_warn "私钥显示完毕，请妥善保存！"

            else
                log_error "SSH密钥生成失败"
            fi
            ;;
        2)
            # 导入现有公钥
            echo ""
            echo "请粘贴SSH公钥内容 (以ssh-rsa, ssh-ed25519等开头):"
            read -r public_key

            if [[ -n "$public_key" && "$public_key" =~ ^ssh- ]]; then
                echo "$public_key" > "$ssh_dir/authorized_keys"
                chmod 600 "$ssh_dir/authorized_keys"
                chown "$username:$username" "$ssh_dir/authorized_keys"
                log_success "SSH公钥导入成功"
            else
                log_error "无效的SSH公钥格式"
            fi
            ;;
        3)
            log_info "跳过SSH密钥配置"
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

configure_user_permissions() {
    log_info "配置用户权限..."

    # 显示当前用户列表
    echo ""
    echo "当前系统用户 (UID >= 1000):"
    echo "----------------------------------------"
    while IFS=: read -r username _ uid gid _ _ home shell; do
        if [[ $uid -ge 1000 && "$username" != "nobody" ]]; then
            groups_info=$(groups "$username" 2>/dev/null | cut -d: -f2)
            echo "用户: $username (UID: $uid)"
            echo "  主目录: $home"
            echo "  Shell: $shell"
            echo "  用户组:$groups_info"
            echo ""
        fi
    done < /etc/passwd
    echo "----------------------------------------"

    read -p "请输入要配置的用户名: " target_user

    if ! id "$target_user" &>/dev/null; then
        log_error "用户 $target_user 不存在"
        read -p "按回车键继续..."
        return 1
    fi

    echo ""
    echo "权限配置选项:"
    echo "1. 添加sudo权限"
    echo "2. 移除sudo权限"
    echo "3. 锁定用户账户"
    echo "4. 解锁用户账户"
    echo "5. 修改用户Shell"
    echo "6. 返回上级菜单"
    echo ""

    read -p "请选择 [1-6]: " perm_choice

    case $perm_choice in
        1)
            if usermod -aG sudo "$target_user"; then
                log_success "已为用户 $target_user 添加sudo权限"
            else
                log_error "添加sudo权限失败"
            fi
            ;;
        2)
            if gpasswd -d "$target_user" sudo; then
                log_success "已移除用户 $target_user 的sudo权限"
            else
                log_error "移除sudo权限失败"
            fi
            ;;
        3)
            if usermod -L "$target_user"; then
                log_success "用户 $target_user 已被锁定"
            else
                log_error "锁定用户失败"
            fi
            ;;
        4)
            if usermod -U "$target_user"; then
                log_success "用户 $target_user 已被解锁"
            else
                log_error "解锁用户失败"
            fi
            ;;
        5)
            echo ""
            echo "可用Shell:"
            cat /etc/shells
            echo ""
            read -p "请输入新的Shell路径: " new_shell

            if [[ -x "$new_shell" ]]; then
                if usermod -s "$new_shell" "$target_user"; then
                    log_success "用户 $target_user 的Shell已修改为: $new_shell"
                else
                    log_error "修改Shell失败"
                fi
            else
                log_error "无效的Shell路径: $new_shell"
            fi
            ;;
        6)
            return
            ;;
        *)
            log_error "无效选择"
            ;;
    esac

    read -p "按回车键继续..."
}

set_password_policy() {
    log_info "设置密码策略..."

    # 检查是否安装了libpam-pwquality
    if ! dpkg -l | grep -q libpam-pwquality 2>/dev/null && ! rpm -q libpwquality &>/dev/null; then
        log_info "安装密码质量检查工具..."
        case $PACKAGE_MANAGER in
            apt)
                install_package "libpam-pwquality"
                ;;
            yum)
                install_package "libpwquality"
                ;;
        esac
    fi

    echo ""
    echo "密码策略配置选项:"
    echo "1. 设置基础密码策略 (推荐)"
    echo "2. 设置严格密码策略"
    echo "3. 自定义密码策略"
    echo "4. 查看当前密码策略"
    echo "5. 返回上级菜单"
    echo ""

    read -p "请选择 [1-5]: " policy_choice

    case $policy_choice in
        1)
            set_basic_password_policy
            ;;
        2)
            set_strict_password_policy
            ;;
        3)
            set_custom_password_policy
            ;;
        4)
            show_current_password_policy
            ;;
        5)
            return
            ;;
        *)
            log_error "无效选择"
            ;;
    esac

    read -p "按回车键继续..."
}

set_basic_password_policy() {
    log_info "设置基础密码策略..."

    # 备份原配置
    backup_file "/etc/pam.d/common-password" "common-password" 2>/dev/null || true
    backup_file "/etc/login.defs" "login-defs"

    # 配置PAM密码策略
    if [[ -f "/etc/pam.d/common-password" ]]; then
        # Ubuntu/Debian
        sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
        sed -i '/password.*pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 maxrepeat=3 reject_username' /etc/pam.d/common-password
    elif [[ -f "/etc/pam.d/system-auth" ]]; then
        # CentOS/RHEL
        sed -i '/pam_pwquality.so/d' /etc/pam.d/system-auth
        sed -i '/password.*pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 maxrepeat=3 reject_username' /etc/pam.d/system-auth
    fi

    # 配置密码过期策略
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

    log_success "基础密码策略设置完成"
    log_info "策略要求:"
    log_info "- 最小长度: 8位"
    log_info "- 必须包含: 大写字母、小写字母、数字"
    log_info "- 最大重复字符: 3个"
    log_info "- 密码有效期: 90天"
    log_info "- 密码更改间隔: 1天"
}

set_strict_password_policy() {
    log_info "设置严格密码策略..."

    # 备份原配置
    backup_file "/etc/pam.d/common-password" "common-password" 2>/dev/null || true
    backup_file "/etc/login.defs" "login-defs"

    # 配置严格PAM密码策略
    if [[ -f "/etc/pam.d/common-password" ]]; then
        sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
        sed -i '/password.*pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 difok=4 ucredit=-2 lcredit=-2 dcredit=-2 ocredit=-1 maxrepeat=2 reject_username enforce_for_root' /etc/pam.d/common-password
    elif [[ -f "/etc/pam.d/system-auth" ]]; then
        sed -i '/pam_pwquality.so/d' /etc/pam.d/system-auth
        sed -i '/password.*pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 difok=4 ucredit=-2 lcredit=-2 dcredit=-2 ocredit=-1 maxrepeat=2 reject_username enforce_for_root' /etc/pam.d/system-auth
    fi

    # 配置严格密码过期策略
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 2/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs

    log_success "严格密码策略设置完成"
    log_info "策略要求:"
    log_info "- 最小长度: 12位"
    log_info "- 必须包含: 至少2个大写字母、2个小写字母、2个数字、1个特殊字符"
    log_info "- 最大重复字符: 2个"
    log_info "- 密码有效期: 60天"
    log_info "- 密码更改间隔: 2天"
    log_info "- 对root用户也强制执行"
}

set_custom_password_policy() {
    log_info "自定义密码策略..."

    echo ""
    read -p "最小密码长度 [8]: " min_len
    min_len=${min_len:-8}

    read -p "最小大写字母数量 [1]: " ucredit
    ucredit=${ucredit:-1}

    read -p "最小小写字母数量 [1]: " lcredit
    lcredit=${lcredit:-1}

    read -p "最小数字数量 [1]: " dcredit
    dcredit=${dcredit:-1}

    read -p "最小特殊字符数量 [0]: " ocredit
    ocredit=${ocredit:-0}

    read -p "最大重复字符数量 [3]: " maxrepeat
    maxrepeat=${maxrepeat:-3}

    read -p "密码有效期(天) [90]: " max_days
    max_days=${max_days:-90}

    read -p "密码更改间隔(天) [1]: " min_days
    min_days=${min_days:-1}

    # 备份原配置
    backup_file "/etc/pam.d/common-password" "common-password" 2>/dev/null || true
    backup_file "/etc/login.defs" "login-defs"

    # 应用自定义策略
    local pam_rule="password requisite pam_pwquality.so retry=3 minlen=$min_len ucredit=-$ucredit lcredit=-$lcredit dcredit=-$dcredit ocredit=-$ocredit maxrepeat=$maxrepeat reject_username"

    if [[ -f "/etc/pam.d/common-password" ]]; then
        sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
        sed -i "/password.*pam_unix.so/i $pam_rule" /etc/pam.d/common-password
    elif [[ -f "/etc/pam.d/system-auth" ]]; then
        sed -i '/pam_pwquality.so/d' /etc/pam.d/system-auth
        sed -i "/password.*pam_unix.so/i $pam_rule" /etc/pam.d/system-auth
    fi

    # 配置密码过期策略
    sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS $max_days/" /etc/login.defs
    sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS $min_days/" /etc/login.defs

    log_success "自定义密码策略设置完成"
}

show_current_password_policy() {
    log_info "当前密码策略:"
    echo ""

    # 显示PAM配置
    echo "PAM密码质量配置:"
    if [[ -f "/etc/pam.d/common-password" ]]; then
        grep "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null || echo "未配置PAM密码质量检查"
    elif [[ -f "/etc/pam.d/system-auth" ]]; then
        grep "pam_pwquality.so" /etc/pam.d/system-auth 2>/dev/null || echo "未配置PAM密码质量检查"
    fi

    echo ""
    echo "密码过期策略:"
    grep -E "^PASS_(MAX|MIN|WARN)_" /etc/login.defs 2>/dev/null || echo "使用默认过期策略"
}

show_user_info() {
    log_info "显示用户信息..."

    echo ""
    echo "=== 系统用户概览 ==="
    echo ""

    # 显示普通用户
    echo "普通用户 (UID >= 1000):"
    echo "----------------------------------------"
    local user_count=0
    while IFS=: read -r username _ uid gid _ _ home shell; do
        if [[ $uid -ge 1000 && "$username" != "nobody" ]]; then
            ((user_count++))
            echo "用户: $username"
            echo "  UID: $uid"
            echo "  主目录: $home"
            echo "  Shell: $shell"

            # 显示用户组
            groups_info=$(groups "$username" 2>/dev/null | cut -d: -f2)
            echo "  用户组:$groups_info"

            # 检查sudo权限
            if groups "$username" | grep -q sudo; then
                echo "  权限: 管理员 (sudo)"
            else
                echo "  权限: 普通用户"
            fi

            # 检查账户状态
            if passwd -S "$username" 2>/dev/null | grep -q " L "; then
                echo "  状态: 已锁定"
            else
                echo "  状态: 正常"
            fi

            # 检查SSH密钥
            ssh_dir="$home/.ssh"
            if [[ -f "$ssh_dir/authorized_keys" ]]; then
                key_count=$(wc -l < "$ssh_dir/authorized_keys" 2>/dev/null || echo "0")
                echo "  SSH密钥: $key_count 个"
            else
                echo "  SSH密钥: 未配置"
            fi

            echo ""
        fi
    done < /etc/passwd

    if [[ $user_count -eq 0 ]]; then
        echo "未找到普通用户"
    fi

    echo "----------------------------------------"
    echo "总计: $user_count 个普通用户"

    # 显示当前登录用户
    echo ""
    echo "当前登录用户:"
    who 2>/dev/null || echo "无法获取登录信息"

    read -p "按回车键继续..."
}

# ========================================
# SSH安全配置模块
# ========================================

get_current_ssh_port() {
    # 从SSH配置文件获取当前端口
    local port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ -z "$port" ]]; then
        port="22"  # 默认端口
    fi
    echo "$port"
}

detect_ssh_service() {
    # 检测SSH服务名称 (ssh 或 sshd)
    if systemctl list-units --type=service | grep -q "ssh.service"; then
        echo "ssh"
    elif systemctl list-units --type=service | grep -q "sshd.service"; then
        echo "sshd"
    else
        # 尝试检测可用的服务
        if [[ -f "/lib/systemd/system/ssh.service" ]] || [[ -f "/etc/systemd/system/ssh.service" ]]; then
            echo "ssh"
        elif [[ -f "/lib/systemd/system/sshd.service" ]] || [[ -f "/etc/systemd/system/sshd.service" ]]; then
            echo "sshd"
        else
            echo "ssh"  # 默认使用ssh
        fi
    fi
}

validate_ssh_port() {
    local port="$1"

    # 检查端口范围
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
        return 1
    fi

    # 检查是否为系统保留端口 (除了22)
    if [[ $port -lt 1024 && $port -ne 22 ]]; then
        return 1
    fi

    # 检查端口是否被占用 (除了当前SSH端口)
    local current_port=$(get_current_ssh_port)
    if [[ $port -ne $current_port ]] && netstat -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi

    return 0
}

change_ssh_port() {
    log_info "修改SSH端口..."

    local current_port=$(get_current_ssh_port)
    local ssh_service=$(detect_ssh_service)

    log_info "当前SSH端口: $current_port"
    log_info "SSH服务名称: $ssh_service"

    echo ""
    echo "建议的SSH端口范围:"
    echo "- 1024-65535 (非系统保留端口)"
    echo "- 避免常用端口: 80, 443, 3389, 8080等"
    echo "- 推荐端口: 2222, 2022, 10022, 22222等"
    echo ""

    while true; do
        read -p "请输入新的SSH端口 [2222]: " new_port
        new_port=${new_port:-2222}

        if ! validate_ssh_port "$new_port"; then
            log_error "无效的端口号: $new_port"
            log_info "端口要求: 1-65535，避免系统保留端口(1-1023，除22外)"
            continue
        fi

        if [[ $new_port -eq $current_port ]]; then
            log_info "端口未改变，保持当前设置"
            read -p "按回车键继续..."
            return 0
        fi

        break
    done

    # 确认修改
    echo ""
    log_warn "即将修改SSH端口: $current_port -> $new_port"
    log_warn "修改后需要使用新端口连接: ssh -p $new_port user@server"
    echo ""
    read -p "确认修改SSH端口? (y/N): " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "取消修改"
        read -p "按回车键继续..."
        return 0
    fi

    # 备份SSH配置
    backup_file "/etc/ssh/sshd_config" "sshd_config"

    # 修改SSH配置
    log_info "修改SSH配置文件..."
    if grep -q "^Port " /etc/ssh/sshd_config; then
        sed -i "s/^Port .*/Port $new_port/" /etc/ssh/sshd_config
    else
        echo "Port $new_port" >> /etc/ssh/sshd_config
    fi

    # 测试SSH配置
    log_info "测试SSH配置..."
    if sshd -t; then
        log_success "SSH配置语法正确"
    else
        log_error "SSH配置语法错误，恢复原配置"
        restore_ssh_config
        read -p "按回车键继续..."
        return 1
    fi

    # 更新防火墙规则
    update_firewall_for_ssh "$new_port" "$current_port"

    # 重启SSH服务
    log_info "重启SSH服务..."
    if systemctl restart "$ssh_service"; then
        log_success "SSH服务重启成功"
    else
        log_error "SSH服务重启失败，恢复原配置"
        restore_ssh_config
        systemctl restart "$ssh_service"
        read -p "按回车键继续..."
        return 1
    fi

    # 更新配置文件
    sed -i "s/^SSH_PORT=.*/SSH_PORT=$new_port/" "$CONFIG_FILE" 2>/dev/null || true

    log_success "SSH端口修改完成: $new_port"
    log_warn "请使用新端口重新连接: ssh -p $new_port user@$(hostname -I | awk '{print $1}')"
    log_info "当前连接会话在断开后无法重连，请确保新端口可用"

    read -p "按回车键继续..."
}

restore_ssh_config() {
    local backup_file=$(ls -t "$BACKUP_DIR"/sshd_config_*.backup 2>/dev/null | head -1)
    if [[ -n "$backup_file" ]]; then
        cp "$backup_file" /etc/ssh/sshd_config
        log_info "SSH配置已恢复"
    fi
}

update_firewall_for_ssh() {
    local new_port="$1"
    local old_port="$2"

    if command -v ufw &> /dev/null; then
        log_info "更新UFW防火墙规则..."

        # 添加新端口
        ufw allow "$new_port/tcp" comment "SSH"

        # 询问是否删除旧端口规则
        if [[ "$old_port" != "$new_port" && "$old_port" != "22" ]]; then
            read -p "是否删除旧SSH端口 $old_port 的防火墙规则? (Y/n): " remove_old
            if [[ ! "$remove_old" =~ ^[Nn]$ ]]; then
                ufw delete allow "$old_port/tcp"
                log_info "已删除旧端口防火墙规则: $old_port"
            fi
        fi

        log_success "防火墙规则更新完成"
    fi
}

manage_ssh_keys() {
    log_info "管理SSH密钥..."

    echo ""
    echo "SSH密钥管理选项:"
    echo "1. 为当前用户生成SSH密钥"
    echo "2. 为指定用户生成SSH密钥"
    echo "3. 导入SSH公钥"
    echo "4. 查看SSH密钥"
    echo "5. 删除SSH密钥"
    echo "6. 返回上级菜单"
    echo ""

    read -p "请选择 [1-6]: " key_choice

    case $key_choice in
        1) generate_ssh_key_current_user ;;
        2) generate_ssh_key_for_user ;;
        3) import_ssh_public_key ;;
        4) show_ssh_keys ;;
        5) delete_ssh_key ;;
        6) return ;;
        *) log_error "无效选择" ;;
    esac

    read -p "按回车键继续..."
}

generate_ssh_key_current_user() {
    local current_user=$(whoami)
    local user_home="$HOME"
    local ssh_dir="$user_home/.ssh"

    log_info "为当前用户 $current_user 生成SSH密钥..."

    # 创建SSH目录
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"

    # 检查是否已存在密钥
    if [[ -f "$ssh_dir/id_rsa" ]]; then
        log_warn "SSH密钥已存在: $ssh_dir/id_rsa"
        read -p "是否覆盖现有密钥? (y/N): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            log_info "取消生成密钥"
            return
        fi
    fi

    # 获取密钥参数
    echo ""
    echo "密钥类型选项:"
    echo "1. RSA 4096位 (推荐)"
    echo "2. RSA 2048位"
    echo "3. ED25519 (现代加密)"
    echo ""

    read -p "请选择密钥类型 [1]: " key_type_choice
    key_type_choice=${key_type_choice:-1}

    case $key_type_choice in
        1) key_type="rsa"; key_bits="4096" ;;
        2) key_type="rsa"; key_bits="2048" ;;
        3) key_type="ed25519"; key_bits="" ;;
        *) key_type="rsa"; key_bits="4096" ;;
    esac

    read -p "请输入密钥注释 (如邮箱地址) [$current_user@$(hostname)]: " key_comment
    key_comment=${key_comment:-"$current_user@$(hostname)"}

    # 生成密钥
    local key_file="$ssh_dir/id_$key_type"
    log_info "生成SSH密钥..."

    if [[ "$key_type" == "ed25519" ]]; then
        ssh-keygen -t ed25519 -C "$key_comment" -f "$key_file" -N ""
    else
        ssh-keygen -t rsa -b "$key_bits" -C "$key_comment" -f "$key_file" -N ""
    fi

    if [[ $? -eq 0 ]]; then
        log_success "SSH密钥生成成功"

        # 设置权限
        chmod 600 "$key_file"
        chmod 644 "$key_file.pub"

        # 显示公钥
        echo ""
        log_info "SSH公钥内容:"
        echo "----------------------------------------"
        cat "$key_file.pub"
        echo "----------------------------------------"

        # 询问是否添加到authorized_keys
        read -p "是否将公钥添加到authorized_keys? (Y/n): " add_to_auth
        if [[ ! "$add_to_auth" =~ ^[Nn]$ ]]; then
            cat "$key_file.pub" >> "$ssh_dir/authorized_keys"
            chmod 600 "$ssh_dir/authorized_keys"
            log_success "公钥已添加到authorized_keys"
        fi

    else
        log_error "SSH密钥生成失败"
    fi
}

generate_ssh_key_for_user() {
    read -p "请输入用户名: " target_user

    if ! id "$target_user" &>/dev/null; then
        log_error "用户 $target_user 不存在"
        return 1
    fi

    setup_user_ssh_key "$target_user"
}

import_ssh_public_key() {
    log_info "导入SSH公钥..."

    read -p "请输入目标用户名: " target_user

    if ! id "$target_user" &>/dev/null; then
        log_error "用户 $target_user 不存在"
        return 1
    fi

    local user_home=$(eval echo "~$target_user")
    local ssh_dir="$user_home/.ssh"

    # 创建SSH目录
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$target_user:$target_user" "$ssh_dir"

    echo ""
    echo "请粘贴SSH公钥内容 (以ssh-rsa, ssh-ed25519等开头):"
    read -r public_key

    if [[ -z "$public_key" ]]; then
        log_error "公钥内容不能为空"
        return 1
    fi

    if [[ ! "$public_key" =~ ^ssh- ]]; then
        log_error "无效的SSH公钥格式"
        return 1
    fi

    # 添加到authorized_keys
    echo "$public_key" >> "$ssh_dir/authorized_keys"
    chmod 600 "$ssh_dir/authorized_keys"
    chown "$target_user:$target_user" "$ssh_dir/authorized_keys"

    log_success "SSH公钥已导入用户 $target_user"
}

show_ssh_keys() {
    log_info "查看SSH密钥..."

    echo ""
    echo "=== 系统SSH密钥概览 ==="
    echo ""

    # 遍历所有用户的SSH密钥
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ $uid -ge 1000 || "$username" == "root" ]]; then
            local ssh_dir="$home/.ssh"

            if [[ -d "$ssh_dir" ]]; then
                echo "用户: $username"
                echo "SSH目录: $ssh_dir"

                # 检查私钥
                local private_keys=()
                for key_file in "$ssh_dir"/id_*; do
                    if [[ -f "$key_file" && ! "$key_file" =~ \.pub$ ]]; then
                        private_keys+=("$(basename "$key_file")")
                    fi
                done

                if [[ ${#private_keys[@]} -gt 0 ]]; then
                    echo "  私钥: ${private_keys[*]}"
                else
                    echo "  私钥: 无"
                fi

                # 检查authorized_keys
                if [[ -f "$ssh_dir/authorized_keys" ]]; then
                    local key_count=$(wc -l < "$ssh_dir/authorized_keys")
                    echo "  授权密钥: $key_count 个"

                    # 显示公钥指纹
                    echo "  密钥指纹:"
                    while read -r key; do
                        if [[ -n "$key" && "$key" =~ ^ssh- ]]; then
                            local fingerprint=$(echo "$key" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
                            local comment=$(echo "$key" | awk '{print $3}')
                            echo "    $fingerprint ($comment)"
                        fi
                    done < "$ssh_dir/authorized_keys"
                else
                    echo "  授权密钥: 无"
                fi

                echo ""
            fi
        fi
    done < /etc/passwd
}

delete_ssh_key() {
    log_info "删除SSH密钥..."

    read -p "请输入用户名: " target_user

    if ! id "$target_user" &>/dev/null; then
        log_error "用户 $target_user 不存在"
        return 1
    fi

    local user_home=$(eval echo "~$target_user")
    local ssh_dir="$user_home/.ssh"

    if [[ ! -d "$ssh_dir" ]]; then
        log_error "用户 $target_user 没有SSH目录"
        return 1
    fi

    echo ""
    echo "删除选项:"
    echo "1. 删除指定私钥"
    echo "2. 清空authorized_keys"
    echo "3. 删除整个SSH目录"
    echo "4. 取消"
    echo ""

    read -p "请选择 [1-4]: " delete_choice

    case $delete_choice in
        1)
            # 列出私钥文件
            echo ""
            echo "可用的私钥文件:"
            local key_files=()
            local i=1
            for key_file in "$ssh_dir"/id_*; do
                if [[ -f "$key_file" && ! "$key_file" =~ \.pub$ ]]; then
                    echo "$i. $(basename "$key_file")"
                    key_files+=("$key_file")
                    ((i++))
                fi
            done

            if [[ ${#key_files[@]} -eq 0 ]]; then
                log_error "没有找到私钥文件"
                return 1
            fi

            read -p "请选择要删除的私钥 [1-${#key_files[@]}]: " key_index

            if [[ $key_index -ge 1 && $key_index -le ${#key_files[@]} ]]; then
                local selected_key="${key_files[$((key_index-1))]}"
                log_warn "即将删除私钥: $selected_key"
                read -p "确认删除? (y/N): " confirm

                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    rm -f "$selected_key" "$selected_key.pub"
                    log_success "私钥已删除: $(basename "$selected_key")"
                fi
            else
                log_error "无效选择"
            fi
            ;;
        2)
            if [[ -f "$ssh_dir/authorized_keys" ]]; then
                log_warn "即将清空 $target_user 的authorized_keys"
                read -p "确认清空? (y/N): " confirm

                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    > "$ssh_dir/authorized_keys"
                    log_success "authorized_keys已清空"
                fi
            else
                log_error "authorized_keys文件不存在"
            fi
            ;;
        3)
            log_warn "即将删除 $target_user 的整个SSH目录: $ssh_dir"
            log_warn "这将删除所有SSH密钥和配置"
            read -p "确认删除? (y/N): " confirm

            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                rm -rf "$ssh_dir"
                log_success "SSH目录已删除"
            fi
            ;;
        4)
            log_info "取消删除"
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

disable_password_auth() {
    log_info "禁用SSH密码登录..."

    # 检查是否有用户配置了SSH密钥
    local users_with_keys=()
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ $uid -ge 1000 || "$username" == "root" ]]; then
            if [[ -f "$home/.ssh/authorized_keys" ]] && [[ -s "$home/.ssh/authorized_keys" ]]; then
                users_with_keys+=("$username")
            fi
        fi
    done < /etc/passwd

    if [[ ${#users_with_keys[@]} -eq 0 ]]; then
        log_error "没有用户配置SSH密钥，禁用密码登录可能导致无法连接"
        log_warn "请先为至少一个用户配置SSH密钥"
        read -p "是否强制继续? (y/N): " force_continue

        if [[ ! "$force_continue" =~ ^[Yy]$ ]]; then
            log_info "取消禁用密码登录"
            return 0
        fi
    else
        log_info "检测到以下用户已配置SSH密钥:"
        for user in "${users_with_keys[@]}"; do
            echo "  - $user"
        done
    fi

    echo ""
    log_warn "禁用密码登录后，只能使用SSH密钥登录"
    read -p "确认禁用SSH密码登录? (y/N): " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "取消禁用密码登录"
        return 0
    fi

    # 备份SSH配置
    backup_file "/etc/ssh/sshd_config" "sshd_config"

    # 修改SSH配置
    log_info "修改SSH配置..."

    # 禁用密码认证
    if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    else
        echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    fi

    # 禁用质询响应认证
    if grep -q "^ChallengeResponseAuthentication" /etc/ssh/sshd_config; then
        sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    else
        echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
    fi

    # 禁用PAM认证 (可选)
    if grep -q "^UsePAM" /etc/ssh/sshd_config; then
        sed -i 's/^UsePAM.*/UsePAM no/' /etc/ssh/sshd_config
    else
        echo "UsePAM no" >> /etc/ssh/sshd_config
    fi

    # 测试SSH配置
    if sshd -t; then
        log_success "SSH配置语法正确"

        # 重启SSH服务
        local ssh_service=$(detect_ssh_service)
        if systemctl restart "$ssh_service"; then
            log_success "SSH密码登录已禁用"
            log_info "现在只能使用SSH密钥登录"

            # 更新配置文件
            sed -i "s/^PASSWORD_AUTH=.*/PASSWORD_AUTH=no/" "$CONFIG_FILE" 2>/dev/null || true
        else
            log_error "SSH服务重启失败，恢复原配置"
            restore_ssh_config
            systemctl restart "$ssh_service"
        fi
    else
        log_error "SSH配置语法错误，恢复原配置"
        restore_ssh_config
    fi

    read -p "按回车键继续..."
}

disable_root_login() {
    log_info "禁用SSH root登录..."

    # 检查是否有其他管理员用户
    local admin_users=()
    while IFS=: read -r username _ uid _ _ _ _; do
        if [[ $uid -ge 1000 ]] && groups "$username" 2>/dev/null | grep -q sudo; then
            admin_users+=("$username")
        fi
    done < /etc/passwd

    if [[ ${#admin_users[@]} -eq 0 ]]; then
        log_error "没有其他管理员用户，禁用root登录可能导致无法管理系统"
        log_warn "请先创建一个具有sudo权限的用户"
        read -p "是否强制继续? (y/N): " force_continue

        if [[ ! "$force_continue" =~ ^[Yy]$ ]]; then
            log_info "取消禁用root登录"
            return 0
        fi
    else
        log_info "检测到以下管理员用户:"
        for user in "${admin_users[@]}"; do
            echo "  - $user"
        done
    fi

    echo ""
    echo "Root登录禁用选项:"
    echo "1. 完全禁用root登录"
    echo "2. 禁用root密码登录，允许密钥登录"
    echo "3. 取消"
    echo ""

    read -p "请选择 [1-3]: " root_choice

    case $root_choice in
        1) root_login_setting="no" ;;
        2) root_login_setting="prohibit-password" ;;
        3) log_info "取消禁用root登录"; return 0 ;;
        *) log_error "无效选择"; return 1 ;;
    esac

    # 备份SSH配置
    backup_file "/etc/ssh/sshd_config" "sshd_config"

    # 修改SSH配置
    log_info "修改SSH配置..."

    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sed -i "s/^PermitRootLogin.*/PermitRootLogin $root_login_setting/" /etc/ssh/sshd_config
    else
        echo "PermitRootLogin $root_login_setting" >> /etc/ssh/sshd_config
    fi

    # 测试SSH配置
    if sshd -t; then
        log_success "SSH配置语法正确"

        # 重启SSH服务
        local ssh_service=$(detect_ssh_service)
        if systemctl restart "$ssh_service"; then
            if [[ "$root_login_setting" == "no" ]]; then
                log_success "SSH root登录已完全禁用"
            else
                log_success "SSH root密码登录已禁用，仍可使用密钥登录"
            fi

            # 更新配置文件
            sed -i "s/^ROOT_LOGIN=.*/ROOT_LOGIN=$root_login_setting/" "$CONFIG_FILE" 2>/dev/null || true
        else
            log_error "SSH服务重启失败，恢复原配置"
            restore_ssh_config
            systemctl restart "$ssh_service"
        fi
    else
        log_error "SSH配置语法错误，恢复原配置"
        restore_ssh_config
    fi

    read -p "按回车键继续..."
}

optimize_ssh_config() {
    log_info "SSH配置优化..."

    echo ""
    echo "SSH优化选项:"
    echo "1. 应用推荐的安全配置"
    echo "2. 自定义SSH配置"
    echo "3. 查看当前SSH配置"
    echo "4. 返回上级菜单"
    echo ""

    read -p "请选择 [1-4]: " opt_choice

    case $opt_choice in
        1) apply_recommended_ssh_config ;;
        2) custom_ssh_config ;;
        3) show_current_ssh_config ;;
        4) return ;;
        *) log_error "无效选择" ;;
    esac

    read -p "按回车键继续..."
}

apply_recommended_ssh_config() {
    log_info "应用推荐的SSH安全配置..."

    echo ""
    log_info "推荐配置包括:"
    echo "- 禁用SSH协议版本1"
    echo "- 设置登录超时时间"
    echo "- 限制最大认证尝试次数"
    echo "- 禁用空密码登录"
    echo "- 禁用X11转发"
    echo "- 启用严格模式"
    echo ""

    read -p "确认应用推荐配置? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "取消配置优化"
        return 0
    fi

    # 备份SSH配置
    backup_file "/etc/ssh/sshd_config" "sshd_config"

    # 应用推荐配置
    log_info "应用安全配置..."

    # 创建临时配置文件
    local temp_config="/tmp/sshd_config_optimized"
    cp /etc/ssh/sshd_config "$temp_config"

    # 应用各项配置
    apply_ssh_setting "$temp_config" "Protocol" "2"
    apply_ssh_setting "$temp_config" "LoginGraceTime" "60"
    apply_ssh_setting "$temp_config" "MaxAuthTries" "3"
    apply_ssh_setting "$temp_config" "MaxSessions" "10"
    apply_ssh_setting "$temp_config" "PermitEmptyPasswords" "no"
    apply_ssh_setting "$temp_config" "X11Forwarding" "no"
    apply_ssh_setting "$temp_config" "StrictModes" "yes"
    apply_ssh_setting "$temp_config" "IgnoreRhosts" "yes"
    apply_ssh_setting "$temp_config" "HostbasedAuthentication" "no"
    apply_ssh_setting "$temp_config" "PermitUserEnvironment" "no"
    apply_ssh_setting "$temp_config" "ClientAliveInterval" "300"
    apply_ssh_setting "$temp_config" "ClientAliveCountMax" "2"
    apply_ssh_setting "$temp_config" "TCPKeepAlive" "no"
    apply_ssh_setting "$temp_config" "Compression" "no"

    # 测试配置
    if sshd -t -f "$temp_config"; then
        log_success "SSH配置测试通过"

        # 应用配置
        cp "$temp_config" /etc/ssh/sshd_config
        rm -f "$temp_config"

        # 重启SSH服务
        local ssh_service=$(detect_ssh_service)
        if systemctl restart "$ssh_service"; then
            log_success "SSH配置优化完成"
        else
            log_error "SSH服务重启失败，恢复原配置"
            restore_ssh_config
            systemctl restart "$ssh_service"
        fi
    else
        log_error "SSH配置测试失败，恢复原配置"
        rm -f "$temp_config"
    fi
}

apply_ssh_setting() {
    local config_file="$1"
    local setting="$2"
    local value="$3"

    if grep -q "^$setting " "$config_file"; then
        sed -i "s/^$setting .*/$setting $value/" "$config_file"
    else
        echo "$setting $value" >> "$config_file"
    fi
}

custom_ssh_config() {
    log_info "自定义SSH配置..."

    echo ""
    echo "可配置的SSH参数:"
    echo "1. 登录超时时间 (LoginGraceTime)"
    echo "2. 最大认证尝试次数 (MaxAuthTries)"
    echo "3. 最大会话数 (MaxSessions)"
    echo "4. 客户端存活检测间隔 (ClientAliveInterval)"
    echo "5. 客户端存活检测次数 (ClientAliveCountMax)"
    echo "6. 返回上级菜单"
    echo ""

    read -p "请选择要配置的参数 [1-6]: " param_choice

    case $param_choice in
        1)
            read -p "请输入登录超时时间(秒) [60]: " login_grace_time
            login_grace_time=${login_grace_time:-60}
            modify_ssh_parameter "LoginGraceTime" "$login_grace_time"
            ;;
        2)
            read -p "请输入最大认证尝试次数 [3]: " max_auth_tries
            max_auth_tries=${max_auth_tries:-3}
            modify_ssh_parameter "MaxAuthTries" "$max_auth_tries"
            ;;
        3)
            read -p "请输入最大会话数 [10]: " max_sessions
            max_sessions=${max_sessions:-10}
            modify_ssh_parameter "MaxSessions" "$max_sessions"
            ;;
        4)
            read -p "请输入客户端存活检测间隔(秒) [300]: " client_alive_interval
            client_alive_interval=${client_alive_interval:-300}
            modify_ssh_parameter "ClientAliveInterval" "$client_alive_interval"
            ;;
        5)
            read -p "请输入客户端存活检测次数 [2]: " client_alive_count
            client_alive_count=${client_alive_count:-2}
            modify_ssh_parameter "ClientAliveCountMax" "$client_alive_count"
            ;;
        6)
            return
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

modify_ssh_parameter() {
    local parameter="$1"
    local value="$2"

    # 备份SSH配置
    backup_file "/etc/ssh/sshd_config" "sshd_config"

    # 修改参数
    if grep -q "^$parameter " /etc/ssh/sshd_config; then
        sed -i "s/^$parameter .*/$parameter $value/" /etc/ssh/sshd_config
    else
        echo "$parameter $value" >> /etc/ssh/sshd_config
    fi

    # 测试配置
    if sshd -t; then
        log_success "SSH配置修改成功: $parameter = $value"

        # 重启SSH服务
        local ssh_service=$(detect_ssh_service)
        if systemctl restart "$ssh_service"; then
            log_success "SSH服务重启成功"
        else
            log_error "SSH服务重启失败，恢复原配置"
            restore_ssh_config
            systemctl restart "$ssh_service"
        fi
    else
        log_error "SSH配置语法错误，恢复原配置"
        restore_ssh_config
    fi
}

show_current_ssh_config() {
    log_info "当前SSH配置:"
    echo ""

    echo "=== 主要SSH配置参数 ==="
    echo "端口: $(get_current_ssh_port)"
    echo "协议版本: $(grep "^Protocol " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "2 (默认)")"
    echo "Root登录: $(grep "^PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (默认)")"
    echo "密码认证: $(grep "^PasswordAuthentication " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (默认)")"
    echo "公钥认证: $(grep "^PubkeyAuthentication " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (默认)")"
    echo "空密码登录: $(grep "^PermitEmptyPasswords " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "no (默认)")"
    echo "X11转发: $(grep "^X11Forwarding " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (默认)")"
    echo "登录超时: $(grep "^LoginGraceTime " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "120 (默认)")"
    echo "最大认证尝试: $(grep "^MaxAuthTries " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "6 (默认)")"
    echo "最大会话数: $(grep "^MaxSessions " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "10 (默认)")"
    echo "客户端存活间隔: $(grep "^ClientAliveInterval " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "0 (默认)")"
    echo "客户端存活次数: $(grep "^ClientAliveCountMax " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "3 (默认)")"

    echo ""
    echo "=== SSH服务状态 ==="
    local ssh_service=$(detect_ssh_service)
    echo "服务名称: $ssh_service"
    echo "服务状态: $(systemctl is-active "$ssh_service")"
    echo "开机启动: $(systemctl is-enabled "$ssh_service")"

    # 显示监听端口
    echo ""
    echo "=== 监听端口 ==="
    netstat -tlnp 2>/dev/null | grep sshd || ss -tlnp | grep sshd
}

show_ssh_status() {
    log_info "SSH服务状态检查..."

    local ssh_service=$(detect_ssh_service)
    local current_port=$(get_current_ssh_port)

    echo ""
    echo "=== SSH服务状态 ==="
    echo "服务名称: $ssh_service"
    echo "服务状态: $(systemctl is-active "$ssh_service")"
    echo "开机启动: $(systemctl is-enabled "$ssh_service")"
    echo "当前端口: $current_port"

    # 检查端口监听状态
    echo ""
    echo "=== 端口监听状态 ==="
    if netstat -tlnp 2>/dev/null | grep -q ":$current_port.*sshd" || ss -tlnp 2>/dev/null | grep -q ":$current_port.*sshd"; then
        echo "✓ SSH端口 $current_port 正在监听"
    else
        echo "✗ SSH端口 $current_port 未监听"
    fi

    # 检查防火墙状态
    echo ""
    echo "=== 防火墙状态 ==="
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            echo "UFW防火墙: 已启用"
            if ufw status | grep -q "$current_port/tcp"; then
                echo "✓ SSH端口 $current_port 已在防火墙中开放"
            else
                echo "✗ SSH端口 $current_port 未在防火墙中开放"
            fi
        else
            echo "UFW防火墙: 未启用"
        fi
    else
        echo "UFW防火墙: 未安装"
    fi

    # 显示最近的SSH连接
    echo ""
    echo "=== 最近SSH连接 (最后10条) ==="
    journalctl -u "$ssh_service" -n 10 --no-pager 2>/dev/null | grep -E "(Accepted|Failed)" || echo "无法获取SSH连接日志"

    # 显示当前SSH会话
    echo ""
    echo "=== 当前SSH会话 ==="
    who | grep -E "pts|tty" || echo "无活动SSH会话"

    read -p "按回车键继续..."
}

# ========================================
# 防火墙管理模块
# ========================================

check_ufw_installed() {
    if ! command -v ufw &> /dev/null; then
        log_warn "UFW防火墙未安装"
        read -p "是否安装UFW防火墙? (Y/n): " install_ufw

        if [[ ! "$install_ufw" =~ ^[Nn]$ ]]; then
            log_info "安装UFW防火墙..."
            if install_package "ufw"; then
                log_success "UFW防火墙安装完成"
                return 0
            else
                log_error "UFW防火墙安装失败"
                return 1
            fi
        else
            log_info "取消安装UFW防火墙"
            return 1
        fi
    fi
    return 0
}

get_firewall_status() {
    if ! command -v ufw &> /dev/null; then
        echo "not_installed"
        return
    fi

    if ufw status | grep -q "Status: active"; then
        echo "active"
    else
        echo "inactive"
    fi
}

detect_running_services() {
    log_info "检测运行中的服务端口..."

    local services=()

    # 检测常见服务端口
    local common_ports=(
        "22:SSH"
        "80:HTTP"
        "443:HTTPS"
        "21:FTP"
        "25:SMTP"
        "53:DNS"
        "110:POP3"
        "143:IMAP"
        "993:IMAPS"
        "995:POP3S"
        "3306:MySQL"
        "5432:PostgreSQL"
        "6379:Redis"
        "27017:MongoDB"
    )

    for port_info in "${common_ports[@]}"; do
        local port=$(echo "$port_info" | cut -d: -f1)
        local service=$(echo "$port_info" | cut -d: -f2)

        if netstat -tlnp 2>/dev/null | grep -q ":$port " || ss -tlnp 2>/dev/null | grep -q ":$port "; then
            services+=("$port:$service")
        fi
    done

    # 检测自定义端口
    local custom_ports=$(netstat -tlnp 2>/dev/null | awk '/LISTEN/ {print $4}' | cut -d: -f2 | sort -n | uniq)
    for port in $custom_ports; do
        local found=false
        for port_info in "${common_ports[@]}"; do
            local known_port=$(echo "$port_info" | cut -d: -f1)
            if [[ "$port" == "$known_port" ]]; then
                found=true
                break
            fi
        done

        if [[ "$found" == false && "$port" =~ ^[0-9]+$ ]]; then
            services+=("$port:Custom")
        fi
    done

    printf '%s\n' "${services[@]}"
}

toggle_firewall() {
    log_info "防火墙状态管理..."

    if ! check_ufw_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    local status=$(get_firewall_status)

    echo ""
    echo "当前防火墙状态: $status"
    echo ""

    if [[ "$status" == "active" ]]; then
        echo "防火墙管理选项:"
        echo "1. 禁用防火墙"
        echo "2. 重启防火墙"
        echo "3. 查看防火墙状态"
        echo "4. 返回上级菜单"
        echo ""

        read -p "请选择 [1-4]: " choice

        case $choice in
            1)
                log_warn "即将禁用防火墙，这可能降低系统安全性"
                read -p "确认禁用防火墙? (y/N): " confirm

                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    if ufw disable; then
                        log_success "防火墙已禁用"
                        sed -i "s/^UFW_ENABLED=.*/UFW_ENABLED=no/" "$CONFIG_FILE" 2>/dev/null || true
                    else
                        log_error "防火墙禁用失败"
                    fi
                fi
                ;;
            2)
                if ufw reload; then
                    log_success "防火墙已重启"
                else
                    log_error "防火墙重启失败"
                fi
                ;;
            3)
                show_firewall_status
                return
                ;;
            4)
                return
                ;;
            *)
                log_error "无效选择"
                ;;
        esac
    else
        echo "防火墙管理选项:"
        echo "1. 启用防火墙"
        echo "2. 配置并启用防火墙"
        echo "3. 返回上级菜单"
        echo ""

        read -p "请选择 [1-3]: " choice

        case $choice in
            1)
                enable_firewall_basic
                ;;
            2)
                configure_basic_rules
                ;;
            3)
                return
                ;;
            *)
                log_error "无效选择"
                ;;
        esac
    fi

    read -p "按回车键继续..."
}

enable_firewall_basic() {
    log_info "启用基础防火墙配置..."

    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing

    # 自动添加SSH端口
    local ssh_port=$(get_current_ssh_port)
    log_info "添加SSH端口: $ssh_port"
    ufw allow "$ssh_port/tcp" comment "SSH"

    # 启用防火墙
    if ufw --force enable; then
        log_success "防火墙已启用"
        sed -i "s/^UFW_ENABLED=.*/UFW_ENABLED=yes/" "$CONFIG_FILE" 2>/dev/null || true

        # 显示当前规则
        echo ""
        log_info "当前防火墙规则:"
        ufw status numbered
    else
        log_error "防火墙启用失败"
    fi
}

configure_basic_rules() {
    log_info "配置基础防火墙规则..."

    if ! check_ufw_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    echo ""
    log_info "检测系统服务..."
    local services=($(detect_running_services))

    if [[ ${#services[@]} -gt 0 ]]; then
        echo ""
        echo "检测到以下运行中的服务:"
        for service in "${services[@]}"; do
            local port=$(echo "$service" | cut -d: -f1)
            local name=$(echo "$service" | cut -d: -f2)
            echo "  - 端口 $port ($name)"
        done
        echo ""
    fi

    # 设置默认策略
    log_info "设置默认策略..."
    ufw default deny incoming
    ufw default allow outgoing

    # 自动添加SSH端口
    local ssh_port=$(get_current_ssh_port)
    log_info "添加SSH端口: $ssh_port"
    ufw allow "$ssh_port/tcp" comment "SSH"

    # 询问是否添加常用服务端口
    echo ""
    echo "是否添加以下常用服务端口?"

    local common_services=(
        "80:HTTP Web服务"
        "443:HTTPS Web服务"
        "25:SMTP 邮件发送"
        "110:POP3 邮件接收"
        "143:IMAP 邮件接收"
        "993:IMAPS 安全邮件"
        "995:POP3S 安全邮件"
    )

    for service_info in "${common_services[@]}"; do
        local port=$(echo "$service_info" | cut -d: -f1)
        local desc=$(echo "$service_info" | cut -d: -f2)

        # 检查端口是否在运行
        local is_running=false
        for running_service in "${services[@]}"; do
            local running_port=$(echo "$running_service" | cut -d: -f1)
            if [[ "$port" == "$running_port" ]]; then
                is_running=true
                break
            fi
        done

        if [[ "$is_running" == true ]]; then
            read -p "添加端口 $port ($desc) - 检测到服务运行中? (Y/n): " add_port
        else
            read -p "添加端口 $port ($desc)? (y/N): " add_port
        fi

        if [[ "$add_port" =~ ^[Yy]$ ]] || ([[ "$is_running" == true ]] && [[ ! "$add_port" =~ ^[Nn]$ ]]); then
            ufw allow "$port/tcp" comment "$desc"
            log_success "已添加端口: $port ($desc)"
        fi
    done

    # 询问是否添加自定义端口
    echo ""
    read -p "是否添加自定义端口? (y/N): " add_custom

    if [[ "$add_custom" =~ ^[Yy]$ ]]; then
        add_custom_ports
    fi

    # 启用防火墙
    echo ""
    log_info "启用防火墙..."
    if ufw --force enable; then
        log_success "防火墙配置完成并已启用"
        sed -i "s/^UFW_ENABLED=.*/UFW_ENABLED=yes/" "$CONFIG_FILE" 2>/dev/null || true

        # 显示最终规则
        echo ""
        log_info "最终防火墙规则:"
        ufw status numbered
    else
        log_error "防火墙启用失败"
    fi

    read -p "按回车键继续..."
}

add_custom_ports() {
    while true; do
        echo ""
        read -p "请输入端口号 (或输入 'done' 完成): " custom_port

        if [[ "$custom_port" == "done" ]]; then
            break
        fi

        if [[ ! "$custom_port" =~ ^[0-9]+$ ]] || [[ $custom_port -lt 1 ]] || [[ $custom_port -gt 65535 ]]; then
            log_error "无效的端口号: $custom_port"
            continue
        fi

        echo "协议选择:"
        echo "1. TCP"
        echo "2. UDP"
        echo "3. 两者都添加"

        read -p "请选择协议 [1]: " protocol_choice
        protocol_choice=${protocol_choice:-1}

        read -p "请输入端口描述 (可选): " port_desc
        port_desc=${port_desc:-"Custom port $custom_port"}

        case $protocol_choice in
            1)
                ufw allow "$custom_port/tcp" comment "$port_desc"
                log_success "已添加TCP端口: $custom_port"
                ;;
            2)
                ufw allow "$custom_port/udp" comment "$port_desc"
                log_success "已添加UDP端口: $custom_port"
                ;;
            3)
                ufw allow "$custom_port/tcp" comment "$port_desc (TCP)"
                ufw allow "$custom_port/udp" comment "$port_desc (UDP)"
                log_success "已添加TCP/UDP端口: $custom_port"
                ;;
            *)
                log_error "无效选择，跳过端口: $custom_port"
                ;;
        esac
    done
}

manage_port_rules() {
    log_info "管理端口规则..."

    if ! check_ufw_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    local status=$(get_firewall_status)
    if [[ "$status" != "active" ]]; then
        log_warn "防火墙未启用"
        read -p "是否启用防火墙? (Y/n): " enable_fw

        if [[ ! "$enable_fw" =~ ^[Nn]$ ]]; then
            enable_firewall_basic
        else
            read -p "按回车键继续..."
            return
        fi
    fi

    while true; do
        echo ""
        echo "端口规则管理:"
        echo "1. 添加端口规则"
        echo "2. 删除端口规则"
        echo "3. 查看所有规则"
        echo "4. 批量管理端口"
        echo "5. 返回上级菜单"
        echo ""

        read -p "请选择 [1-5]: " rule_choice

        case $rule_choice in
            1) add_port_rule ;;
            2) delete_port_rule ;;
            3) show_all_rules ;;
            4) batch_manage_ports ;;
            5) break ;;
            *) log_error "无效选择" ;;
        esac
    done

    read -p "按回车键继续..."
}

add_port_rule() {
    echo ""
    echo "添加端口规则:"

    read -p "请输入端口号: " port

    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
        log_error "无效的端口号: $port"
        return 1
    fi

    echo ""
    echo "协议选择:"
    echo "1. TCP"
    echo "2. UDP"
    echo "3. 两者都添加"

    read -p "请选择协议 [1]: " protocol_choice
    protocol_choice=${protocol_choice:-1}

    echo ""
    echo "规则类型:"
    echo "1. 允许 (allow)"
    echo "2. 拒绝 (deny)"
    echo "3. 限制 (limit) - 防止暴力破解"

    read -p "请选择规则类型 [1]: " rule_type_choice
    rule_type_choice=${rule_type_choice:-1}

    case $rule_type_choice in
        1) rule_type="allow" ;;
        2) rule_type="deny" ;;
        3) rule_type="limit" ;;
        *) rule_type="allow" ;;
    esac

    read -p "请输入规则描述 (可选): " rule_desc

    # 构建UFW命令
    local ufw_cmd="ufw $rule_type"
    local comment_text=""

    if [[ -n "$rule_desc" ]]; then
        comment_text=" comment \"$rule_desc\""
    fi

    case $protocol_choice in
        1)
            eval "$ufw_cmd $port/tcp$comment_text"
            log_success "已添加TCP端口规则: $port ($rule_type)"
            ;;
        2)
            eval "$ufw_cmd $port/udp$comment_text"
            log_success "已添加UDP端口规则: $port ($rule_type)"
            ;;
        3)
            eval "$ufw_cmd $port/tcp$comment_text"
            eval "$ufw_cmd $port/udp$comment_text"
            log_success "已添加TCP/UDP端口规则: $port ($rule_type)"
            ;;
        *)
            log_error "无效的协议选择"
            return 1
            ;;
    esac
}

delete_port_rule() {
    echo ""
    echo "删除端口规则:"

    # 显示当前规则
    echo ""
    log_info "当前防火墙规则:"
    ufw status numbered

    echo ""
    echo "删除方式:"
    echo "1. 按规则编号删除"
    echo "2. 按端口删除"
    echo "3. 取消"

    read -p "请选择删除方式 [1]: " delete_method
    delete_method=${delete_method:-1}

    case $delete_method in
        1)
            read -p "请输入要删除的规则编号: " rule_number

            if [[ "$rule_number" =~ ^[0-9]+$ ]]; then
                if ufw delete "$rule_number"; then
                    log_success "规则已删除"
                else
                    log_error "删除规则失败"
                fi
            else
                log_error "无效的规则编号"
            fi
            ;;
        2)
            read -p "请输入要删除的端口号: " port

            if [[ ! "$port" =~ ^[0-9]+$ ]]; then
                log_error "无效的端口号"
                return 1
            fi

            echo ""
            echo "协议选择:"
            echo "1. TCP"
            echo "2. UDP"
            echo "3. 两者都删除"

            read -p "请选择协议 [1]: " protocol_choice
            protocol_choice=${protocol_choice:-1}

            case $protocol_choice in
                1)
                    if ufw delete allow "$port/tcp" 2>/dev/null || ufw delete deny "$port/tcp" 2>/dev/null || ufw delete limit "$port/tcp" 2>/dev/null; then
                        log_success "TCP端口规则已删除: $port"
                    else
                        log_error "未找到TCP端口规则: $port"
                    fi
                    ;;
                2)
                    if ufw delete allow "$port/udp" 2>/dev/null || ufw delete deny "$port/udp" 2>/dev/null || ufw delete limit "$port/udp" 2>/dev/null; then
                        log_success "UDP端口规则已删除: $port"
                    else
                        log_error "未找到UDP端口规则: $port"
                    fi
                    ;;
                3)
                    local tcp_deleted=false
                    local udp_deleted=false

                    if ufw delete allow "$port/tcp" 2>/dev/null || ufw delete deny "$port/tcp" 2>/dev/null || ufw delete limit "$port/tcp" 2>/dev/null; then
                        tcp_deleted=true
                    fi

                    if ufw delete allow "$port/udp" 2>/dev/null || ufw delete deny "$port/udp" 2>/dev/null || ufw delete limit "$port/udp" 2>/dev/null; then
                        udp_deleted=true
                    fi

                    if [[ "$tcp_deleted" == true ]] || [[ "$udp_deleted" == true ]]; then
                        log_success "端口规则已删除: $port"
                    else
                        log_error "未找到端口规则: $port"
                    fi
                    ;;
                *)
                    log_error "无效的协议选择"
                    ;;
            esac
            ;;
        3)
            log_info "取消删除"
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

show_all_rules() {
    echo ""
    log_info "所有防火墙规则:"
    echo ""

    # 显示详细状态
    ufw status verbose

    echo ""
    read -p "按回车键继续..."
}

batch_manage_ports() {
    echo ""
    echo "批量端口管理:"
    echo "1. 批量添加端口"
    echo "2. 批量删除端口"
    echo "3. 导入端口列表"
    echo "4. 导出端口列表"
    echo "5. 返回上级菜单"
    echo ""

    read -p "请选择 [1-5]: " batch_choice

    case $batch_choice in
        1) batch_add_ports ;;
        2) batch_delete_ports ;;
        3) import_port_list ;;
        4) export_port_list ;;
        5) return ;;
        *) log_error "无效选择" ;;
    esac
}

batch_add_ports() {
    echo ""
    log_info "批量添加端口 (用空格分隔多个端口)"
    read -p "请输入端口列表: " port_list

    if [[ -z "$port_list" ]]; then
        log_error "端口列表不能为空"
        return 1
    fi

    echo ""
    echo "协议选择:"
    echo "1. TCP"
    echo "2. UDP"
    echo "3. 两者都添加"

    read -p "请选择协议 [1]: " protocol_choice
    protocol_choice=${protocol_choice:-1}

    read -p "请输入批量描述前缀 (可选): " desc_prefix

    local added_count=0
    local failed_count=0

    for port in $port_list; do
        if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
            log_warn "跳过无效端口: $port"
            ((failed_count++))
            continue
        fi

        local comment=""
        if [[ -n "$desc_prefix" ]]; then
            comment=" comment \"$desc_prefix $port\""
        fi

        case $protocol_choice in
            1)
                if eval "ufw allow $port/tcp$comment"; then
                    ((added_count++))
                else
                    ((failed_count++))
                fi
                ;;
            2)
                if eval "ufw allow $port/udp$comment"; then
                    ((added_count++))
                else
                    ((failed_count++))
                fi
                ;;
            3)
                local tcp_success=false
                local udp_success=false

                if eval "ufw allow $port/tcp$comment"; then
                    tcp_success=true
                fi

                if eval "ufw allow $port/udp$comment"; then
                    udp_success=true
                fi

                if [[ "$tcp_success" == true ]] || [[ "$udp_success" == true ]]; then
                    ((added_count++))
                else
                    ((failed_count++))
                fi
                ;;
        esac
    done

    log_success "批量添加完成: 成功 $added_count 个，失败 $failed_count 个"
}

batch_delete_ports() {
    echo ""
    log_info "批量删除端口 (用空格分隔多个端口)"
    read -p "请输入端口列表: " port_list

    if [[ -z "$port_list" ]]; then
        log_error "端口列表不能为空"
        return 1
    fi

    echo ""
    echo "协议选择:"
    echo "1. TCP"
    echo "2. UDP"
    echo "3. 两者都删除"

    read -p "请选择协议 [1]: " protocol_choice
    protocol_choice=${protocol_choice:-1}

    local deleted_count=0
    local failed_count=0

    for port in $port_list; do
        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            log_warn "跳过无效端口: $port"
            ((failed_count++))
            continue
        fi

        local success=false

        case $protocol_choice in
            1)
                if ufw delete allow "$port/tcp" 2>/dev/null || ufw delete deny "$port/tcp" 2>/dev/null || ufw delete limit "$port/tcp" 2>/dev/null; then
                    success=true
                fi
                ;;
            2)
                if ufw delete allow "$port/udp" 2>/dev/null || ufw delete deny "$port/udp" 2>/dev/null || ufw delete limit "$port/udp" 2>/dev/null; then
                    success=true
                fi
                ;;
            3)
                if ufw delete allow "$port/tcp" 2>/dev/null || ufw delete deny "$port/tcp" 2>/dev/null || ufw delete limit "$port/tcp" 2>/dev/null; then
                    success=true
                fi
                if ufw delete allow "$port/udp" 2>/dev/null || ufw delete deny "$port/udp" 2>/dev/null || ufw delete limit "$port/udp" 2>/dev/null; then
                    success=true
                fi
                ;;
        esac

        if [[ "$success" == true ]]; then
            ((deleted_count++))
        else
            ((failed_count++))
        fi
    done

    log_success "批量删除完成: 成功 $deleted_count 个，失败 $failed_count 个"
}

import_port_list() {
    echo ""
    read -p "请输入端口列表文件路径: " file_path

    if [[ ! -f "$file_path" ]]; then
        log_error "文件不存在: $file_path"
        return 1
    fi

    log_info "从文件导入端口列表: $file_path"

    local imported_count=0
    local failed_count=0

    while IFS= read -r line; do
        # 跳过空行和注释行
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # 解析端口和协议 (格式: port/protocol 或 port)
        local port protocol="tcp"

        if [[ "$line" =~ ^([0-9]+)/(tcp|udp)$ ]]; then
            port="${BASH_REMATCH[1]}"
            protocol="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ ^[0-9]+$ ]]; then
            port="$line"
        else
            log_warn "跳过无效行: $line"
            ((failed_count++))
            continue
        fi

        if ufw allow "$port/$protocol"; then
            ((imported_count++))
        else
            ((failed_count++))
        fi

    done < "$file_path"

    log_success "导入完成: 成功 $imported_count 个，失败 $failed_count 个"
}

export_port_list() {
    echo ""
    local export_file="/tmp/ufw_ports_$(date +%Y%m%d_%H%M%S).txt"

    log_info "导出端口列表到: $export_file"

    # 导出当前UFW规则
    {
        echo "# UFW端口规则导出 - $(date)"
        echo "# 格式: port/protocol"
        echo ""

        ufw status | grep -E "^[0-9]" | awk '{print $1}' | sort -n

    } > "$export_file"

    log_success "端口列表已导出到: $export_file"

    echo ""
    read -p "是否查看导出内容? (y/N): " view_content
    if [[ "$view_content" =~ ^[Yy]$ ]]; then
        cat "$export_file"
    fi
}

show_firewall_status() {
    log_info "防火墙状态检查..."

    if ! command -v ufw &> /dev/null; then
        log_error "UFW防火墙未安装"
        read -p "按回车键继续..."
        return 1
    fi

    echo ""
    echo "=== UFW防火墙状态 ==="

    local status=$(get_firewall_status)
    echo "状态: $status"

    if [[ "$status" == "active" ]]; then
        echo ""
        echo "=== 详细状态信息 ==="
        ufw status verbose

        echo ""
        echo "=== 规则统计 ==="
        local total_rules=$(ufw status numbered | grep -c "^\[")
        local allow_rules=$(ufw status | grep -c "ALLOW")
        local deny_rules=$(ufw status | grep -c "DENY")
        local limit_rules=$(ufw status | grep -c "LIMIT")

        echo "总规则数: $total_rules"
        echo "允许规则: $allow_rules"
        echo "拒绝规则: $deny_rules"
        echo "限制规则: $limit_rules"

        echo ""
        echo "=== 默认策略 ==="
        ufw status verbose | grep "Default:"

        echo ""
        echo "=== 监听端口检查 ==="
        check_listening_ports

        echo ""
        echo "=== 防火墙日志 ==="
        if [[ -f "/var/log/ufw.log" ]]; then
            echo "最近10条防火墙日志:"
            tail -10 /var/log/ufw.log 2>/dev/null | grep -E "(BLOCK|ALLOW|DENY)" || echo "无相关日志"
        else
            echo "防火墙日志文件不存在"
        fi

    else
        echo ""
        log_warn "防火墙未启用"
        echo ""
        echo "建议操作:"
        echo "1. 启用基础防火墙配置"
        echo "2. 配置并启用防火墙"
        echo ""

        read -p "是否现在启用防火墙? (Y/n): " enable_now
        if [[ ! "$enable_now" =~ ^[Nn]$ ]]; then
            enable_firewall_basic
        fi
    fi

    read -p "按回车键继续..."
}

check_listening_ports() {
    log_info "检查监听端口与防火墙规则匹配情况..."

    # 获取所有监听端口
    local listening_ports=()
    while read -r line; do
        local port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            listening_ports+=("$port")
        fi
    done < <(netstat -tlnp 2>/dev/null | grep LISTEN)

    # 获取UFW允许的端口
    local allowed_ports=()
    while read -r line; do
        if [[ "$line" =~ ^([0-9]+)/(tcp|udp) ]]; then
            allowed_ports+=("${BASH_REMATCH[1]}")
        fi
    done < <(ufw status | grep ALLOW | awk '{print $1}')

    echo ""
    echo "端口匹配检查:"

    # 检查监听端口是否在防火墙规则中
    for port in "${listening_ports[@]}"; do
        local found=false
        for allowed in "${allowed_ports[@]}"; do
            if [[ "$port" == "$allowed" ]]; then
                found=true
                break
            fi
        done

        if [[ "$found" == true ]]; then
            echo "✓ 端口 $port: 监听中，已在防火墙规则中"
        else
            echo "⚠ 端口 $port: 监听中，但未在防火墙规则中"
        fi
    done

    # 检查防火墙规则中的端口是否在监听
    for allowed in "${allowed_ports[@]}"; do
        local found=false
        for port in "${listening_ports[@]}"; do
            if [[ "$allowed" == "$port" ]]; then
                found=true
                break
            fi
        done

        if [[ "$found" == false ]]; then
            echo "ℹ 端口 $allowed: 防火墙已开放，但无服务监听"
        fi
    done
}

reset_firewall() {
    log_info "重置防火墙配置..."

    if ! command -v ufw &> /dev/null; then
        log_error "UFW防火墙未安装"
        read -p "按回车键继续..."
        return 1
    fi

    echo ""
    log_warn "重置防火墙将删除所有自定义规则"
    log_warn "这可能会影响当前的网络连接"
    echo ""

    # 显示当前规则
    echo "当前防火墙规则:"
    ufw status numbered
    echo ""

    read -p "确认重置防火墙配置? (y/N): " confirm_reset

    if [[ ! "$confirm_reset" =~ ^[Yy]$ ]]; then
        log_info "取消重置"
        read -p "按回车键继续..."
        return 0
    fi

    # 备份当前配置
    local backup_file="$BACKUP_DIR/ufw_rules_$(date +%Y%m%d_%H%M%S).backup"
    mkdir -p "$BACKUP_DIR"

    log_info "备份当前防火墙规则..."
    {
        echo "# UFW规则备份 - $(date)"
        echo "# 状态: $(get_firewall_status)"
        echo ""
        ufw status verbose
    } > "$backup_file"

    log_success "规则已备份到: $backup_file"

    # 重置UFW
    log_info "重置UFW配置..."
    if ufw --force reset; then
        log_success "防火墙配置已重置"

        # 询问是否重新配置基础规则
        echo ""
        read -p "是否重新配置基础防火墙规则? (Y/n): " reconfig

        if [[ ! "$reconfig" =~ ^[Nn]$ ]]; then
            configure_basic_rules
        else
            log_info "防火墙已重置但未启用"
            log_warn "请记得重新配置防火墙规则"
        fi

        # 更新配置文件
        sed -i "s/^UFW_ENABLED=.*/UFW_ENABLED=no/" "$CONFIG_FILE" 2>/dev/null || true

    else
        log_error "防火墙重置失败"
    fi

    read -p "按回车键继续..."
}

# ========================================
# Fail2Ban入侵防护模块
# ========================================

check_fail2ban_installed() {
    if ! command -v fail2ban-server &> /dev/null; then
        log_warn "Fail2Ban未安装"
        read -p "是否安装Fail2Ban? (Y/n): " install_f2b

        if [[ ! "$install_f2b" =~ ^[Nn]$ ]]; then
            log_info "安装Fail2Ban..."
            if install_package "fail2ban"; then
                log_success "Fail2Ban安装完成"

                # 启用并启动服务
                systemctl enable fail2ban
                systemctl start fail2ban

                return 0
            else
                log_error "Fail2Ban安装失败"
                return 1
            fi
        else
            log_info "取消安装Fail2Ban"
            return 1
        fi
    fi
    return 0
}

get_fail2ban_status() {
    if ! command -v fail2ban-server &> /dev/null; then
        echo "not_installed"
        return
    fi

    if systemctl is-active --quiet fail2ban; then
        echo "active"
    else
        echo "inactive"
    fi
}

setup_fail2ban() {
    log_info "设置Fail2Ban入侵防护..."

    if ! check_fail2ban_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    local status=$(get_fail2ban_status)
    log_info "Fail2Ban状态: $status"

    if [[ "$status" != "active" ]]; then
        log_info "启动Fail2Ban服务..."
        systemctl start fail2ban
        systemctl enable fail2ban
    fi

    echo ""
    echo "Fail2Ban配置选项:"
    echo "1. 快速配置 (推荐设置)"
    echo "2. 自定义配置"
    echo "3. 查看当前配置"
    echo "4. 返回上级菜单"
    echo ""

    read -p "请选择 [1-4]: " config_choice

    case $config_choice in
        1) setup_fail2ban_quick ;;
        2) setup_fail2ban_custom ;;
        3) show_fail2ban_config ;;
        4) return ;;
        *) log_error "无效选择" ;;
    esac

    read -p "按回车键继续..."
}

setup_fail2ban_quick() {
    log_info "快速配置Fail2Ban..."

    # 备份原配置
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        backup_file "/etc/fail2ban/jail.local" "jail.local"
    fi

    # 获取SSH端口
    local ssh_port=$(get_current_ssh_port)

    # 创建基础配置
    log_info "创建Fail2Ban配置文件..."

    cat > /etc/fail2ban/jail.local << EOF
# Fail2Ban配置 - VPS Security Tool生成
# 生成时间: $(date)

[DEFAULT]
# 忽略的IP地址 (白名单)
ignoreip = 127.0.0.1/8 ::1

# 封禁时间 (秒)
bantime = 3600

# 查找时间窗口 (秒)
findtime = 600

# 最大重试次数
maxretry = 5

# 后端类型
backend = auto

# 邮件设置 (可选)
# destemail = admin@example.com
# sender = fail2ban@example.com
# mta = sendmail

# 动作设置
action = %(action_)s

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1800
findtime = 300

[sshd-ddos]
enabled = true
port = $ssh_port
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 3600
findtime = 300

EOF

    # 检查是否有Web服务运行
    if netstat -tlnp 2>/dev/null | grep -q ":80\|:443" || ss -tlnp 2>/dev/null | grep -q ":80\|:443"; then
        log_info "检测到Web服务，添加HTTP防护规则..."

        cat >> /etc/fail2ban/jail.local << EOF

# Web服务防护
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 3
bantime = 3600

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache*/*access.log
maxretry = 2
bantime = 86400

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache*/*access.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600

EOF
    fi

    # 重启Fail2Ban服务
    log_info "重启Fail2Ban服务..."
    if systemctl restart fail2ban; then
        log_success "Fail2Ban快速配置完成"

        # 更新配置文件
        sed -i "s/^FAIL2BAN_ENABLED=.*/FAIL2BAN_ENABLED=yes/" "$CONFIG_FILE" 2>/dev/null || true

        # 显示配置摘要
        echo ""
        log_info "配置摘要:"
        echo "- SSH防护: 启用 (端口 $ssh_port)"
        echo "- 封禁时间: 30分钟 (SSH), 1小时 (其他)"
        echo "- 最大重试: 3次 (SSH), 2-5次 (其他)"
        echo "- 查找窗口: 5分钟 (SSH), 10分钟 (其他)"

        if netstat -tlnp 2>/dev/null | grep -q ":80\|:443"; then
            echo "- Web防护: 启用"
        fi

    else
        log_error "Fail2Ban服务重启失败"
        log_info "检查配置文件语法..."
        fail2ban-client -t 2>/dev/null || log_error "配置文件语法错误"
    fi
}

setup_fail2ban_custom() {
    log_info "自定义Fail2Ban配置..."

    echo ""
    echo "自定义配置选项:"
    echo "1. 修改全局设置"
    echo "2. 配置SSH防护"
    echo "3. 配置Web防护"
    echo "4. 添加自定义规则"
    echo "5. 返回上级菜单"
    echo ""

    read -p "请选择 [1-5]: " custom_choice

    case $custom_choice in
        1) configure_fail2ban_global ;;
        2) configure_fail2ban_ssh ;;
        3) configure_fail2ban_web ;;
        4) add_custom_fail2ban_rule ;;
        5) return ;;
        *) log_error "无效选择" ;;
    esac
}

configure_fail2ban_global() {
    log_info "配置Fail2Ban全局设置..."

    echo ""
    read -p "默认封禁时间(秒) [3600]: " ban_time
    ban_time=${ban_time:-3600}

    read -p "查找时间窗口(秒) [600]: " find_time
    find_time=${find_time:-600}

    read -p "最大重试次数 [5]: " max_retry
    max_retry=${max_retry:-5}

    echo ""
    echo "白名单IP地址 (用空格分隔，回车跳过):"
    read -p "IP地址: " ignore_ips

    # 备份配置
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        backup_file "/etc/fail2ban/jail.local" "jail.local"
    fi

    # 更新全局配置
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        echo "[DEFAULT]" > /etc/fail2ban/jail.local
    fi

    # 更新或添加配置项
    update_fail2ban_config "bantime" "$ban_time"
    update_fail2ban_config "findtime" "$find_time"
    update_fail2ban_config "maxretry" "$max_retry"

    if [[ -n "$ignore_ips" ]]; then
        local ignore_list="127.0.0.1/8 ::1 $ignore_ips"
        update_fail2ban_config "ignoreip" "$ignore_list"
    fi

    # 重启服务
    if systemctl restart fail2ban; then
        log_success "全局配置更新完成"
    else
        log_error "配置更新失败，请检查语法"
    fi
}

update_fail2ban_config() {
    local key="$1"
    local value="$2"
    local config_file="/etc/fail2ban/jail.local"

    if grep -q "^$key = " "$config_file"; then
        sed -i "s/^$key = .*/$key = $value/" "$config_file"
    else
        # 在[DEFAULT]段落下添加
        sed -i "/^\[DEFAULT\]/a $key = $value" "$config_file"
    fi
}

configure_fail2ban_ssh() {
    log_info "配置SSH防护规则..."

    local ssh_port=$(get_current_ssh_port)

    echo ""
    echo "当前SSH端口: $ssh_port"
    echo ""

    read -p "SSH最大重试次数 [3]: " ssh_maxretry
    ssh_maxretry=${ssh_maxretry:-3}

    read -p "SSH封禁时间(秒) [1800]: " ssh_bantime
    ssh_bantime=${ssh_bantime:-1800}

    read -p "SSH查找窗口(秒) [300]: " ssh_findtime
    ssh_findtime=${ssh_findtime:-300}

    # 备份配置
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        backup_file "/etc/fail2ban/jail.local" "jail.local"
    fi

    # 创建或更新SSH规则
    if ! grep -q "^\[sshd\]" /etc/fail2ban/jail.local 2>/dev/null; then
        cat >> /etc/fail2ban/jail.local << EOF

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = $ssh_maxretry
bantime = $ssh_bantime
findtime = $ssh_findtime

EOF
    else
        # 更新现有配置
        sed -i "/^\[sshd\]/,/^\[/ {
            s/^port = .*/port = $ssh_port/
            s/^maxretry = .*/maxretry = $ssh_maxretry/
            s/^bantime = .*/bantime = $ssh_bantime/
            s/^findtime = .*/findtime = $ssh_findtime/
        }" /etc/fail2ban/jail.local
    fi

    # 重启服务
    if systemctl restart fail2ban; then
        log_success "SSH防护配置更新完成"
    else
        log_error "配置更新失败"
    fi
}

configure_fail2ban_web() {
    log_info "配置Web服务防护..."

    # 检查是否有Web服务运行
    local has_apache=false
    local has_nginx=false

    if systemctl is-active --quiet apache2 || systemctl is-active --quiet httpd; then
        has_apache=true
    fi

    if systemctl is-active --quiet nginx; then
        has_nginx=true
    fi

    if [[ "$has_apache" == false && "$has_nginx" == false ]]; then
        log_warn "未检测到运行中的Web服务"
        read -p "是否仍要配置Web防护? (y/N): " force_web

        if [[ ! "$force_web" =~ ^[Yy]$ ]]; then
            log_info "跳过Web防护配置"
            return
        fi
    fi

    echo ""
    echo "Web服务防护选项:"
    if [[ "$has_apache" == true ]]; then
        echo "✓ Apache服务已检测到"
    fi
    if [[ "$has_nginx" == true ]]; then
        echo "✓ Nginx服务已检测到"
    fi
    echo ""

    read -p "Web服务最大重试次数 [3]: " web_maxretry
    web_maxretry=${web_maxretry:-3}

    read -p "Web服务封禁时间(秒) [3600]: " web_bantime
    web_bantime=${web_bantime:-3600}

    read -p "Web服务查找窗口(秒) [600]: " web_findtime
    web_findtime=${web_findtime:-600}

    # 备份配置
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        backup_file "/etc/fail2ban/jail.local" "jail.local"
    fi

    # 添加Web防护规则
    if [[ "$has_apache" == true ]]; then
        cat >> /etc/fail2ban/jail.local << EOF

# Apache防护
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = $web_maxretry
bantime = $web_bantime
findtime = $web_findtime

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache*/*access.log
maxretry = 2
bantime = 86400
findtime = $web_findtime

EOF
    fi

    if [[ "$has_nginx" == true ]]; then
        cat >> /etc/fail2ban/jail.local << EOF

# Nginx防护
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = $web_maxretry
bantime = $web_bantime
findtime = $web_findtime

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = $web_bantime
findtime = $web_findtime

EOF
    fi

    # 重启服务
    if systemctl restart fail2ban; then
        log_success "Web防护配置完成"
    else
        log_error "配置更新失败"
    fi
}

add_custom_fail2ban_rule() {
    log_info "添加自定义Fail2Ban规则..."

    echo ""
    read -p "请输入规则名称: " rule_name

    if [[ -z "$rule_name" ]]; then
        log_error "规则名称不能为空"
        return 1
    fi

    read -p "请输入监控端口 (如: 22, http,https): " rule_port
    read -p "请输入过滤器名称 (如: sshd): " rule_filter
    read -p "请输入日志文件路径: " rule_logpath
    read -p "最大重试次数 [5]: " rule_maxretry
    rule_maxretry=${rule_maxretry:-5}

    read -p "封禁时间(秒) [3600]: " rule_bantime
    rule_bantime=${rule_bantime:-3600}

    read -p "查找窗口(秒) [600]: " rule_findtime
    rule_findtime=${rule_findtime:-600}

    # 验证日志文件是否存在
    if [[ ! -f "$rule_logpath" ]]; then
        log_warn "日志文件不存在: $rule_logpath"
        read -p "是否仍要添加规则? (y/N): " force_add

        if [[ ! "$force_add" =~ ^[Yy]$ ]]; then
            log_info "取消添加规则"
            return
        fi
    fi

    # 添加自定义规则
    cat >> /etc/fail2ban/jail.local << EOF

# 自定义规则: $rule_name
[$rule_name]
enabled = true
port = $rule_port
filter = $rule_filter
logpath = $rule_logpath
maxretry = $rule_maxretry
bantime = $rule_bantime
findtime = $rule_findtime

EOF

    # 重启服务
    if systemctl restart fail2ban; then
        log_success "自定义规则添加完成: $rule_name"
    else
        log_error "规则添加失败，请检查配置"
    fi
}

show_fail2ban_config() {
    log_info "当前Fail2Ban配置:"

    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        log_warn "未找到自定义配置文件"
        echo ""
        echo "默认配置位置: /etc/fail2ban/jail.conf"
        read -p "是否查看默认配置? (y/N): " show_default

        if [[ "$show_default" =~ ^[Yy]$ ]]; then
            echo ""
            echo "=== 默认配置摘要 ==="
            grep -E "^\[|^enabled|^port|^maxretry|^bantime|^findtime" /etc/fail2ban/jail.conf | head -20
        fi
        return
    fi

    echo ""
    echo "=== 自定义配置文件 ==="
    echo "配置文件: /etc/fail2ban/jail.local"
    echo ""
    cat /etc/fail2ban/jail.local

    echo ""
    echo "=== 活动规则状态 ==="
    if systemctl is-active --quiet fail2ban; then
        fail2ban-client status 2>/dev/null || echo "无法获取状态信息"
    else
        echo "Fail2Ban服务未运行"
    fi
}

manage_fail2ban_rules() {
    log_info "管理Fail2Ban规则..."

    if ! check_fail2ban_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    local status=$(get_fail2ban_status)
    if [[ "$status" != "active" ]]; then
        log_warn "Fail2Ban服务未运行"
        read -p "是否启动服务? (Y/n): " start_service

        if [[ ! "$start_service" =~ ^[Nn]$ ]]; then
            systemctl start fail2ban
            systemctl enable fail2ban
        else
            read -p "按回车键继续..."
            return
        fi
    fi

    while true; do
        echo ""
        echo "Fail2Ban规则管理:"
        echo "1. 查看所有规则状态"
        echo "2. 启用/禁用规则"
        echo "3. 重载配置"
        echo "4. 测试配置"
        echo "5. 返回上级菜单"
        echo ""

        read -p "请选择 [1-5]: " rule_choice

        case $rule_choice in
            1) show_all_jail_status ;;
            2) toggle_jail_status ;;
            3) reload_fail2ban_config ;;
            4) test_fail2ban_config ;;
            5) break ;;
            *) log_error "无效选择" ;;
        esac
    done

    read -p "按回车键继续..."
}

show_all_jail_status() {
    echo ""
    log_info "所有Fail2Ban规则状态:"
    echo ""

    if ! systemctl is-active --quiet fail2ban; then
        log_error "Fail2Ban服务未运行"
        return 1
    fi

    # 显示总体状态
    echo "=== 服务状态 ==="
    fail2ban-client status

    echo ""
    echo "=== 详细规则状态 ==="

    # 获取所有jail列表
    local jails=$(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | tr -d ' ')

    for jail in $jails; do
        echo ""
        echo "规则: $jail"
        echo "----------------------------------------"
        fail2ban-client status "$jail" 2>/dev/null || echo "无法获取 $jail 状态"
    done
}

toggle_jail_status() {
    echo ""
    log_info "启用/禁用规则:"

    # 显示当前规则
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | tr -d ' ')

    if [[ -z "$jails" ]]; then
        log_error "没有找到活动规则"
        return 1
    fi

    echo ""
    echo "当前活动规则:"
    local i=1
    local jail_array=()
    for jail in $jails; do
        echo "$i. $jail"
        jail_array+=("$jail")
        ((i++))
    done

    echo ""
    read -p "请选择要操作的规则编号: " jail_index

    if [[ ! "$jail_index" =~ ^[0-9]+$ ]] || [[ $jail_index -lt 1 ]] || [[ $jail_index -gt ${#jail_array[@]} ]]; then
        log_error "无效的规则编号"
        return 1
    fi

    local selected_jail="${jail_array[$((jail_index-1))]}"

    echo ""
    echo "规则操作:"
    echo "1. 停止规则"
    echo "2. 重启规则"
    echo "3. 取消"

    read -p "请选择操作 [1-3]: " action_choice

    case $action_choice in
        1)
            if fail2ban-client stop "$selected_jail"; then
                log_success "规则已停止: $selected_jail"
            else
                log_error "停止规则失败: $selected_jail"
            fi
            ;;
        2)
            if fail2ban-client restart "$selected_jail"; then
                log_success "规则已重启: $selected_jail"
            else
                log_error "重启规则失败: $selected_jail"
            fi
            ;;
        3)
            log_info "取消操作"
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

reload_fail2ban_config() {
    log_info "重载Fail2Ban配置..."

    if fail2ban-client reload; then
        log_success "配置重载完成"
    else
        log_error "配置重载失败"
    fi
}

test_fail2ban_config() {
    log_info "测试Fail2Ban配置..."

    echo ""
    echo "配置测试结果:"
    if fail2ban-client -t; then
        log_success "配置文件语法正确"
    else
        log_error "配置文件存在语法错误"
    fi
}

show_ban_status() {
    log_info "显示封禁状态..."

    if ! check_fail2ban_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    local status=$(get_fail2ban_status)
    if [[ "$status" != "active" ]]; then
        log_error "Fail2Ban服务未运行"
        read -p "按回车键继续..."
        return 1
    fi

    echo ""
    echo "=== Fail2Ban封禁状态 ==="

    # 获取所有jail列表
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | tr -d ' ')

    if [[ -z "$jails" ]]; then
        log_warn "没有活动的防护规则"
        read -p "按回车键继续..."
        return
    fi

    local total_banned=0

    for jail in $jails; do
        echo ""
        echo "规则: $jail"
        echo "----------------------------------------"

        local jail_status=$(fail2ban-client status "$jail" 2>/dev/null)
        if [[ -n "$jail_status" ]]; then
            echo "$jail_status"

            # 统计封禁IP数量
            local banned_count=$(echo "$jail_status" | grep "Currently banned:" | awk '{print $3}')
            if [[ "$banned_count" =~ ^[0-9]+$ ]]; then
                total_banned=$((total_banned + banned_count))
            fi
        else
            echo "无法获取状态信息"
        fi
    done

    echo ""
    echo "=== 封禁统计 ==="
    echo "总封禁IP数量: $total_banned"

    # 显示最近的封禁记录
    echo ""
    echo "=== 最近封禁记录 (最后10条) ==="
    if [[ -f "/var/log/fail2ban.log" ]]; then
        grep "Ban " /var/log/fail2ban.log | tail -10 | while read -r line; do
            echo "$line"
        done
    else
        echo "未找到Fail2Ban日志文件"
    fi

    read -p "按回车键继续..."
}

unban_ip() {
    log_info "解封IP地址..."

    if ! check_fail2ban_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    local status=$(get_fail2ban_status)
    if [[ "$status" != "active" ]]; then
        log_error "Fail2Ban服务未运行"
        read -p "按回车键继续..."
        return 1
    fi

    # 显示当前封禁的IP
    echo ""
    log_info "当前封禁的IP地址:"
    echo ""

    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | tr -d ' ')
    local has_banned_ips=false

    for jail in $jails; do
        local banned_ips=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | cut -d: -f2 | tr -d ' ')

        if [[ -n "$banned_ips" && "$banned_ips" != "" ]]; then
            echo "规则 $jail:"
            echo "  $banned_ips"
            has_banned_ips=true
        fi
    done

    if [[ "$has_banned_ips" == false ]]; then
        log_info "当前没有被封禁的IP地址"
        read -p "按回车键继续..."
        return
    fi

    echo ""
    echo "解封选项:"
    echo "1. 解封指定IP地址"
    echo "2. 解封所有IP地址"
    echo "3. 取消"
    echo ""

    read -p "请选择 [1-3]: " unban_choice

    case $unban_choice in
        1)
            read -p "请输入要解封的IP地址: " ip_address

            if [[ -z "$ip_address" ]]; then
                log_error "IP地址不能为空"
                return 1
            fi

            # 验证IP地址格式
            if [[ ! "$ip_address" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                log_error "无效的IP地址格式: $ip_address"
                return 1
            fi

            # 尝试从所有jail中解封
            local unban_success=false
            for jail in $jails; do
                if fail2ban-client set "$jail" unbanip "$ip_address" 2>/dev/null; then
                    log_success "已从规则 $jail 中解封IP: $ip_address"
                    unban_success=true
                fi
            done

            if [[ "$unban_success" == false ]]; then
                log_warn "IP地址 $ip_address 未在任何规则中找到"
            fi
            ;;
        2)
            log_warn "即将解封所有被封禁的IP地址"
            read -p "确认解封所有IP? (y/N): " confirm_unban_all

            if [[ "$confirm_unban_all" =~ ^[Yy]$ ]]; then
                local total_unbanned=0

                for jail in $jails; do
                    local banned_ips=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | cut -d: -f2)

                    if [[ -n "$banned_ips" && "$banned_ips" != " " ]]; then
                        for ip in $banned_ips; do
                            if fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
                                ((total_unbanned++))
                            fi
                        done
                    fi
                done

                log_success "已解封 $total_unbanned 个IP地址"
            else
                log_info "取消解封操作"
            fi
            ;;
        3)
            log_info "取消解封操作"
            ;;
        *)
            log_error "无效选择"
            ;;
    esac

    read -p "按回车键继续..."
}

show_fail2ban_logs() {
    log_info "显示Fail2Ban日志..."

    if ! check_fail2ban_installed; then
        read -p "按回车键继续..."
        return 1
    fi

    echo ""
    echo "日志查看选项:"
    echo "1. 查看最近日志 (最后50行)"
    echo "2. 查看封禁日志"
    echo "3. 查看解封日志"
    echo "4. 查看错误日志"
    echo "5. 实时监控日志"
    echo "6. 返回上级菜单"
    echo ""

    read -p "请选择 [1-6]: " log_choice

    case $log_choice in
        1)
            echo ""
            log_info "最近的Fail2Ban日志:"
            echo "----------------------------------------"
            if [[ -f "/var/log/fail2ban.log" ]]; then
                tail -50 /var/log/fail2ban.log
            else
                log_error "未找到Fail2Ban日志文件"
            fi
            ;;
        2)
            echo ""
            log_info "封禁日志:"
            echo "----------------------------------------"
            if [[ -f "/var/log/fail2ban.log" ]]; then
                grep "Ban " /var/log/fail2ban.log | tail -20
            else
                log_error "未找到Fail2Ban日志文件"
            fi
            ;;
        3)
            echo ""
            log_info "解封日志:"
            echo "----------------------------------------"
            if [[ -f "/var/log/fail2ban.log" ]]; then
                grep "Unban " /var/log/fail2ban.log | tail -20
            else
                log_error "未找到Fail2Ban日志文件"
            fi
            ;;
        4)
            echo ""
            log_info "错误日志:"
            echo "----------------------------------------"
            if [[ -f "/var/log/fail2ban.log" ]]; then
                grep -i "error\|warning\|exception" /var/log/fail2ban.log | tail -20
            else
                log_error "未找到Fail2Ban日志文件"
            fi
            ;;
        5)
            echo ""
            log_info "实时监控Fail2Ban日志 (按Ctrl+C退出):"
            echo "----------------------------------------"
            if [[ -f "/var/log/fail2ban.log" ]]; then
                tail -f /var/log/fail2ban.log
            else
                log_error "未找到Fail2Ban日志文件"
            fi
            ;;
        6)
            return
            ;;
        *)
            log_error "无效选择"
            ;;
    esac

    if [[ $log_choice -ne 5 && $log_choice -ne 6 ]]; then
        read -p "按回车键继续..."
    fi
}

# ========================================
# 安全状态检查模块
# ========================================

security_status_check() {
    log_info "系统安全状态检查..."

    echo ""
    echo "安全检查选项:"
    echo "1. 完整安全检查 (推荐)"
    echo "2. 快速安全检查"
    echo "3. 服务状态检查"
    echo "4. 配置文件检查"
    echo "5. 网络安全检查"
    echo "6. 生成安全报告"
    echo "7. 返回主菜单"
    echo ""

    read -p "请选择 [1-7]: " check_choice

    case $check_choice in
        1) comprehensive_security_check ;;
        2) quick_security_check ;;
        3) service_status_check ;;
        4) config_file_check ;;
        5) network_security_check ;;
        6) generate_security_report ;;
        7) return ;;
        *) log_error "无效选择" ;;
    esac

    read -p "按回车键返回主菜单..."
}

comprehensive_security_check() {
    log_info "执行完整安全检查..."

    local check_results=()
    local security_score=0
    local max_score=100

    echo ""
    echo "=== 完整安全状态检查 ==="
    echo "检查时间: $(date)"
    echo ""

    # 1. 系统基础检查
    echo "1. 系统基础检查"
    echo "----------------------------------------"
    check_system_basics

    # 2. 用户和权限检查
    echo ""
    echo "2. 用户和权限检查"
    echo "----------------------------------------"
    check_user_security

    # 3. SSH安全检查
    echo ""
    echo "3. SSH安全检查"
    echo "----------------------------------------"
    check_ssh_security

    # 4. 防火墙检查
    echo ""
    echo "4. 防火墙检查"
    echo "----------------------------------------"
    check_firewall_security

    # 5. 入侵防护检查
    echo ""
    echo "5. 入侵防护检查"
    echo "----------------------------------------"
    check_intrusion_protection

    # 6. 网络服务检查
    echo ""
    echo "6. 网络服务检查"
    echo "----------------------------------------"
    check_network_services

    # 7. 系统更新检查
    echo ""
    echo "7. 系统更新检查"
    echo "----------------------------------------"
    check_system_updates

    # 8. 日志和监控检查
    echo ""
    echo "8. 日志和监控检查"
    echo "----------------------------------------"
    check_logging_monitoring

    # 生成总结
    echo ""
    echo "=== 安全检查总结 ==="
    calculate_security_score
    provide_security_recommendations
}

quick_security_check() {
    log_info "执行快速安全检查..."

    echo ""
    echo "=== 快速安全状态检查 ==="
    echo "检查时间: $(date)"
    echo ""

    # 关键服务状态
    echo "关键服务状态:"
    echo "----------------------------------------"
    check_critical_services

    echo ""
    echo "SSH安全状态:"
    echo "----------------------------------------"
    check_ssh_quick

    echo ""
    echo "防火墙状态:"
    echo "----------------------------------------"
    check_firewall_quick

    echo ""
    echo "系统安全状态:"
    echo "----------------------------------------"
    check_system_quick
}

check_system_basics() {
    local issues=0

    # 检查系统更新
    echo -n "系统更新状态: "
    if command -v apt &> /dev/null; then
        local updates=$(apt list --upgradable 2>/dev/null | wc -l)
        if [[ $updates -gt 1 ]]; then
            echo -e "${YELLOW}有 $((updates-1)) 个可用更新${NC}"
            ((issues++))
        else
            echo -e "${GREEN}系统已是最新${NC}"
        fi
    elif command -v yum &> /dev/null; then
        local updates=$(yum check-update --quiet | wc -l)
        if [[ $updates -gt 0 ]]; then
            echo -e "${YELLOW}有 $updates 个可用更新${NC}"
            ((issues++))
        else
            echo -e "${GREEN}系统已是最新${NC}"
        fi
    else
        echo -e "${YELLOW}无法检查更新状态${NC}"
    fi

    # 检查时区设置
    echo -n "时区设置: "
    local timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "未知")
    echo -e "${GREEN}$timezone${NC}"

    # 检查磁盘空间
    echo -n "磁盘空间: "
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 90 ]]; then
        echo -e "${RED}磁盘使用率 ${disk_usage}% (严重)${NC}"
        ((issues++))
    elif [[ $disk_usage -gt 80 ]]; then
        echo -e "${YELLOW}磁盘使用率 ${disk_usage}% (警告)${NC}"
    else
        echo -e "${GREEN}磁盘使用率 ${disk_usage}%${NC}"
    fi

    # 检查内存使用
    echo -n "内存使用: "
    local mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [[ $mem_usage -gt 90 ]]; then
        echo -e "${RED}内存使用率 ${mem_usage}% (严重)${NC}"
        ((issues++))
    elif [[ $mem_usage -gt 80 ]]; then
        echo -e "${YELLOW}内存使用率 ${mem_usage}% (警告)${NC}"
    else
        echo -e "${GREEN}内存使用率 ${mem_usage}%${NC}"
    fi

    # 检查系统负载
    echo -n "系统负载: "
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local cpu_cores=$(nproc)
    local load_percent=$(echo "$load_avg * 100 / $cpu_cores" | bc -l 2>/dev/null | cut -d. -f1)

    if [[ -n "$load_percent" && $load_percent -gt 80 ]]; then
        echo -e "${YELLOW}负载较高: $load_avg (${load_percent}%)${NC}"
    else
        echo -e "${GREEN}负载正常: $load_avg${NC}"
    fi

    echo "系统基础问题数: $issues"
}

check_user_security() {
    local issues=0

    # 检查root用户状态
    echo -n "Root用户状态: "
    if passwd -S root 2>/dev/null | grep -q " L "; then
        echo -e "${GREEN}已锁定${NC}"
    else
        echo -e "${YELLOW}未锁定${NC}"
        ((issues++))
    fi

    # 检查管理员用户
    echo -n "管理员用户: "
    local admin_users=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
    if [[ -n "$admin_users" ]]; then
        echo -e "${GREEN}$admin_users${NC}"
    else
        echo -e "${RED}未找到管理员用户${NC}"
        ((issues++))
    fi

    # 检查空密码用户
    echo -n "空密码用户: "
    local empty_pass_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$empty_pass_users" ]]; then
        echo -e "${GREEN}无${NC}"
    else
        echo -e "${RED}发现空密码用户: $empty_pass_users${NC}"
        ((issues++))
    fi

    # 检查密码策略
    echo -n "密码策略: "
    if [[ -f "/etc/pam.d/common-password" ]] && grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        echo -e "${GREEN}已配置${NC}"
    elif [[ -f "/etc/pam.d/system-auth" ]] && grep -q "pam_pwquality.so" /etc/pam.d/system-auth; then
        echo -e "${GREEN}已配置${NC}"
    else
        echo -e "${YELLOW}未配置强密码策略${NC}"
        ((issues++))
    fi

    echo "用户安全问题数: $issues"
}

check_ssh_security() {
    local issues=0
    local ssh_port=$(get_current_ssh_port)

    # 检查SSH端口
    echo -n "SSH端口: "
    if [[ "$ssh_port" == "22" ]]; then
        echo -e "${YELLOW}使用默认端口 22${NC}"
        ((issues++))
    else
        echo -e "${GREEN}$ssh_port (已修改)${NC}"
    fi

    # 检查root登录
    echo -n "Root SSH登录: "
    local root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    case "$root_login" in
        "no")
            echo -e "${GREEN}已禁用${NC}"
            ;;
        "prohibit-password")
            echo -e "${YELLOW}仅允许密钥登录${NC}"
            ;;
        *)
            echo -e "${RED}允许密码登录${NC}"
            ((issues++))
            ;;
    esac

    # 检查密码认证
    echo -n "SSH密码认证: "
    local password_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ "$password_auth" == "no" ]]; then
        echo -e "${GREEN}已禁用${NC}"
    else
        echo -e "${YELLOW}已启用${NC}"
        ((issues++))
    fi

    # 检查SSH密钥
    echo -n "SSH密钥配置: "
    local users_with_keys=0
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ $uid -ge 1000 || "$username" == "root" ]]; then
            if [[ -f "$home/.ssh/authorized_keys" ]] && [[ -s "$home/.ssh/authorized_keys" ]]; then
                ((users_with_keys++))
            fi
        fi
    done < /etc/passwd

    if [[ $users_with_keys -gt 0 ]]; then
        echo -e "${GREEN}$users_with_keys 个用户已配置${NC}"
    else
        echo -e "${RED}无用户配置SSH密钥${NC}"
        ((issues++))
    fi

    # 检查SSH服务状态
    echo -n "SSH服务状态: "
    local ssh_service=$(detect_ssh_service)
    if systemctl is-active --quiet "$ssh_service"; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}未运行${NC}"
        ((issues++))
    fi

    echo "SSH安全问题数: $issues"
}

check_firewall_security() {
    local issues=0

    # 检查UFW状态
    echo -n "UFW防火墙: "
    if command -v ufw &> /dev/null; then
        local ufw_status=$(get_firewall_status)
        if [[ "$ufw_status" == "active" ]]; then
            echo -e "${GREEN}已启用${NC}"
        else
            echo -e "${RED}未启用${NC}"
            ((issues++))
        fi
    else
        echo -e "${RED}未安装${NC}"
        ((issues++))
    fi

    # 检查SSH端口规则
    if command -v ufw &> /dev/null && [[ "$(get_firewall_status)" == "active" ]]; then
        echo -n "SSH端口规则: "
        local ssh_port=$(get_current_ssh_port)
        if ufw status | grep -q "$ssh_port/tcp"; then
            echo -e "${GREEN}已配置${NC}"
        else
            echo -e "${YELLOW}SSH端口未在防火墙规则中${NC}"
            ((issues++))
        fi

        # 检查默认策略
        echo -n "默认策略: "
        local default_policy=$(ufw status verbose | grep "Default:" | head -1)
        if echo "$default_policy" | grep -q "deny (incoming)"; then
            echo -e "${GREEN}拒绝入站连接${NC}"
        else
            echo -e "${YELLOW}入站策略不够严格${NC}"
            ((issues++))
        fi
    fi

    echo "防火墙问题数: $issues"
}

check_intrusion_protection() {
    local issues=0

    # 检查Fail2Ban状态
    echo -n "Fail2Ban服务: "
    if command -v fail2ban-server &> /dev/null; then
        local f2b_status=$(get_fail2ban_status)
        if [[ "$f2b_status" == "active" ]]; then
            echo -e "${GREEN}运行中${NC}"

            # 检查活动规则
            echo -n "活动防护规则: "
            local active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | wc -w)
            if [[ $active_jails -gt 0 ]]; then
                echo -e "${GREEN}$active_jails 个${NC}"
            else
                echo -e "${YELLOW}无活动规则${NC}"
                ((issues++))
            fi

            # 检查SSH防护
            echo -n "SSH防护: "
            if fail2ban-client status 2>/dev/null | grep -q "sshd"; then
                echo -e "${GREEN}已启用${NC}"
            else
                echo -e "${YELLOW}未启用SSH防护${NC}"
                ((issues++))
            fi

        else
            echo -e "${RED}未运行${NC}"
            ((issues++))
        fi
    else
        echo -e "${RED}未安装${NC}"
        ((issues++))
    fi

    echo "入侵防护问题数: $issues"
}

check_network_services() {
    local issues=0

    echo "开放端口检查:"

    # 获取监听端口
    local listening_ports=()
    while read -r line; do
        local port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
        local process=$(echo "$line" | awk '{print $7}' | cut -d/ -f2)
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            listening_ports+=("$port:$process")
        fi
    done < <(netstat -tlnp 2>/dev/null | grep LISTEN)

    # 检查常见不安全服务
    local unsafe_services=("21:FTP" "23:Telnet" "25:SMTP" "53:DNS" "110:POP3" "143:IMAP")

    for port_info in "${listening_ports[@]}"; do
        local port=$(echo "$port_info" | cut -d: -f1)
        local process=$(echo "$port_info" | cut -d: -f2)

        # 检查是否为不安全服务
        local is_unsafe=false
        for unsafe in "${unsafe_services[@]}"; do
            local unsafe_port=$(echo "$unsafe" | cut -d: -f1)
            local unsafe_name=$(echo "$unsafe" | cut -d: -f2)
            if [[ "$port" == "$unsafe_port" ]]; then
                echo -e "  ${RED}端口 $port ($unsafe_name): 不安全服务${NC}"
                is_unsafe=true
                ((issues++))
                break
            fi
        done

        if [[ "$is_unsafe" == false ]]; then
            case $port in
                22|2222) echo -e "  ${GREEN}端口 $port: SSH服务${NC}" ;;
                80) echo -e "  ${GREEN}端口 $port: HTTP服务${NC}" ;;
                443) echo -e "  ${GREEN}端口 $port: HTTPS服务${NC}" ;;
                *) echo -e "  ${YELLOW}端口 $port: $process${NC}" ;;
            esac
        fi
    done

    echo "网络服务问题数: $issues"
}

check_system_updates() {
    local issues=0

    echo -n "系统更新检查: "

    if command -v apt &> /dev/null; then
        # 更新包列表
        apt update -qq 2>/dev/null

        local security_updates=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
        local total_updates=$(apt list --upgradable 2>/dev/null | wc -l)
        total_updates=$((total_updates - 1)) # 减去标题行

        if [[ $security_updates -gt 0 ]]; then
            echo -e "${RED}有 $security_updates 个安全更新${NC}"
            ((issues++))
        elif [[ $total_updates -gt 0 ]]; then
            echo -e "${YELLOW}有 $total_updates 个可用更新${NC}"
        else
            echo -e "${GREEN}系统已是最新${NC}"
        fi

    elif command -v yum &> /dev/null; then
        local security_updates=$(yum --security check-update --quiet 2>/dev/null | wc -l)
        local total_updates=$(yum check-update --quiet 2>/dev/null | wc -l)

        if [[ $security_updates -gt 0 ]]; then
            echo -e "${RED}有 $security_updates 个安全更新${NC}"
            ((issues++))
        elif [[ $total_updates -gt 0 ]]; then
            echo -e "${YELLOW}有 $total_updates 个可用更新${NC}"
        else
            echo -e "${GREEN}系统已是最新${NC}"
        fi
    else
        echo -e "${YELLOW}无法检查更新${NC}"
    fi

    echo "系统更新问题数: $issues"
}

check_logging_monitoring() {
    local issues=0

    # 检查系统日志
    echo -n "系统日志服务: "
    if systemctl is-active --quiet rsyslog || systemctl is-active --quiet syslog-ng; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}未运行${NC}"
        ((issues++))
    fi

    # 检查日志文件
    echo -n "认证日志: "
    if [[ -f "/var/log/auth.log" ]] || [[ -f "/var/log/secure" ]]; then
        echo -e "${GREEN}存在${NC}"
    else
        echo -e "${YELLOW}未找到认证日志${NC}"
        ((issues++))
    fi

    # 检查日志轮转
    echo -n "日志轮转: "
    if [[ -f "/etc/logrotate.conf" ]] && command -v logrotate &> /dev/null; then
        echo -e "${GREEN}已配置${NC}"
    else
        echo -e "${YELLOW}未配置${NC}"
        ((issues++))
    fi

    echo "日志监控问题数: $issues"
}

calculate_security_score() {
    # 这里可以根据各项检查结果计算安全评分
    # 简化版本，实际可以更复杂
    echo "安全评分计算功能待完善"
}

provide_security_recommendations() {
    echo ""
    echo "=== 安全建议 ==="

    # 基于检查结果提供建议
    echo "1. 定期更新系统和软件包"
    echo "2. 使用强密码策略"
    echo "3. 启用防火墙和入侵防护"
    echo "4. 定期检查系统日志"
    echo "5. 禁用不必要的服务"
    echo "6. 使用SSH密钥认证"
    echo "7. 定期备份重要数据"
}

service_status_check() {
    log_info "服务状态检查..."

    echo ""
    echo "=== 关键服务状态 ==="

    check_critical_services

    echo ""
    echo "=== 安全服务状态 ==="

    # SSH服务
    local ssh_service=$(detect_ssh_service)
    echo -n "SSH服务 ($ssh_service): "
    if systemctl is-active --quiet "$ssh_service"; then
        echo -e "${GREEN}运行中${NC} ($(systemctl is-enabled "$ssh_service"))"
    else
        echo -e "${RED}未运行${NC}"
    fi

    # UFW防火墙
    echo -n "UFW防火墙: "
    if command -v ufw &> /dev/null; then
        local ufw_status=$(get_firewall_status)
        if [[ "$ufw_status" == "active" ]]; then
            echo -e "${GREEN}已启用${NC}"
        else
            echo -e "${YELLOW}未启用${NC}"
        fi
    else
        echo -e "${RED}未安装${NC}"
    fi

    # Fail2Ban
    echo -n "Fail2Ban: "
    if command -v fail2ban-server &> /dev/null; then
        local f2b_status=$(get_fail2ban_status)
        if [[ "$f2b_status" == "active" ]]; then
            echo -e "${GREEN}运行中${NC} ($(systemctl is-enabled fail2ban))"
        else
            echo -e "${YELLOW}未运行${NC}"
        fi
    else
        echo -e "${RED}未安装${NC}"
    fi

    echo ""
    echo "=== 系统服务状态 ==="

    # 系统日志
    echo -n "系统日志: "
    if systemctl is-active --quiet rsyslog; then
        echo -e "${GREEN}rsyslog 运行中${NC}"
    elif systemctl is-active --quiet syslog-ng; then
        echo -e "${GREEN}syslog-ng 运行中${NC}"
    else
        echo -e "${YELLOW}日志服务状态未知${NC}"
    fi

    # 时间同步
    echo -n "时间同步: "
    if systemctl is-active --quiet ntp; then
        echo -e "${GREEN}NTP 运行中${NC}"
    elif systemctl is-active --quiet systemd-timesyncd; then
        echo -e "${GREEN}systemd-timesyncd 运行中${NC}"
    else
        echo -e "${YELLOW}时间同步服务未运行${NC}"
    fi
}

check_critical_services() {
    local services=("ssh" "sshd" "networking" "systemd-networkd" "systemd-resolved")

    for service in "${services[@]}"; do
        if systemctl list-units --type=service | grep -q "$service.service"; then
            echo -n "$service: "
            if systemctl is-active --quiet "$service"; then
                echo -e "${GREEN}运行中${NC}"
            else
                echo -e "${RED}未运行${NC}"
            fi
        fi
    done
}

check_ssh_quick() {
    local ssh_port=$(get_current_ssh_port)
    local ssh_service=$(detect_ssh_service)

    echo "SSH端口: $ssh_port"
    echo -n "SSH服务: "
    if systemctl is-active --quiet "$ssh_service"; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}未运行${NC}"
    fi

    echo -n "Root登录: "
    local root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    case "$root_login" in
        "no") echo -e "${GREEN}已禁用${NC}" ;;
        "prohibit-password") echo -e "${YELLOW}仅密钥${NC}" ;;
        *) echo -e "${RED}允许${NC}" ;;
    esac

    echo -n "密码认证: "
    local password_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ "$password_auth" == "no" ]]; then
        echo -e "${GREEN}已禁用${NC}"
    else
        echo -e "${YELLOW}已启用${NC}"
    fi
}

check_firewall_quick() {
    echo -n "UFW状态: "
    if command -v ufw &> /dev/null; then
        local status=$(get_firewall_status)
        if [[ "$status" == "active" ]]; then
            echo -e "${GREEN}已启用${NC}"

            local rule_count=$(ufw status numbered | grep -c "^\[")
            echo "活动规则: $rule_count 个"
        else
            echo -e "${RED}未启用${NC}"
        fi
    else
        echo -e "${RED}未安装${NC}"
    fi
}

check_system_quick() {
    # 系统负载
    echo -n "系统负载: "
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    echo "$load_avg"

    # 磁盘使用
    echo -n "磁盘使用: "
    local disk_usage=$(df / | awk 'NR==2 {print $5}')
    echo "$disk_usage"

    # 内存使用
    echo -n "内存使用: "
    local mem_usage=$(free | awk 'NR==2{printf "%.0f%%", $3*100/$2}')
    echo "$mem_usage"

    # 运行时间
    echo -n "系统运行时间: "
    uptime | awk '{print $3,$4}' | sed 's/,//'
}

config_file_check() {
    log_info "配置文件检查..."

    echo ""
    echo "=== 关键配置文件检查 ==="

    # SSH配置检查
    echo ""
    echo "SSH配置文件检查:"
    echo "----------------------------------------"
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        echo -e "${GREEN}✓ SSH配置文件存在${NC}"

        # 检查配置语法
        if sshd -t 2>/dev/null; then
            echo -e "${GREEN}✓ SSH配置语法正确${NC}"
        else
            echo -e "${RED}✗ SSH配置语法错误${NC}"
        fi

        # 检查关键配置项
        echo "关键配置项:"
        echo "  端口: $(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22 (默认)")"
        echo "  Root登录: $(grep "^PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (默认)")"
        echo "  密码认证: $(grep "^PasswordAuthentication " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (默认)")"
        echo "  公钥认证: $(grep "^PubkeyAuthentication " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (默认)")"
    else
        echo -e "${RED}✗ SSH配置文件不存在${NC}"
    fi

    # UFW配置检查
    echo ""
    echo "防火墙配置检查:"
    echo "----------------------------------------"
    if command -v ufw &> /dev/null; then
        echo -e "${GREEN}✓ UFW已安装${NC}"

        local ufw_status=$(get_firewall_status)
        echo "状态: $ufw_status"

        if [[ "$ufw_status" == "active" ]]; then
            echo "规则数量: $(ufw status numbered | grep -c "^\[")"
        fi
    else
        echo -e "${RED}✗ UFW未安装${NC}"
    fi

    # Fail2Ban配置检查
    echo ""
    echo "Fail2Ban配置检查:"
    echo "----------------------------------------"
    if command -v fail2ban-server &> /dev/null; then
        echo -e "${GREEN}✓ Fail2Ban已安装${NC}"

        if [[ -f "/etc/fail2ban/jail.local" ]]; then
            echo -e "${GREEN}✓ 自定义配置文件存在${NC}"

            # 检查配置语法
            if fail2ban-client -t 2>/dev/null; then
                echo -e "${GREEN}✓ 配置语法正确${NC}"
            else
                echo -e "${RED}✗ 配置语法错误${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ 使用默认配置${NC}"
        fi

        local f2b_status=$(get_fail2ban_status)
        echo "服务状态: $f2b_status"
    else
        echo -e "${RED}✗ Fail2Ban未安装${NC}"
    fi

    # 系统配置检查
    echo ""
    echo "系统配置检查:"
    echo "----------------------------------------"

    # 检查sudo配置
    if [[ -f "/etc/sudoers" ]]; then
        echo -e "${GREEN}✓ sudo配置文件存在${NC}"
        if visudo -c 2>/dev/null; then
            echo -e "${GREEN}✓ sudo配置语法正确${NC}"
        else
            echo -e "${RED}✗ sudo配置语法错误${NC}"
        fi
    fi

    # 检查PAM配置
    if [[ -f "/etc/pam.d/common-password" ]] || [[ -f "/etc/pam.d/system-auth" ]]; then
        echo -e "${GREEN}✓ PAM密码配置存在${NC}"
    else
        echo -e "${YELLOW}⚠ PAM密码配置可能缺失${NC}"
    fi

    # 检查登录配置
    if [[ -f "/etc/login.defs" ]]; then
        echo -e "${GREEN}✓ 登录配置文件存在${NC}"
        echo "密码策略:"
        echo "  最大天数: $(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "未设置")"
        echo "  最小天数: $(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "未设置")"
        echo "  警告天数: $(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "未设置")"
    fi
}

network_security_check() {
    log_info "网络安全检查..."

    echo ""
    echo "=== 网络安全状态检查 ==="

    # 端口扫描检查
    echo ""
    echo "开放端口检查:"
    echo "----------------------------------------"

    echo "TCP端口:"
    netstat -tlnp 2>/dev/null | grep LISTEN | while read -r line; do
        local port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
        local process=$(echo "$line" | awk '{print $7}' | cut -d/ -f2)
        echo "  $port/tcp - $process"
    done

    echo ""
    echo "UDP端口:"
    netstat -ulnp 2>/dev/null | head -10 | while read -r line; do
        local port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
        local process=$(echo "$line" | awk '{print $6}' | cut -d/ -f2)
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            echo "  $port/udp - $process"
        fi
    done

    # 网络连接检查
    echo ""
    echo "活动网络连接:"
    echo "----------------------------------------"
    local established_count=$(netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l)
    echo "已建立连接数: $established_count"

    if [[ $established_count -gt 0 ]]; then
        echo "连接详情 (前10个):"
        netstat -tn 2>/dev/null | grep ESTABLISHED | head -10 | while read -r line; do
            local remote_ip=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
            local local_port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
            echo "  本地端口 $local_port <- $remote_ip"
        done
    fi

    # 路由表检查
    echo ""
    echo "路由表检查:"
    echo "----------------------------------------"
    echo "默认网关:"
    ip route | grep default | head -3

    # DNS配置检查
    echo ""
    echo "DNS配置检查:"
    echo "----------------------------------------"
    if [[ -f "/etc/resolv.conf" ]]; then
        echo "DNS服务器:"
        grep "^nameserver" /etc/resolv.conf | head -3
    else
        echo "DNS配置文件不存在"
    fi

    # 网络接口检查
    echo ""
    echo "网络接口状态:"
    echo "----------------------------------------"
    ip addr show | grep -E "^[0-9]+:|inet " | while read -r line; do
        if [[ "$line" =~ ^[0-9]+: ]]; then
            echo "$line" | awk '{print $2}' | sed 's/://'
        elif [[ "$line" =~ inet ]]; then
            echo "  $(echo "$line" | awk '{print $2}')"
        fi
    done
}

generate_security_report() {
    log_info "生成安全报告..."

    local report_file="/tmp/security_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "========================================"
        echo "VPS 安全状态报告"
        echo "========================================"
        echo "生成时间: $(date)"
        echo "主机名: $(hostname)"
        echo "系统信息: $(uname -a)"
        echo ""

        echo "=== 系统基础信息 ==="
        echo "操作系统: $OS $OS_VERSION"
        echo "内核版本: $(uname -r)"
        echo "系统架构: $(uname -m)"
        echo "运行时间: $(uptime | awk '{print $3,$4}' | sed 's/,//')"
        echo ""

        echo "=== 资源使用情况 ==="
        echo "磁盘使用:"
        df -h | grep -E "^/dev/"
        echo ""
        echo "内存使用:"
        free -h
        echo ""
        echo "系统负载:"
        uptime
        echo ""

        echo "=== 用户和权限 ==="
        echo "管理员用户:"
        getent group sudo | cut -d: -f4 | tr ',' '\n' | while read -r user; do
            if [[ -n "$user" ]]; then
                echo "  $user"
            fi
        done
        echo ""

        echo "=== SSH配置状态 ==="
        echo "SSH端口: $(get_current_ssh_port)"
        echo "Root登录: $(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "默认")"
        echo "密码认证: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "默认")"
        echo ""

        echo "=== 防火墙状态 ==="
        if command -v ufw &> /dev/null; then
            echo "UFW状态: $(get_firewall_status)"
            if [[ "$(get_firewall_status)" == "active" ]]; then
                echo "防火墙规则:"
                ufw status numbered
            fi
        else
            echo "UFW: 未安装"
        fi
        echo ""

        echo "=== 入侵防护状态 ==="
        if command -v fail2ban-server &> /dev/null; then
            echo "Fail2Ban状态: $(get_fail2ban_status)"
            if [[ "$(get_fail2ban_status)" == "active" ]]; then
                echo "活动规则:"
                fail2ban-client status 2>/dev/null || echo "无法获取状态"
            fi
        else
            echo "Fail2Ban: 未安装"
        fi
        echo ""

        echo "=== 网络服务 ==="
        echo "监听端口:"
        netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print $4 " - " $7}' | sort
        echo ""

        echo "=== 系统更新状态 ==="
        if command -v apt &> /dev/null; then
            local updates=$(apt list --upgradable 2>/dev/null | wc -l)
            echo "可用更新: $((updates-1)) 个"
        elif command -v yum &> /dev/null; then
            local updates=$(yum check-update --quiet 2>/dev/null | wc -l)
            echo "可用更新: $updates 个"
        fi
        echo ""

        echo "=== 安全建议 ==="
        echo "1. 定期更新系统和软件包"
        echo "2. 使用强密码和SSH密钥认证"
        echo "3. 启用防火墙和入侵防护系统"
        echo "4. 定期检查系统日志和安全状态"
        echo "5. 禁用不必要的服务和端口"
        echo "6. 定期备份重要数据"
        echo ""

        echo "========================================"
        echo "报告生成完成: $(date)"
        echo "========================================"

    } > "$report_file"

    log_success "安全报告已生成: $report_file"

    echo ""
    read -p "是否查看报告内容? (Y/n): " view_report
    if [[ ! "$view_report" =~ ^[Nn]$ ]]; then
        echo ""
        cat "$report_file"
    fi

    echo ""
    read -p "是否保存报告到配置目录? (Y/n): " save_report
    if [[ ! "$save_report" =~ ^[Nn]$ ]]; then
        local saved_report="$CONFIG_DIR/security_report_$(date +%Y%m%d_%H%M%S).txt"
        cp "$report_file" "$saved_report"
        log_success "报告已保存到: $saved_report"
    fi
}

# 高级选项函数
advanced_options() { log_info "高级选项 - 待实现"; read -p "按回车键返回主菜单..."; }

# 查看配置函数
show_configuration() { log_info "查看配置 - 待实现"; read -p "按回车键返回主菜单..."; }

main() {
    init_script

    while true; do
        show_main_menu
        read -p "请输入选项 [0-9]: " choice

        case $choice in
            1) one_click_hardening ;;
            2) show_system_menu ;;
            3) show_user_menu ;;
            4) show_ssh_menu ;;
            5) show_firewall_menu ;;
            6) show_fail2ban_menu ;;
            7) security_status_check ;;
            8) advanced_options ;;
            9) show_configuration ;;
            0)
                log_info "感谢使用 $SCRIPT_NAME！"
                exit 0
                ;;
            *)
                log_error "无效选择，请输入 0-9"
                sleep 2
                ;;
        esac
    done
}

# ========================================
# 脚本入口点
# ========================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
