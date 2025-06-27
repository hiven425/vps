#!/bin/bash

# VPS管理脚本
# 适用于Debian/Ubuntu系统
# 作者: hiven425
# 版本: 3.0
# 功能: VPS安全加固和代理服务管理

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
LOG_FILE="/var/log/vps-management.log"

# 配置备份目录
BACKUP_DIR="/root/vps-backup-$(date +%Y%m%d-%H%M%S)"

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
    [[ $REPLY =~ ^[Yy]$ ]]
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_message "$RED" "此脚本需要root权限运行"
        print_message "$YELLOW" "请使用: sudo $0"
        exit 1
    fi
}

# 检查系统
check_system() {
    if [[ ! -f /etc/debian_version ]]; then
        print_message "$RED" "此脚本仅支持Debian/Ubuntu系统"
        exit 1
    fi
}

# 创建备份目录
create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    log_message "创建备份目录: $BACKUP_DIR"
}

# 备份文件
backup_file() {
    local file_path=$1
    if [[ -f "$file_path" ]]; then
        local backup_name="$(basename "$file_path").backup.$(date +%Y%m%d_%H%M%S)"
        cp "$file_path" "$BACKUP_DIR/$backup_name"
        log_message "备份文件: $file_path -> $BACKUP_DIR/$backup_name"
    fi
}

# 获取SSH端口
get_ssh_port() {
    local ssh_port
    
    # 尝试从sshd配置获取端口
    if command -v sshd &> /dev/null; then
        ssh_port=$(sshd -T 2>/dev/null | grep -i "^port" | awk '{print $2}')
    fi
    
    # 如果没有获取到，尝试从配置文件读取
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
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

# 主菜单
show_menu() {
    clear
    print_message "$BLUE" "=================================="
    print_message "$BLUE" "       VPS管理脚本"
    print_message "$BLUE" "=================================="
    echo
    echo "🔍 0. 安全状态概览"
    echo ""
    echo "🛡️  【安全加固模块】"
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
    echo "⚡ 14. 一键安全加固"
    echo ""
    echo "🚀 【代理服务模块】"
    echo "20. 证书管理 (Cloudflare)"
    echo "21. Hysteria2服务"
    echo "22. 3X-UI面板"
    echo "23. Sub-Store服务"
    echo "24. Nginx分流配置"
    echo "25. vless+reality代理"
    echo "26. sing-box安装"
    echo "27. 代理服务管理"
    echo ""
    echo "❌ 99. 退出"
    echo
}

# 主程序
main() {
    check_root
    check_system
    create_backup_dir
    
    print_message "$GREEN" "VPS管理脚本启动成功！"
    print_message "$CYAN" "日志文件: $LOG_FILE"
    print_message "$CYAN" "备份目录: $BACKUP_DIR"
    echo
    
    while true; do
        show_menu
        read -p "请选择操作 (0-27, 99): " choice

        case $choice in
            0) print_message "$YELLOW" "安全状态概览功能开发中..." ;;
            1) show_system_info ;;
            2) update_system ;;
            3) print_message "$YELLOW" "创建用户功能开发中..." ;;
            4) print_message "$YELLOW" "SSH配置功能开发中..." ;;
            5) print_message "$YELLOW" "防火墙配置功能开发中..." ;;
            6) print_message "$YELLOW" "fail2ban安装功能开发中..." ;;
            7) print_message "$YELLOW" "网络安全配置功能开发中..." ;;
            8) print_message "$YELLOW" "系统监控配置功能开发中..." ;;
            9) print_message "$YELLOW" "系统清理功能开发中..." ;;
            10) print_message "$YELLOW" "安全扫描功能开发中..." ;;
            11) print_message "$YELLOW" "备份恢复功能开发中..." ;;
            12) print_message "$YELLOW" "fail2ban管理功能开发中..." ;;
            13) print_message "$YELLOW" "安全验证功能开发中..." ;;
            14) print_message "$YELLOW" "一键加固功能开发中..." ;;
            20) print_message "$YELLOW" "证书管理功能开发中..." ;;
            21) print_message "$YELLOW" "Hysteria2功能开发中..." ;;
            22) print_message "$YELLOW" "3X-UI功能开发中..." ;;
            23) print_message "$YELLOW" "Sub-Store功能开发中..." ;;
            24) print_message "$YELLOW" "Nginx配置功能开发中..." ;;
            25) print_message "$YELLOW" "vless+reality功能开发中..." ;;
            26) print_message "$YELLOW" "sing-box功能开发中..." ;;
            27) print_message "$YELLOW" "代理管理功能开发中..." ;;
            99)
                print_message "$GREEN" "感谢使用VPS管理脚本!"
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

# 运行主程序
main "$@"
