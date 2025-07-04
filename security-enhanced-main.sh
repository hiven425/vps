#!/bin/bash

# VPS安全加固工具 - 优化版本集成模块
# 集成所有安全改进和增强功能

set -euo pipefail

# 版本信息
ENHANCED_VERSION="2.2.0-security"
SCRIPT_DIR="$(dirname "$(realpath "$0")")"

# 颜色定义
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    red='\033[31m'
    green='\033[32m'
    yellow='\033[33m'
    blue='\033[34m'
    pink='\033[35m'
    cyan='\033[36m'
    white='\033[0m'
    bold='\033[1m'
else
    red='' green='' yellow='' blue='' pink='' cyan='' white='' bold=''
fi

#region //模块加载和初始化

# 加载增强模块
load_enhanced_modules() {
    local modules=(
        "enhanced-logging.sh"
        "security-fixes.sh"  
        "ssh-security-enhanced.sh"
        "secure-service-manager.sh"
    )
    
    echo -e "${cyan}正在加载安全增强模块...${white}"
    
    for module in "${modules[@]}"; do
        local module_path="$SCRIPT_DIR/$module"
        
        if [[ -f "$module_path" ]]; then
            echo -e "${green}✓ 加载模块: $module${white}"
            source "$module_path"
        else
            echo -e "${yellow}⚠ 模块不存在: $module${white}"
        fi
    done
    
    echo -e "${green}✓ 所有可用模块已加载${white}"
}

# 初始化安全系统
initialize_security_system() {
    echo -e "${pink}=== VPS安全加固工具 v$ENHANCED_VERSION ===${white}"
    echo -e "${cyan}增强版本包含以下安全改进:${white}"
    echo "• 文件权限安全修复"
    echo "• 增强输入验证和清理"
    echo "• 下载文件完整性验证"
    echo "• 结构化日志和错误处理"
    echo "• SSH配置安全审计"
    echo "• 安全的服务管理"
    echo ""
    
    # 初始化各个子系统
    if command -v init_enhanced_logging >/dev/null; then
        init_enhanced_logging
    fi
    
    if command -v init_service_manager >/dev/null; then
        init_service_manager
    fi
    
    echo -e "${green}✓ 安全系统初始化完成${white}"
}

#endregion

#region //安全加固主菜单

# 主菜单
security_main_menu() {
    while true; do
        clear
        echo -e "${pink}╔════════════════════════════════════════╗${white}"
        echo -e "${pink}║     VPS安全加固工具 v$ENHANCED_VERSION       ║${white}"
        echo -e "${pink}║           增强安全版本                    ║${white}"
        echo -e "${pink}╚════════════════════════════════════════╝${white}"
        echo ""
        echo -e "${cyan}🛡️  安全加固模块${white}"
        echo "1. SSH安全配置增强"
        echo "2. 防火墙安全配置"
        echo "3. 系统安全优化"
        echo "4. 服务安全管理"
        echo ""
        echo -e "${cyan}🔧 系统管理${white}"
        echo "5. 安全审计检查"
        echo "6. 日志分析工具"
        echo "7. 系统健康检查"
        echo "8. 备份和恢复"
        echo ""
        echo -e "${cyan}🚀 代理部署${white}"
        echo "9. 安全代理部署"
        echo "10. 代理配置管理"
        echo ""
        echo -e "${cyan}⚙️  高级功能${white}"
        echo "11. 安全补丁应用"
        echo "12. 配置文件验证"
        echo "13. 性能监控"
        echo "14. 安全基线检查"
        echo ""
        echo -e "${cyan}📊 报告和分析${white}"
        echo "15. 生成安全报告"
        echo "16. 漏洞扫描"
        echo ""
        echo "0. 退出"
        echo ""
        
        local choice
        if secure_read_input "请选择功能 [0-16]: " "validate_numeric_range_or_empty" 3 30 choice; then
            case "${choice:-0}" in
                1) enhanced_ssh_security_menu ;;
                2) firewall_security_menu ;;
                3) system_security_menu ;;
                4) service_security_menu ;;
                5) security_audit_menu ;;
                6) log_analysis_menu ;;
                7) system_health_menu ;;
                8) backup_recovery_menu ;;
                9) secure_proxy_deployment ;;
                10) proxy_config_management ;;
                11) apply_security_patches ;;
                12) config_validation_menu ;;
                13) performance_monitoring ;;
                14) security_baseline_check ;;
                15) generate_security_report ;;
                16) vulnerability_scan ;;
                0) 
                    echo -e "${green}感谢使用VPS安全加固工具！${white}"
                    exit 0
                    ;;
                *)
                    log_warn "无效选择: $choice" "main_menu"
                    ;;
            esac
        else
            log_warn "输入超时或无效" "main_menu"
        fi
        
        echo ""
        echo "按任意键继续..."
        read -n 1 -s
    done
}

# SSH安全配置增强菜单
enhanced_ssh_security_menu() {
    if command -v enhanced_ssh_security_setup >/dev/null; then
        enhanced_ssh_security_setup
    else
        echo -e "${red}SSH安全增强模块未加载${white}"
    fi
}

# 服务安全管理菜单
service_security_menu() {
    if command -v service_management_menu >/dev/null; then
        service_management_menu
    else
        echo -e "${red}服务管理模块未加载${white}"
    fi
}

# 安全审计菜单
security_audit_menu() {
    clear
    echo -e "${cyan}=== 安全审计检查 ===${white}"
    echo ""
    echo "1. SSH配置审计"
    echo "2. 系统权限审计"
    echo "3. 网络配置审计"
    echo "4. 服务安全审计"
    echo "5. 完整安全审计"
    echo ""
    echo "0. 返回主菜单"
    echo ""
    
    local choice
    if secure_read_input "请选择审计类型 [0-5]: " "validate_numeric_range_or_empty" 3 30 choice; then
        case "${choice:-0}" in
            1) audit_ssh_security ;;
            2) audit_system_permissions ;;
            3) audit_network_config ;;
            4) audit_service_security ;;
            5) perform_complete_audit ;;
            0) return ;;
        esac
    fi
}

# 日志分析菜单
log_analysis_menu() {
    if command -v analyze_logs >/dev/null; then
        clear
        echo -e "${cyan}=== 日志分析工具 ===${white}"
        echo ""
        echo "1. 查看错误日志"
        echo "2. 查看审计日志"
        echo "3. 查看所有日志"
        echo "4. 日志统计分析"
        echo ""
        echo "0. 返回主菜单"
        echo ""
        
        local choice
        if secure_read_input "请选择分析类型 [0-4]: " "validate_numeric_range_or_empty" 3 30 choice; then
            case "${choice:-0}" in
                1) analyze_logs "error" 100 ;;
                2) analyze_logs "audit" 100 ;;
                3) analyze_logs "all" 100 ;;
                4) analyze_log_statistics ;;
                0) return ;;
            esac
        fi
    else
        echo -e "${red}日志分析模块未加载${white}"
    fi
}

#endregion

#region //安全检查和审计功能

# SSH安全审计
audit_ssh_security() {
    echo -e "${cyan}=== SSH安全审计 ===${white}"
    
    log_info "开始SSH安全审计..." "ssh_audit"
    
    # 检查SSH配置文件
    if command -v ssh_security_validator >/dev/null; then
        ssh_security_validator "/etc/ssh/sshd_config"
    fi
    
    # 检查SSH密钥
    if command -v audit_ssh_keys >/dev/null; then
        audit_ssh_keys "$HOME/.ssh"
        audit_ssh_keys "/root/.ssh"
    fi
    
    # 检查SSH服务状态
    if command -v service_health_check >/dev/null; then
        service_health_check "ssh"
    fi
    
    log_success "SSH安全审计完成" "ssh_audit"
}

# 系统权限审计
audit_system_permissions() {
    echo -e "${cyan}=== 系统权限审计 ===${white}"
    
    log_info "开始系统权限审计..." "permission_audit"
    
    local issues=0
    
    # 检查重要文件权限
    local critical_files=(
        "/etc/passwd:644"
        "/etc/shadow:600"
        "/etc/group:644"
        "/etc/gshadow:600"
        "/etc/ssh/sshd_config:644"
        "/etc/sudoers:440"
    )
    
    for file_perm in "${critical_files[@]}"; do
        local file="${file_perm%:*}"
        local expected_perm="${file_perm#*:}"
        
        if [[ -f "$file" ]]; then
            local actual_perm=$(stat -c '%a' "$file" 2>/dev/null)
            if [[ "$actual_perm" == "$expected_perm" ]]; then
                log_success "权限正确: $file ($actual_perm)" "permission_audit"
            else
                log_error "权限异常: $file (实际:$actual_perm, 期望:$expected_perm)" "permission_audit"
                ((issues++))
            fi
        else
            log_warn "文件不存在: $file" "permission_audit"
        fi
    done
    
    # 检查SUID/SGID文件
    echo -e "\n${cyan}检查SUID/SGID文件...${white}"
    local suid_files=$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
    if [[ -n "$suid_files" ]]; then
        echo "发现SUID/SGID文件:"
        echo "$suid_files"
    fi
    
    if [[ $issues -eq 0 ]]; then
        log_success "系统权限审计通过" "permission_audit"
    else
        log_error "发现 $issues 个权限问题" "permission_audit"
    fi
}

# 完整安全审计
perform_complete_audit() {
    echo -e "${cyan}=== 完整安全审计 ===${white}"
    
    log_info "开始完整安全审计..." "complete_audit"
    
    local audit_report="/tmp/security_audit_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "VPS安全审计报告"
        echo "生成时间: $(date)"
        echo "系统信息: $(uname -a)"
        echo ""
        
        echo "=== SSH安全检查 ==="
        audit_ssh_security
        echo ""
        
        echo "=== 系统权限检查 ==="
        audit_system_permissions
        echo ""
        
        echo "=== 网络配置检查 ==="
        audit_network_config
        echo ""
        
        echo "=== 服务安全检查 ==="
        audit_service_security
        echo ""
        
    } > "$audit_report"
    
    log_success "完整安全审计完成，报告保存到: $audit_report" "complete_audit"
    
    # 显示报告摘要
    echo -e "\n${cyan}审计报告摘要:${white}"
    grep -E "(✓|✗|⚠)" "$audit_report" | tail -10
}

# 网络配置审计
audit_network_config() {
    echo -e "${cyan}=== 网络配置审计 ===${white}"
    
    log_info "检查网络安全配置..." "network_audit"
    
    # 检查防火墙状态
    if command -v ufw >/dev/null; then
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        echo "UFW状态: $ufw_status"
    fi
    
    # 检查开放端口
    echo "开放的端口:"
    ss -tuln | grep LISTEN | head -10
    
    # 检查网络连接
    echo "活动网络连接:"
    ss -tuln | grep ESTAB | wc -l
    
    log_success "网络配置审计完成" "network_audit"
}

# 服务安全审计
audit_service_security() {
    echo -e "${cyan}=== 服务安全审计 ===${white}"
    
    log_info "检查关键服务安全状态..." "service_audit"
    
    local critical_services=("ssh" "xray" "fail2ban")
    
    for service in "${critical_services[@]}"; do
        if command -v service_health_check >/dev/null; then
            service_health_check "$service" false
        fi
    done
    
    log_success "服务安全审计完成" "service_audit"
}

#endregion

#region //安全补丁和配置验证

# 应用安全补丁
apply_security_patches() {
    echo -e "${cyan}=== 应用安全补丁 ===${white}"
    
    if command -v apply_security_fixes >/dev/null; then
        log_info "应用安全修复补丁..." "security_patches"
        
        if apply_security_fixes; then
            log_success "安全补丁应用成功" "security_patches"
        else
            log_error "安全补丁应用失败" "security_patches"
        fi
    else
        log_error "安全修复模块未加载" "security_patches"
    fi
}

# 配置文件验证菜单
config_validation_menu() {
    clear
    echo -e "${cyan}=== 配置文件验证 ===${white}"
    echo ""
    echo "1. SSH配置验证"
    echo "2. 防火墙配置验证"
    echo "3. 系统配置验证"
    echo "4. 所有配置验证"
    echo ""
    echo "0. 返回主菜单"
    echo ""
    
    local choice
    if secure_read_input "请选择验证类型 [0-4]: " "validate_numeric_range_or_empty" 3 30 choice; then
        case "${choice:-0}" in
            1) validate_ssh_config ;;
            2) validate_firewall_config ;;
            3) validate_system_config ;;
            4) validate_all_configs ;;
            0) return ;;
        esac
    fi
}

# SSH配置验证
validate_ssh_config() {
    echo -e "${cyan}验证SSH配置...${white}"
    
    if sshd -t 2>/dev/null; then
        log_success "SSH配置语法正确" "config_validation"
    else
        log_error "SSH配置语法错误" "config_validation"
        echo "错误详情:"
        sshd -t
    fi
    
    # 使用增强的SSH验证器
    if command -v ssh_security_validator >/dev/null; then
        ssh_security_validator "/etc/ssh/sshd_config"
    fi
}

# 验证所有配置
validate_all_configs() {
    echo -e "${cyan}=== 验证所有配置文件 ===${white}"
    
    validate_ssh_config
    echo ""
    validate_firewall_config
    echo ""
    validate_system_config
    
    log_success "所有配置验证完成" "config_validation"
}

#endregion

#region //报告生成和监控

# 生成安全报告
generate_security_report() {
    local report_file="/tmp/vps_security_report_$(date +%Y%m%d_%H%M%S).html"
    
    log_info "生成安全报告..." "report_generator"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>VPS安全报告</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
        .success { color: #27ae60; }
        .warning { color: #f39c12; }
        .error { color: #e74c3c; }
        .info { color: #3498db; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>VPS安全加固报告</h1>
        <p>生成时间: $(date)</p>
        <p>系统: $(uname -a)</p>
        <p>工具版本: $ENHANCED_VERSION</p>
    </div>
    
    <div class="section">
        <h2>系统信息</h2>
        <table>
            <tr><th>项目</th><th>值</th></tr>
            <tr><td>主机名</td><td>$(hostname)</td></tr>
            <tr><td>内核版本</td><td>$(uname -r)</td></tr>
            <tr><td>系统负载</td><td>$(uptime | cut -d',' -f4-)</td></tr>
            <tr><td>内存使用</td><td>$(free -h | grep Mem | awk '{print $3"/"$2}')</td></tr>
            <tr><td>磁盘使用</td><td>$(df -h / | tail -1 | awk '{print $3"/"$2" ("$5")"}')</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>安全状态检查</h2>
        <h3>SSH服务</h3>
        <ul>
EOF
    
    # 添加SSH状态检查
    if systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
        echo '<li class="success">✓ SSH服务正在运行</li>' >> "$report_file"
    else
        echo '<li class="error">✗ SSH服务未运行</li>' >> "$report_file"
    fi
    
    if sshd -t 2>/dev/null; then
        echo '<li class="success">✓ SSH配置语法正确</li>' >> "$report_file"
    else
        echo '<li class="error">✗ SSH配置语法错误</li>' >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
        </ul>
        
        <h3>防火墙状态</h3>
        <ul>
EOF
    
    # 添加防火墙状态检查
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        echo '<li class="success">✓ UFW防火墙已启用</li>' >> "$report_file"
    elif command -v iptables >/dev/null && iptables -L | grep -q "Chain"; then
        echo '<li class="warning">⚠ 使用iptables防火墙</li>' >> "$report_file"
    else
        echo '<li class="error">✗ 防火墙未配置</li>' >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
        </ul>
    </div>
    
    <div class="section">
        <h2>建议操作</h2>
        <ul>
            <li>定期更新系统和软件包</li>
            <li>定期检查系统日志</li>
            <li>定期备份重要配置文件</li>
            <li>监控系统资源使用情况</li>
            <li>定期进行安全审计</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>联系信息</h2>
        <p>本报告由VPS安全加固工具 v$ENHANCED_VERSION 生成</p>
        <p>如有问题，请检查系统日志或重新运行安全检查</p>
    </div>
</body>
</html>
EOF
    
    log_success "安全报告已生成: $report_file" "report_generator"
    echo -e "${green}可以使用浏览器打开查看详细报告${white}"
}

# 性能监控
performance_monitoring() {
    echo -e "${cyan}=== 系统性能监控 ===${white}"
    
    log_info "收集系统性能数据..." "performance_monitor"
    
    echo "CPU使用率:"
    top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1
    
    echo ""
    echo "内存使用情况:"
    free -h
    
    echo ""
    echo "磁盘使用情况:"
    df -h
    
    echo ""
    echo "网络连接统计:"
    ss -s
    
    echo ""
    echo "系统负载:"
    uptime
    
    log_success "性能监控数据收集完成" "performance_monitor"
}

# 安全基线检查
security_baseline_check() {
    echo -e "${cyan}=== 安全基线检查 ===${white}"
    
    log_info "执行安全基线检查..." "baseline_check"
    
    local total_checks=0
    local passed_checks=0
    
    # 检查项目列表
    local checks=(
        "check_ssh_config:SSH配置安全性"
        "check_firewall_status:防火墙状态"
        "check_system_updates:系统更新状态"
        "check_user_accounts:用户账户安全"
        "check_file_permissions:文件权限"
        "check_service_security:服务安全"
    )
    
    for check_item in "${checks[@]}"; do
        local check_func="${check_item%:*}"
        local check_desc="${check_item#*:}"
        
        ((total_checks++))
        
        echo -n "检查 $check_desc... "
        
        if command -v "$check_func" >/dev/null && "$check_func"; then
            echo -e "${green}通过${white}"
            ((passed_checks++))
        else
            echo -e "${red}失败${white}"
        fi
    done
    
    echo ""
    echo "基线检查结果: $passed_checks/$total_checks 通过"
    
    local percentage=$((passed_checks * 100 / total_checks))
    if [[ $percentage -ge 80 ]]; then
        log_success "安全基线检查: 良好 ($percentage%)" "baseline_check"
    elif [[ $percentage -ge 60 ]]; then
        log_warn "安全基线检查: 一般 ($percentage%)" "baseline_check"
    else
        log_error "安全基线检查: 差 ($percentage%)" "baseline_check"
    fi
}

#endregion

#region //占位符函数（需要根据具体需求实现）

# 以下是一些占位符函数，可以根据需要进一步实现

firewall_security_menu() {
    echo -e "${yellow}防火墙安全配置功能开发中...${white}"
}

system_security_menu() {
    echo -e "${yellow}系统安全优化功能开发中...${white}"
}

system_health_menu() {
    echo -e "${yellow}系统健康检查功能开发中...${white}"
}

backup_recovery_menu() {
    echo -e "${yellow}备份和恢复功能开发中...${white}"
}

secure_proxy_deployment() {
    echo -e "${yellow}安全代理部署功能开发中...${white}"
}

proxy_config_management() {
    echo -e "${yellow}代理配置管理功能开发中...${white}"
}

vulnerability_scan() {
    echo -e "${yellow}漏洞扫描功能开发中...${white}"
}

validate_firewall_config() {
    echo -e "${yellow}防火墙配置验证功能开发中...${white}"
}

validate_system_config() {
    echo -e "${yellow}系统配置验证功能开发中...${white}"
}

analyze_log_statistics() {
    echo -e "${yellow}日志统计分析功能开发中...${white}"
}

# 基线检查函数
check_ssh_config() {
    sshd -t 2>/dev/null
}

check_firewall_status() {
    if command -v ufw >/dev/null; then
        ufw status | grep -q "Status: active"
    else
        return 1
    fi
}

check_system_updates() {
    if command -v apt >/dev/null; then
        local updates=$(apt list --upgradable 2>/dev/null | wc -l)
        [[ $updates -lt 10 ]]
    else
        return 0
    fi
}

check_user_accounts() {
    # 检查是否有多余的用户账户
    local user_count=$(cut -d: -f1 /etc/passwd | wc -l)
    [[ $user_count -lt 50 ]]
}

check_file_permissions() {
    # 检查关键文件权限
    [[ $(stat -c '%a' /etc/shadow 2>/dev/null) == "600" ]]
}

check_service_security() {
    # 检查关键服务是否运行
    systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1
}

#endregion

# 主程序入口
main() {
    # 检查权限
    if [[ $EUID -ne 0 ]]; then
        echo -e "${red}此脚本需要root权限运行${white}"
        echo "请使用: sudo $0"
        exit 1
    fi
    
    # 加载模块
    load_enhanced_modules
    
    # 初始化系统
    initialize_security_system
    
    # 启动主菜单
    security_main_menu
}

# 如果直接运行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi