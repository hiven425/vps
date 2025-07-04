#!/bin/bash

# 安全的服务管理模块
# 提供统一、安全的系统服务管理功能

#region //安全服务管理核心

# 服务管理配置
ALLOWED_SERVICES=(
    "ssh"
    "sshd" 
    "xray"
    "fail2ban"
    "ufw"
    "iptables"
    "nginx"
    "apache2"
    "systemd-resolved"
)

SERVICE_TIMEOUT=30
SERVICE_RETRY_COUNT=3
SERVICE_RETRY_DELAY=2

# 验证服务名称是否在允许列表中
validate_service_name() {
    local service_name="$1"
    
    # 清理服务名称
    service_name=$(echo "$service_name" | tr -d '`;|&$(){}[]\\')
    
    # 检查是否在允许列表中
    for allowed in "${ALLOWED_SERVICES[@]}"; do
        if [[ "$service_name" == "$allowed" ]]; then
            echo "$service_name"
            return 0
        fi
    done
    
    log_error "服务名称不在允许列表中: $service_name" "service_manager"
    return 1
}

# 获取服务的实际名称（处理ssh/sshd别名）
get_actual_service_name() {
    local service_name="$1"
    
    case "$service_name" in
        "ssh"|"sshd")
            # 检查系统中实际使用的SSH服务名
            if systemctl list-unit-files 2>/dev/null | grep -q "^sshd.service"; then
                echo "sshd"
            elif systemctl list-unit-files 2>/dev/null | grep -q "^ssh.service"; then
                echo "ssh"
            else
                log_error "未找到SSH服务" "service_manager"
                return 1
            fi
            ;;
        *)
            echo "$service_name"
            ;;
    esac
}

# 安全的服务状态检查
secure_service_status() {
    local service_name="$1"
    local detailed="${2:-false}"
    
    # 验证服务名称
    service_name=$(validate_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    # 获取实际服务名称
    local actual_service
    actual_service=$(get_actual_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    log_debug "检查服务状态: $actual_service" "service_manager"
    
    # 获取服务状态信息
    local active_status=$(systemctl is-active "$actual_service" 2>/dev/null || echo "unknown")
    local enabled_status=$(systemctl is-enabled "$actual_service" 2>/dev/null || echo "unknown")
    local loaded_status=$(systemctl is-loaded "$actual_service" 2>/dev/null || echo "unknown")
    
    if [[ "$detailed" == "true" ]]; then
        echo "服务: $actual_service"
        echo "  运行状态: $active_status"
        echo "  启用状态: $enabled_status"
        echo "  加载状态: $loaded_status"
        
        # 获取更详细的信息
        if [[ "$active_status" == "active" ]]; then
            local main_pid=$(systemctl show -p MainPID "$actual_service" 2>/dev/null | cut -d= -f2)
            if [[ -n "$main_pid" && "$main_pid" != "0" ]]; then
                echo "  主进程PID: $main_pid"
                
                # 获取内存使用情况
                local memory_usage=$(systemctl show -p MemoryCurrent "$actual_service" 2>/dev/null | cut -d= -f2)
                if [[ -n "$memory_usage" && "$memory_usage" != "[not set]" ]]; then
                    echo "  内存使用: $(( memory_usage / 1024 / 1024 ))MB"
                fi
            fi
        fi
        
        # 显示最近的日志
        echo "  最近日志:"
        journalctl -u "$actual_service" -n 3 --no-pager -q 2>/dev/null | sed 's/^/    /'
    else
        echo "$active_status"
    fi
    
    return 0
}

# 安全的服务操作函数
secure_service_operation() {
    local operation="$1"
    local service_name="$2"
    local force="${3:-false}"
    
    # 验证操作类型
    case "$operation" in
        "start"|"stop"|"restart"|"reload"|"enable"|"disable")
            ;;
        *)
            log_error "不支持的服务操作: $operation" "service_manager"
            return 1
            ;;
    esac
    
    # 验证服务名称
    service_name=$(validate_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    # 获取实际服务名称
    local actual_service
    actual_service=$(get_actual_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    log_audit "SERVICE_OPERATION" "Operation: $operation, Service: $actual_service"
    
    # 检查服务是否存在
    if ! systemctl list-unit-files 2>/dev/null | grep -q "^${actual_service}.service"; then
        log_error "服务不存在: $actual_service" "service_manager"
        return 1
    fi
    
    # 获取当前状态
    local current_status=$(systemctl is-active "$actual_service" 2>/dev/null || echo "unknown")
    
    # 危险操作确认
    case "$operation" in
        "stop"|"disable")
            if [[ "$actual_service" =~ ^(ssh|sshd)$ ]] && [[ "$force" != "true" ]]; then
                log_warn "警告: 即将$operation SSH服务，这可能导致连接断开" "service_manager"
                
                if ! confirm_action "确认要$operation SSH服务吗？这可能导致无法远程连接"; then
                    log_info "用户取消SSH服务操作" "service_manager"
                    return 1
                fi
            fi
            ;;
    esac
    
    log_info "执行服务操作: $operation $actual_service" "service_manager"
    
    # 执行操作
    local success=false
    local attempts=0
    
    while [[ $attempts -lt $SERVICE_RETRY_COUNT ]]; do
        ((attempts++))
        
        push_error_context "service_management"
        
        if timeout "$SERVICE_TIMEOUT" systemctl "$operation" "$actual_service" 2>/dev/null; then
            success=true
            break
        else
            local exit_code=$?
            log_warn "服务操作失败 (尝试 $attempts/$SERVICE_RETRY_COUNT): $operation $actual_service" "service_manager"
            
            if [[ $attempts -lt $SERVICE_RETRY_COUNT ]]; then
                log_info "${SERVICE_RETRY_DELAY}秒后重试..." "service_manager"
                sleep "$SERVICE_RETRY_DELAY"
            fi
        fi
        
        pop_error_context
    done
    
    if [[ "$success" == "true" ]]; then
        # 验证操作结果
        sleep 2  # 等待服务状态更新
        
        case "$operation" in
            "start")
                local new_status=$(systemctl is-active "$actual_service" 2>/dev/null)
                if [[ "$new_status" == "active" ]]; then
                    log_success "服务启动成功: $actual_service" "service_manager"
                else
                    log_error "服务启动失败，当前状态: $new_status" "service_manager"
                    return 1
                fi
                ;;
            "stop")
                local new_status=$(systemctl is-active "$actual_service" 2>/dev/null)
                if [[ "$new_status" == "inactive" ]]; then
                    log_success "服务停止成功: $actual_service" "service_manager"
                else
                    log_warn "服务可能未完全停止，当前状态: $new_status" "service_manager"
                fi
                ;;
            "restart"|"reload")
                local new_status=$(systemctl is-active "$actual_service" 2>/dev/null)
                if [[ "$new_status" == "active" ]]; then
                    log_success "服务$operation成功: $actual_service" "service_manager"
                else
                    log_error "服务$operation失败，当前状态: $new_status" "service_manager"
                    return 1
                fi
                ;;
            "enable")
                local enabled_status=$(systemctl is-enabled "$actual_service" 2>/dev/null)
                if [[ "$enabled_status" == "enabled" ]]; then
                    log_success "服务启用成功: $actual_service" "service_manager"
                else
                    log_warn "服务启用状态: $enabled_status" "service_manager"
                fi
                ;;
            "disable")
                local enabled_status=$(systemctl is-enabled "$actual_service" 2>/dev/null)
                if [[ "$enabled_status" == "disabled" ]]; then
                    log_success "服务禁用成功: $actual_service" "service_manager"
                else
                    log_warn "服务禁用状态: $enabled_status" "service_manager"
                fi
                ;;
        esac
        
        log_audit "SERVICE_OPERATION" "Operation: $operation, Service: $actual_service, Result: success"
        return 0
    else
        log_error "服务操作最终失败: $operation $actual_service" "service_manager"
        log_audit "SERVICE_OPERATION" "Operation: $operation, Service: $actual_service, Result: failure"
        return 1
    fi
}

#endregion

#region //高级服务管理功能

# 批量服务操作
batch_service_operation() {
    local operation="$1"
    shift
    local services=("$@")
    
    if [[ ${#services[@]} -eq 0 ]]; then
        log_error "没有指定服务" "batch_service"
        return 1
    fi
    
    log_info "批量服务操作: $operation (${#services[@]}个服务)" "batch_service"
    
    local success_count=0
    local failed_services=()
    
    for service in "${services[@]}"; do
        log_info "处理服务: $service" "batch_service"
        
        if secure_service_operation "$operation" "$service"; then
            ((success_count++))
            log_success "服务 $service 操作成功" "batch_service"
        else
            failed_services+=("$service")
            log_error "服务 $service 操作失败" "batch_service"
        fi
    done
    
    echo
    echo "批量操作结果:"
    echo "  成功: $success_count/${#services[@]}"
    echo "  失败: ${#failed_services[@]}/${#services[@]}"
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        echo "  失败的服务: ${failed_services[*]}"
    fi
    
    log_audit "BATCH_SERVICE_OPERATION" "Operation: $operation, Total: ${#services[@]}, Success: $success_count, Failed: ${#failed_services[@]}"
    
    return $([[ ${#failed_services[@]} -eq 0 ]])
}

# 服务健康检查
service_health_check() {
    local service_name="$1"
    local check_config="${2:-true}"
    
    service_name=$(validate_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    local actual_service
    actual_service=$(get_actual_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    log_info "执行服务健康检查: $actual_service" "health_check"
    
    local health_score=0
    local max_score=10
    local issues=()
    local warnings=()
    
    # 1. 检查服务是否运行 (3分)
    local active_status=$(systemctl is-active "$actual_service" 2>/dev/null)
    if [[ "$active_status" == "active" ]]; then
        health_score=$((health_score + 3))
        log_success "服务正在运行" "health_check"
    else
        issues+=("服务未运行，状态: $active_status")
    fi
    
    # 2. 检查服务是否启用 (2分)
    local enabled_status=$(systemctl is-enabled "$actual_service" 2>/dev/null)
    if [[ "$enabled_status" == "enabled" ]]; then
        health_score=$((health_score + 2))
        log_success "服务已启用开机自启" "health_check"
    else
        warnings+=("服务未启用开机自启，状态: $enabled_status")
    fi
    
    # 3. 检查服务启动时间 (2分)
    if [[ "$active_status" == "active" ]]; then
        local active_time=$(systemctl show -p ActiveEnterTimestamp "$actual_service" 2>/dev/null | cut -d= -f2)
        if [[ -n "$active_time" && "$active_time" != "0" ]]; then
            health_score=$((health_score + 2))
            log_success "服务启动正常" "health_check"
        fi
    fi
    
    # 4. 检查内存使用 (1分)
    if [[ "$active_status" == "active" ]]; then
        local memory_usage=$(systemctl show -p MemoryCurrent "$actual_service" 2>/dev/null | cut -d= -f2)
        if [[ -n "$memory_usage" && "$memory_usage" != "[not set]" ]]; then
            local memory_mb=$((memory_usage / 1024 / 1024))
            if [[ $memory_mb -lt 500 ]]; then  # 内存使用小于500MB认为正常
                health_score=$((health_score + 1))
                log_success "内存使用正常: ${memory_mb}MB" "health_check"
            else
                warnings+=("内存使用较高: ${memory_mb}MB")
            fi
        fi
    fi
    
    # 5. 检查错误日志 (2分)
    local error_count=$(journalctl -u "$actual_service" --since "1 hour ago" -p err -q --no-pager 2>/dev/null | wc -l)
    if [[ $error_count -eq 0 ]]; then
        health_score=$((health_score + 2))
        log_success "近1小时无错误日志" "health_check"
    else
        issues+=("近1小时有 $error_count 条错误日志")
    fi
    
    # 特定服务的额外检查
    case "$actual_service" in
        "ssh"|"sshd")
            if [[ "$check_config" == "true" ]]; then
                if sshd -t 2>/dev/null; then
                    log_success "SSH配置语法正确" "health_check"
                else
                    issues+=("SSH配置语法错误")
                fi
            fi
            ;;
        "xray")
            if [[ -f "/usr/local/bin/xray" ]]; then
                if /usr/local/bin/xray version >/dev/null 2>&1; then
                    log_success "Xray程序正常" "health_check"
                else
                    issues+=("Xray程序异常")
                fi
            fi
            ;;
        "fail2ban")
            if command -v fail2ban-client >/dev/null; then
                if fail2ban-client status >/dev/null 2>&1; then
                    log_success "Fail2ban状态正常" "health_check"
                else
                    issues+=("Fail2ban状态异常")
                fi
            fi
            ;;
    esac
    
    # 显示健康检查结果
    echo
    echo -e "${cyan}=== 服务健康检查报告: $actual_service ===${white}"
    echo "健康评分: $health_score/$max_score"
    
    local health_percentage=$((health_score * 100 / max_score))
    if [[ $health_percentage -ge 80 ]]; then
        echo -e "${green}健康状态: 良好 ($health_percentage%)${white}"
    elif [[ $health_percentage -ge 60 ]]; then
        echo -e "${yellow}健康状态: 一般 ($health_percentage%)${white}"
    else
        echo -e "${red}健康状态: 差 ($health_percentage%)${white}"
    fi
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "\n${red}问题:${white}"
        for issue in "${issues[@]}"; do
            echo -e "${red}  ✗ $issue${white}"
        done
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo -e "\n${yellow}警告:${white}"
        for warning in "${warnings[@]}"; do
            echo -e "${yellow}  ⚠ $warning${white}"
        done
    fi
    
    return $([[ $health_percentage -ge 60 ]])
}

# 服务依赖管理
manage_service_dependencies() {
    local service_name="$1"
    local action="${2:-check}"
    
    service_name=$(validate_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    local actual_service
    actual_service=$(get_actual_service_name "$service_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    case "$action" in
        "check")
            echo -e "${cyan}=== 服务依赖检查: $actual_service ===${white}"
            
            # 获取依赖信息
            local wants=$(systemctl show -p Wants "$actual_service" 2>/dev/null | cut -d= -f2)
            local requires=$(systemctl show -p Requires "$actual_service" 2>/dev/null | cut -d= -f2)
            local wanted_by=$(systemctl show -p WantedBy "$actual_service" 2>/dev/null | cut -d= -f2)
            local required_by=$(systemctl show -p RequiredBy "$actual_service" 2>/dev/null | cut -d= -f2)
            
            if [[ -n "$wants" ]]; then
                echo "依赖服务 (Wants): $wants"
            fi
            
            if [[ -n "$requires" ]]; then
                echo "必需服务 (Requires): $requires"
            fi
            
            if [[ -n "$wanted_by" ]]; then
                echo "被依赖 (WantedBy): $wanted_by"
            fi
            
            if [[ -n "$required_by" ]]; then
                echo "被必需 (RequiredBy): $required_by"
            fi
            ;;
        "start_with_deps")
            log_info "启动服务及其依赖: $actual_service" "dependency_manager"
            # 实现依赖启动逻辑
            ;;
        "stop_with_deps")
            log_info "停止服务及其依赖: $actual_service" "dependency_manager"
            # 实现依赖停止逻辑
            ;;
    esac
}

#endregion

#region //服务管理菜单界面

# 交互式服务管理菜单
service_management_menu() {
    while true; do
        clear
        echo -e "${pink}=== 安全服务管理 ===${white}"
        echo ""
        echo "1. 查看服务状态"
        echo "2. 启动服务"
        echo "3. 停止服务"
        echo "4. 重启服务"
        echo "5. 启用服务"
        echo "6. 禁用服务"
        echo "7. 服务健康检查"
        echo "8. 批量操作"
        echo "9. 服务依赖管理"
        echo ""
        echo "0. 返回主菜单"
        echo ""
        
        local choice
        if secure_read_input "请选择操作 [0-9]: " "validate_numeric_range_or_empty" 3 30 choice; then
            case "${choice:-0}" in
                1) service_status_interactive ;;
                2) service_operation_interactive "start" ;;
                3) service_operation_interactive "stop" ;;
                4) service_operation_interactive "restart" ;;
                5) service_operation_interactive "enable" ;;
                6) service_operation_interactive "disable" ;;
                7) service_health_interactive ;;
                8) batch_operation_interactive ;;
                9) dependency_management_interactive ;;
                0) break ;;
                *) log_warn "无效选择" "menu" ;;
            esac
        else
            log_warn "输入超时或无效" "menu"
        fi
        
        echo
        echo "按任意键继续..."
        read -n 1 -s
    done
}

# 交互式服务状态查看
service_status_interactive() {
    echo -e "${cyan}=== 服务状态查看 ===${white}"
    echo ""
    echo "可用的服务:"
    for service in "${ALLOWED_SERVICES[@]}"; do
        echo "  $service"
    done
    echo ""
    
    local service_name
    if secure_read_input "请输入服务名称: " "validate_service_name" 3 30 service_name; then
        secure_service_status "$service_name" "true"
    fi
}

# 交互式服务操作
service_operation_interactive() {
    local operation="$1"
    
    echo -e "${cyan}=== 服务$operation ===${white}"
    echo ""
    echo "可用的服务:"
    for service in "${ALLOWED_SERVICES[@]}"; do
        echo "  $service"
    done
    echo ""
    
    local service_name
    if secure_read_input "请输入服务名称: " "validate_service_name" 3 30 service_name; then
        secure_service_operation "$operation" "$service_name"
    fi
}

# 交互式健康检查
service_health_interactive() {
    echo -e "${cyan}=== 服务健康检查 ===${white}"
    echo ""
    echo "可用的服务:"
    for service in "${ALLOWED_SERVICES[@]}"; do
        echo "  $service"
    done
    echo ""
    
    local service_name
    if secure_read_input "请输入服务名称: " "validate_service_name" 3 30 service_name; then
        service_health_check "$service_name" "true"
    fi
}

# 交互式批量操作
batch_operation_interactive() {
    echo -e "${cyan}=== 批量服务操作 ===${white}"
    echo ""
    echo "支持的操作: start, stop, restart, enable, disable"
    
    local operation
    if secure_read_input "请输入操作类型: " "" 3 30 operation; then
        case "$operation" in
            "start"|"stop"|"restart"|"enable"|"disable")
                echo ""
                echo "可用的服务:"
                for service in "${ALLOWED_SERVICES[@]}"; do
                    echo "  $service"
                done
                echo ""
                
                local services_input
                if secure_read_input "请输入服务名称(空格分隔): " "" 3 60 services_input; then
                    read -ra services_array <<< "$services_input"
                    batch_service_operation "$operation" "${services_array[@]}"
                fi
                ;;
            *)
                log_error "不支持的操作: $operation" "batch_operation"
                ;;
        esac
    fi
}

# 交互式依赖管理
dependency_management_interactive() {
    echo -e "${cyan}=== 服务依赖管理 ===${white}"
    echo ""
    echo "可用的服务:"
    for service in "${ALLOWED_SERVICES[@]}"; do
        echo "  $service"
    done
    echo ""
    
    local service_name
    if secure_read_input "请输入服务名称: " "validate_service_name" 3 30 service_name; then
        manage_service_dependencies "$service_name" "check"
    fi
}

#endregion

# 初始化服务管理系统
init_service_manager() {
    log_info "初始化安全服务管理系统..." "service_manager"
    
    # 检查systemd可用性
    if ! command -v systemctl >/dev/null; then
        log_error "系统不支持systemd" "service_manager"
        return 1
    fi
    
    # 检查权限
    if [[ $EUID -ne 0 ]]; then
        log_warn "需要root权限进行服务管理" "service_manager"
    fi
    
    log_success "安全服务管理系统已初始化" "service_manager"
    return 0
}

# 如果直接运行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 加载依赖
    source "$(dirname "$0")/enhanced-logging.sh" 2>/dev/null || {
        echo "警告: 无法加载增强日志模块"
        # 提供基本的日志函数
        log_info() { echo -e "\033[34mℹ $1\033[0m"; }
        log_error() { echo -e "\033[31m✗ $1\033[0m" >&2; }
        log_success() { echo -e "\033[32m✓ $1\033[0m"; }
        log_warn() { echo -e "\033[33m⚠ $1\033[0m"; }
        log_debug() { :; }
        log_audit() { :; }
        push_error_context() { :; }
        pop_error_context() { :; }
        confirm_action() { 
            echo -n "$1 (y/N): "
            read -r response
            [[ "$response" =~ ^[Yy]$ ]]
        }
        secure_read_input() {
            local prompt="$1"
            local result_var="$5"
            echo -n "$prompt"
            read -r user_input
            if [[ -n "$result_var" ]]; then
                eval "$result_var=\"$user_input\""
            fi
            return 0
        }
        validate_numeric_range_or_empty() { return 0; }
    }
    
    init_service_manager
    service_management_menu
fi