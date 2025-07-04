#!/bin/bash

# 增强的错误处理和日志记录系统
# 提供统一的错误处理、日志记录和恢复机制

#region //增强的日志记录系统

# 日志级别定义
declare -A LOG_LEVELS=(
    ["DEBUG"]=0
    ["INFO"]=1
    ["WARN"]=2
    ["ERROR"]=3
    ["CRITICAL"]=4
)

# 当前日志级别（默认INFO）
CURRENT_LOG_LEVEL=${CURRENT_LOG_LEVEL:-1}

# 日志文件配置
LOG_DIR="/var/log/security-hardening"
LOG_FILE="$LOG_DIR/security-hardening.log"
ERROR_LOG_FILE="$LOG_DIR/error.log"
AUDIT_LOG_FILE="$LOG_DIR/audit.log"
MAX_LOG_SIZE=10485760  # 10MB
MAX_LOG_FILES=5

# 确保日志目录存在
ensure_log_directory() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR"
        chmod 750 "$LOG_DIR"
        chown root:root "$LOG_DIR"
    fi
}

# 日志轮转函数
rotate_log_if_needed() {
    local log_file="$1"
    
    if [[ -f "$log_file" ]]; then
        local file_size=$(stat -c%s "$log_file" 2>/dev/null || echo 0)
        
        if [[ $file_size -gt $MAX_LOG_SIZE ]]; then
            # 轮转日志文件
            for ((i=MAX_LOG_FILES; i>1; i--)); do
                local old_file="${log_file}.$((i-1))"
                local new_file="${log_file}.$i"
                [[ -f "$old_file" ]] && mv "$old_file" "$new_file"
            done
            
            mv "$log_file" "${log_file}.1"
            touch "$log_file"
            chmod 640 "$log_file"
            chown root:root "$log_file"
        fi
    fi
}

# 结构化日志记录函数
write_structured_log() {
    local level="$1"
    local component="$2"
    local message="$3"
    local extra_data="${4:-}"
    
    # 检查日志级别
    if [[ ${LOG_LEVELS[$level]} -lt $CURRENT_LOG_LEVEL ]]; then
        return 0
    fi
    
    ensure_log_directory
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname=$(hostname)
    local user=$(whoami)
    local pid=$$
    
    # JSON格式的结构化日志
    local log_entry=$(cat << EOF
{
  "timestamp": "$timestamp",
  "level": "$level",
  "hostname": "$hostname",
  "user": "$user",
  "pid": $pid,
  "component": "$component",
  "message": "$message"$([ -n "$extra_data" ] && echo ", \"extra\": $extra_data" || echo "")
}
EOF
)
    
    # 写入主日志文件
    rotate_log_if_needed "$LOG_FILE"
    echo "$log_entry" >> "$LOG_FILE"
    
    # 错误级别写入错误日志
    if [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS["ERROR"]} ]]; then
        rotate_log_if_needed "$ERROR_LOG_FILE"
        echo "$log_entry" >> "$ERROR_LOG_FILE"
    fi
}

# 便捷的日志记录函数
log_debug() {
    write_structured_log "DEBUG" "${2:-main}" "$1" "$3"
}

log_info() {
    write_structured_log "INFO" "${2:-main}" "$1" "$3"
    echo -e "${blue}ℹ $1${white}"
}

log_warn() {
    write_structured_log "WARN" "${2:-main}" "$1" "$3"
    echo -e "${yellow}⚠ $1${white}"
}

log_error() {
    write_structured_log "ERROR" "${2:-main}" "$1" "$3"
    echo -e "${red}✗ $1${white}" >&2
}

log_critical() {
    write_structured_log "CRITICAL" "${2:-main}" "$1" "$3"
    echo -e "${red}💀 $1${white}" >&2
}

log_success() {
    write_structured_log "INFO" "${2:-main}" "SUCCESS: $1" "$3"
    echo -e "${green}✓ $1${white}"
}

# 操作审计日志
log_audit() {
    local operation="$1"
    local details="$2"
    local result="${3:-success}"
    
    ensure_log_directory
    rotate_log_if_needed "$AUDIT_LOG_FILE"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local user=$(whoami)
    local tty=$(tty 2>/dev/null || echo "unknown")
    
    local audit_entry=$(cat << EOF
{
  "timestamp": "$timestamp",
  "user": "$user",
  "tty": "$tty",
  "operation": "$operation",
  "details": "$details",
  "result": "$result",
  "pid": $$
}
EOF
)
    
    echo "$audit_entry" >> "$AUDIT_LOG_FILE"
}

#endregion

#region //增强的错误处理系统

# 错误处理配置
ERROR_RECOVERY_ENABLED=true
ERROR_CONTEXT_STACK=()
CLEANUP_FUNCTIONS=()

# 错误上下文管理
push_error_context() {
    local context="$1"
    ERROR_CONTEXT_STACK+=("$context")
    log_debug "进入错误上下文: $context" "error_handler"
}

pop_error_context() {
    if [[ ${#ERROR_CONTEXT_STACK[@]} -gt 0 ]]; then
        local context="${ERROR_CONTEXT_STACK[-1]}"
        unset 'ERROR_CONTEXT_STACK[-1]'
        log_debug "退出错误上下文: $context" "error_handler"
    fi
}

get_current_context() {
    if [[ ${#ERROR_CONTEXT_STACK[@]} -gt 0 ]]; then
        echo "${ERROR_CONTEXT_STACK[-1]}"
    else
        echo "unknown"
    fi
}

# 注册清理函数
register_cleanup() {
    local cleanup_func="$1"
    CLEANUP_FUNCTIONS+=("$cleanup_func")
    log_debug "注册清理函数: $cleanup_func" "error_handler"
}

# 执行清理函数
execute_cleanup() {
    log_info "执行清理操作..." "error_handler"
    
    for ((i=${#CLEANUP_FUNCTIONS[@]}-1; i>=0; i--)); do
        local cleanup_func="${CLEANUP_FUNCTIONS[$i]}"
        log_debug "执行清理函数: $cleanup_func" "error_handler"
        
        if command -v "$cleanup_func" >/dev/null; then
            if "$cleanup_func"; then
                log_debug "清理函数执行成功: $cleanup_func" "error_handler"
            else
                log_warn "清理函数执行失败: $cleanup_func" "error_handler"
            fi
        else
            log_warn "清理函数不存在: $cleanup_func" "error_handler"
        fi
    done
    
    # 清空清理函数列表
    CLEANUP_FUNCTIONS=()
}

# 增强的错误处理函数
handle_error() {
    local exit_code=$1
    local line_number=$2
    local command="$3"
    local context=$(get_current_context)
    
    log_error "命令执行失败" "error_handler" "{\"exit_code\": $exit_code, \"line\": $line_number, \"command\": \"$command\", \"context\": \"$context\"}"
    
    # 记录堆栈跟踪
    log_error "错误堆栈跟踪:" "error_handler"
    local frame=1
    while read -r line func file < <(caller $frame); do
        log_error "  $frame: $func() in $file:$line" "error_handler"
        ((frame++))
    done
    
    # 执行清理操作
    execute_cleanup
    
    # 根据错误类型尝试恢复
    if [[ "$ERROR_RECOVERY_ENABLED" == "true" ]]; then
        attempt_error_recovery "$exit_code" "$context" "$command"
    fi
    
    # 记录审计日志
    log_audit "ERROR" "Command failed: $command in context: $context" "failure"
    
    exit $exit_code
}

# 错误恢复尝试
attempt_error_recovery() {
    local exit_code="$1"
    local context="$2"
    local command="$3"
    
    log_info "尝试错误恢复..." "error_recovery"
    
    case "$context" in
        "ssh_config")
            recover_ssh_config_error "$exit_code" "$command"
            ;;
        "firewall_config")
            recover_firewall_error "$exit_code" "$command"
            ;;
        "service_management")
            recover_service_error "$exit_code" "$command"
            ;;
        "file_operations")
            recover_file_operation_error "$exit_code" "$command"
            ;;
        *)
            log_warn "没有可用的恢复策略: $context" "error_recovery"
            ;;
    esac
}

# SSH配置错误恢复
recover_ssh_config_error() {
    local exit_code="$1"
    local command="$2"
    
    log_info "尝试SSH配置恢复..." "ssh_recovery"
    
    # 检查备份文件
    local backup_files=(
        "/etc/ssh/sshd_config.backup"
        "/etc/ssh/sshd_config.backup.*"
    )
    
    for backup in "${backup_files[@]}"; do
        if [[ -f "$backup" ]]; then
            log_info "发现备份文件: $backup" "ssh_recovery"
            
            if confirm_action "是否恢复SSH配置备份？"; then
                if cp "$backup" "/etc/ssh/sshd_config"; then
                    log_success "SSH配置已从备份恢复" "ssh_recovery"
                    
                    # 验证配置
                    if sshd -t; then
                        log_success "SSH配置验证通过" "ssh_recovery"
                        
                        # 重启SSH服务
                        if systemctl restart sshd || systemctl restart ssh; then
                            log_success "SSH服务已重启" "ssh_recovery"
                            return 0
                        fi
                    fi
                fi
            fi
        fi
    done
    
    log_error "SSH配置恢复失败" "ssh_recovery"
    return 1
}

# 防火墙错误恢复
recover_firewall_error() {
    local exit_code="$1"
    local command="$2"
    
    log_info "尝试防火墙配置恢复..." "firewall_recovery"
    
    # 重置防火墙规则
    if command -v ufw >/dev/null; then
        if confirm_action "是否重置UFW防火墙规则？"; then
            ufw --force reset
            ufw --force enable
            log_success "UFW防火墙已重置" "firewall_recovery"
            return 0
        fi
    elif command -v iptables >/dev/null; then
        if confirm_action "是否清除iptables规则？"; then
            iptables -F
            iptables -X
            iptables -Z
            log_success "iptables规则已清除" "firewall_recovery"
            return 0
        fi
    fi
    
    return 1
}

# 服务错误恢复
recover_service_error() {
    local exit_code="$1"
    local command="$2"
    
    log_info "尝试服务恢复..." "service_recovery"
    
    # 从命令中提取服务名
    local service_name
    if [[ "$command" =~ systemctl.*([a-zA-Z0-9_-]+) ]]; then
        service_name="${BASH_REMATCH[1]}"
        
        log_info "检查服务状态: $service_name" "service_recovery"
        
        # 检查服务状态
        local service_status=$(systemctl is-active "$service_name" 2>/dev/null || echo "unknown")
        
        case "$service_status" in
            "failed"|"inactive")
                if confirm_action "是否尝试重启服务 $service_name？"; then
                    if systemctl restart "$service_name"; then
                        log_success "服务 $service_name 已重启" "service_recovery"
                        return 0
                    fi
                fi
                ;;
            "active")
                log_success "服务 $service_name 正在运行" "service_recovery"
                return 0
                ;;
        esac
    fi
    
    return 1
}

# 文件操作错误恢复
recover_file_operation_error() {
    local exit_code="$1"
    local command="$2"
    
    log_info "尝试文件操作恢复..." "file_recovery"
    
    # 检查磁盘空间
    local available_space=$(df / | tail -1 | awk '{print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # 小于1GB
        log_warn "磁盘空间不足: ${available_space}KB" "file_recovery"
        
        if confirm_action "是否清理临时文件？"; then
            cleanup_temp_files
        fi
    fi
    
    # 检查权限问题
    if [[ $exit_code -eq 1 ]] && [[ "$command" =~ (cp|mv|mkdir|chmod|chown) ]]; then
        log_warn "可能是权限问题，请检查文件权限" "file_recovery"
    fi
    
    return 1
}

# 临时文件清理
cleanup_temp_files() {
    log_info "清理临时文件..." "cleanup"
    
    local temp_dirs=(
        "/tmp"
        "/var/tmp"
        "/var/log"
    )
    
    for dir in "${temp_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # 清理超过7天的临时文件
            find "$dir" -type f -mtime +7 -name "*.tmp" -delete 2>/dev/null
            find "$dir" -type f -mtime +7 -name "*.log.*" -delete 2>/dev/null
        fi
    done
    
    log_success "临时文件清理完成" "cleanup"
}

# 确认操作函数
confirm_action() {
    local message="$1"
    local timeout="${2:-30}"
    
    echo -e "${yellow}$message (y/N): ${white}"
    
    local response
    if read -r -t "$timeout" response; then
        [[ "$response" =~ ^[Yy]$ ]]
    else
        log_warn "操作超时，默认取消" "confirm"
        return 1
    fi
}

#endregion

#region //错误处理设置

# 设置错误处理陷阱
setup_error_handling() {
    # 启用严格模式
    set -eE  # 遇到错误立即退出，包括函数中的错误
    set -u   # 使用未定义变量时报错
    set -o pipefail  # 管道中任何命令失败都会导致整个管道失败
    
    # 设置错误陷阱
    trap 'handle_error $? $LINENO "$BASH_COMMAND"' ERR
    
    # 设置退出陷阱
    trap 'execute_cleanup' EXIT
    
    log_info "错误处理系统已启用" "error_handler"
}

# 安全执行函数
safe_execute() {
    local command="$1"
    local context="${2:-general}"
    local allow_failure="${3:-false}"
    
    push_error_context "$context"
    
    log_debug "执行命令: $command" "$context"
    
    if [[ "$allow_failure" == "true" ]]; then
        # 允许失败的执行
        set +e
        eval "$command"
        local exit_code=$?
        set -e
        
        if [[ $exit_code -ne 0 ]]; then
            log_warn "命令执行失败但已忽略: $command (退出码: $exit_code)" "$context"
        fi
        
        pop_error_context
        return $exit_code
    else
        # 正常执行
        eval "$command"
        pop_error_context
        return 0
    fi
}

# 重试执行函数
retry_execute() {
    local command="$1"
    local max_attempts="${2:-3}"
    local delay="${3:-2}"
    local context="${4:-retry}"
    
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "尝试执行 ($attempt/$max_attempts): $command" "$context"
        
        if safe_execute "$command" "$context" "true"; then
            log_success "命令执行成功" "$context"
            return 0
        else
            if [[ $attempt -lt $max_attempts ]]; then
                log_warn "命令执行失败，${delay}秒后重试..." "$context"
                sleep "$delay"
            fi
        fi
        
        ((attempt++))
    done
    
    log_error "命令在 $max_attempts 次尝试后仍然失败: $command" "$context"
    return 1
}

#endregion

# 日志查询和分析工具
analyze_logs() {
    local log_type="${1:-all}"
    local lines="${2:-50}"
    
    echo -e "${cyan}=== 日志分析 ===${white}"
    
    case "$log_type" in
        "error")
            if [[ -f "$ERROR_LOG_FILE" ]]; then
                echo "最近的错误日志:"
                tail -n "$lines" "$ERROR_LOG_FILE" | jq -r '.timestamp + " [" + .level + "] " + .message'
            else
                echo "没有找到错误日志文件"
            fi
            ;;
        "audit")
            if [[ -f "$AUDIT_LOG_FILE" ]]; then
                echo "最近的审计日志:"
                tail -n "$lines" "$AUDIT_LOG_FILE" | jq -r '.timestamp + " " + .user + " " + .operation + ": " + .details'
            else
                echo "没有找到审计日志文件"
            fi
            ;;
        "all")
            if [[ -f "$LOG_FILE" ]]; then
                echo "最近的系统日志:"
                tail -n "$lines" "$LOG_FILE" | jq -r '.timestamp + " [" + .level + "] " + .component + ": " + .message'
            else
                echo "没有找到主日志文件"
            fi
            ;;
    esac
}

# 初始化函数
init_enhanced_logging() {
    setup_error_handling
    ensure_log_directory
    log_info "增强的日志记录和错误处理系统已初始化" "init"
}

# 如果直接运行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    init_enhanced_logging
    
    echo "增强的错误处理和日志系统演示:"
    echo "1. 查看错误日志"
    echo "2. 查看审计日志"
    echo "3. 查看全部日志"
    echo "4. 测试错误处理"
    
    read -p "请选择: " choice
    
    case "$choice" in
        1) analyze_logs "error" ;;
        2) analyze_logs "audit" ;;
        3) analyze_logs "all" ;;
        4) 
            log_info "测试日志记录..."
            log_warn "这是一个警告消息"
            log_error "这是一个错误消息"
            log_success "测试完成"
            ;;
    esac
fi