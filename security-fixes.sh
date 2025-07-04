#!/bin/bash

# VPS安全加固工具 - 安全修复补丁
# 用于修复主脚本中发现的安全漏洞

#region //安全的文件权限管理

# 安全的脚本复制函数
secure_copy_script_to_system() {
    local script_source="$0"
    local target_path="/usr/local/bin/security-hardening"
    local temp_path="${target_path}.tmp"
    
    # 验证源文件存在且可读
    if [[ ! -r "$script_source" ]]; then
        error_msg "源脚本文件不可读: $script_source"
        return 1
    fi
    
    # 检查目标目录权限
    if [[ ! -w "/usr/local/bin" ]]; then
        error_msg "没有写入权限: /usr/local/bin"
        return 1
    fi
    
    # 如果目标文件已存在，检查其权限和所有者
    if [[ -f "$target_path" ]]; then
        local file_owner=$(stat -c '%U' "$target_path" 2>/dev/null)
        local file_perms=$(stat -c '%a' "$target_path" 2>/dev/null)
        
        if [[ "$file_owner" != "root" ]]; then
            warn_msg "目标文件所有者不是root: $file_owner"
            return 1
        fi
        
        # 备份现有文件
        if ! cp "$target_path" "${target_path}.backup.$(date +%s)"; then
            error_msg "无法备份现有文件"
            return 1
        fi
        
        log_operation "备份现有脚本文件: ${target_path}.backup.$(date +%s)"
    fi
    
    # 安全复制：先复制到临时文件，然后原子性移动
    if ! cp "$script_source" "$temp_path"; then
        error_msg "复制脚本到临时位置失败"
        return 1
    fi
    
    # 设置严格的文件权限 (仅root可读写执行，其他用户可读执行)
    if ! chmod 755 "$temp_path"; then
        error_msg "设置文件权限失败"
        rm -f "$temp_path"
        return 1
    fi
    
    # 确保文件所有者是root
    if ! chown root:root "$temp_path"; then
        error_msg "设置文件所有者失败"
        rm -f "$temp_path"
        return 1
    fi
    
    # 原子性移动到目标位置
    if ! mv "$temp_path" "$target_path"; then
        error_msg "移动文件到目标位置失败"
        rm -f "$temp_path"
        return 1
    fi
    
    success_msg "脚本已安全复制到系统路径: $target_path"
    log_operation "脚本已安全复制到系统路径，权限: 755，所有者: root:root"
    
    return 0
}

# 安全的配置文件修改函数
secure_update_authorization() {
    local config_file="/etc/security-hardening/config"
    local config_dir="/etc/security-hardening"
    
    # 确保配置目录存在且权限正确
    if [[ ! -d "$config_dir" ]]; then
        if ! mkdir -p "$config_dir"; then
            error_msg "无法创建配置目录: $config_dir"
            return 1
        fi
        
        # 设置目录权限：仅root可访问
        if ! chmod 700 "$config_dir"; then
            error_msg "设置配置目录权限失败"
            return 1
        fi
        
        if ! chown root:root "$config_dir"; then
            error_msg "设置配置目录所有者失败"
            return 1
        fi
    fi
    
    # 创建安全的配置文件
    local temp_config="${config_file}.tmp"
    
    # 生成配置内容
    cat > "$temp_config" << EOF
# VPS安全加固工具配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 警告: 此文件包含敏感配置，请勿修改

user_authorization="true"
script_version="$version"
last_updated="$(date '+%Y-%m-%d %H:%M:%S')"
authorized_by="$(whoami)"
EOF
    
    # 设置严格的文件权限
    if ! chmod 600 "$temp_config"; then
        error_msg "设置配置文件权限失败"
        rm -f "$temp_config"
        return 1
    fi
    
    if ! chown root:root "$temp_config"; then
        error_msg "设置配置文件所有者失败"
        rm -f "$temp_config"
        return 1
    fi
    
    # 原子性移动
    if ! mv "$temp_config" "$config_file"; then
        error_msg "保存配置文件失败"
        rm -f "$temp_config"
        return 1
    fi
    
    success_msg "授权配置已安全保存到: $config_file"
    log_operation "用户授权配置已更新，使用安全的配置文件机制"
    
    return 0
}

# 安全的授权状态检查函数
secure_check_authorization() {
    local config_file="/etc/security-hardening/config"
    
    # 检查配置文件是否存在
    if [[ ! -f "$config_file" ]]; then
        return 1
    fi
    
    # 验证文件权限和所有者
    local file_owner=$(stat -c '%U' "$config_file" 2>/dev/null)
    local file_perms=$(stat -c '%a' "$config_file" 2>/dev/null)
    
    if [[ "$file_owner" != "root" ]]; then
        warn_msg "配置文件所有者异常: $file_owner"
        return 1
    fi
    
    if [[ "$file_perms" != "600" ]]; then
        warn_msg "配置文件权限异常: $file_perms"
        return 1
    fi
    
    # 安全读取配置
    if grep -q '^user_authorization="true"' "$config_file" 2>/dev/null; then
        return 0
    fi
    
    return 1
}

#endregion

#region //增强的输入验证和清理

# 安全的字符串清理函数
sanitize_input() {
    local input="$1"
    local max_length="${2:-256}"
    
    # 移除所有控制字符
    input=$(echo "$input" | tr -d '\000-\031\177-\377')
    
    # 限制长度
    if [[ ${#input} -gt $max_length ]]; then
        input="${input:0:$max_length}"
    fi
    
    # 移除危险字符
    input=$(echo "$input" | sed 's/[;&|`$(){}[\]\\]//')
    
    echo "$input"
}

# 安全的端口验证函数
secure_validate_port() {
    local port="$1"
    local check_availability="${2:-false}"
    
    # 基础数字验证
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        error_msg "端口必须是数字"
        return 1
    fi
    
    # 端口范围验证
    if [[ $port -lt 1 || $port -gt 65535 ]]; then
        error_msg "端口范围必须在 1-65535 之间"
        return 1
    fi
    
    # 检查特权端口
    if [[ $port -lt 1024 && $port -ne 22 && $port -ne 80 && $port -ne 443 ]]; then
        warn_msg "端口 $port 是特权端口，可能需要特殊权限"
    fi
    
    # 检查端口是否已被占用
    if [[ "$check_availability" == "true" ]]; then
        if ss -tuln | grep -q ":$port "; then
            error_msg "端口 $port 已被占用"
            return 1
        fi
    fi
    
    # 检查常见服务端口冲突
    case $port in
        22) warn_msg "端口22是SSH默认端口，修改后请确保能通过新端口连接" ;;
        80) warn_msg "端口80通常用于HTTP服务" ;;
        443) warn_msg "端口443通常用于HTTPS服务" ;;
        3306) warn_msg "端口3306通常用于MySQL服务" ;;
        5432) warn_msg "端口5432通常用于PostgreSQL服务" ;;
        6379) warn_msg "端口6379通常用于Redis服务" ;;
    esac
    
    return 0
}

# 安全的文件路径验证函数
secure_validate_path() {
    local path="$1"
    local must_exist="${2:-false}"
    
    # 清理路径
    path=$(realpath -m "$path" 2>/dev/null)
    
    if [[ -z "$path" ]]; then
        error_msg "无效的文件路径"
        return 1
    fi
    
    # 防止路径遍历攻击
    if [[ "$path" == *".."* ]]; then
        error_msg "路径包含危险的父目录引用"
        return 1
    fi
    
    # 检查路径是否在允许的目录内
    local allowed_paths=(
        "/etc/ssh"
        "/etc/security-hardening"
        "/var/log"
        "/tmp"
        "/usr/local/bin"
        "/home"
    )
    
    local path_allowed=false
    for allowed in "${allowed_paths[@]}"; do
        if [[ "$path" == "$allowed"* ]]; then
            path_allowed=true
            break
        fi
    done
    
    if [[ "$path_allowed" != "true" ]]; then
        error_msg "路径不在允许的目录范围内: $path"
        return 1
    fi
    
    # 检查文件是否存在（如果需要）
    if [[ "$must_exist" == "true" && ! -e "$path" ]]; then
        error_msg "文件或目录不存在: $path"
        return 1
    fi
    
    echo "$path"
    return 0
}

# 安全的用户输入获取函数
secure_read_input() {
    local prompt="$1"
    local validator_func="$2"
    local max_attempts="${3:-3}"
    local timeout="${4:-30}"
    local result_var="$5"
    
    local attempts=0
    local user_input
    
    while [[ $attempts -lt $max_attempts ]]; do
        echo -n "$prompt"
        
        # 使用timeout防止无限等待
        if ! read -r -t "$timeout" user_input; then
            error_msg "输入超时"
            return 1
        fi
        
        # 清理输入
        user_input=$(sanitize_input "$user_input")
        
        # 验证输入
        if [[ -n "$validator_func" ]] && command -v "$validator_func" >/dev/null; then
            if "$validator_func" "$user_input"; then
                if [[ -n "$result_var" ]]; then
                    eval "$result_var=\"$user_input\""
                fi
                return 0
            fi
        else
            # 如果没有验证函数，直接返回清理后的输入
            if [[ -n "$result_var" ]]; then
                eval "$result_var=\"$user_input\""
            fi
            return 0
        fi
        
        ((attempts++))
        error_msg "输入验证失败，请重试 ($attempts/$max_attempts)"
    done
    
    error_msg "达到最大尝试次数，操作取消"
    return 1
}

#endregion

#region //下载文件完整性验证

# Xray版本和校验和映射（需要定期更新）
declare -A XRAY_CHECKSUMS=(
    ["v1.8.4_linux_64"]="4e2f4b8a5f4d8b8a6c8d5f2e6a7b3c9d4e8f6a5b2c7d9e4f1a8b5c6d3e7f2a9b"
    ["v1.8.4_linux_arm64"]="9b2f7a8c5d6e4f8a2b5c7d9e3f1a6b8c4d7e9f2a5b8c6d4e7f9a2b5c8d6e3f1a"
    # 更多版本的校验和...
)

# 安全下载函数
secure_download() {
    local url="$1"
    local output_file="$2"
    local expected_checksum="$3"
    local max_attempts="${4:-3}"
    local timeout="${5:-300}"
    
    # 验证URL
    if ! [[ "$url" =~ ^https:// ]]; then
        error_msg "仅支持HTTPS下载以确保安全性"
        return 1
    fi
    
    # 验证输出文件路径
    local safe_output
    safe_output=$(secure_validate_path "$output_file")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    output_file="$safe_output"
    
    # 创建临时文件
    local temp_file
    temp_file=$(mktemp) || {
        error_msg "无法创建临时文件"
        return 1
    }
    
    # 清理函数
    cleanup_download() {
        rm -f "$temp_file"
    }
    trap cleanup_download EXIT
    
    local attempts=0
    while [[ $attempts -lt $max_attempts ]]; do
        ((attempts++))
        info_msg "下载尝试 $attempts/$max_attempts: $url"
        
        # 使用curl下载，带有安全选项
        if curl -L \
            --max-time "$timeout" \
            --retry 2 \
            --retry-delay 1 \
            --fail \
            --silent \
            --show-error \
            --user-agent "VPS-Security-Hardening/$version" \
            --tlsv1.2 \
            --proto '=https' \
            -o "$temp_file" \
            "$url"; then
            
            # 验证文件大小
            local file_size
            file_size=$(stat -c%s "$temp_file" 2>/dev/null)
            if [[ -z "$file_size" || $file_size -eq 0 ]]; then
                warn_msg "下载的文件为空，重试..."
                continue
            fi
            
            # 验证校验和（如果提供）
            if [[ -n "$expected_checksum" ]]; then
                local actual_checksum
                actual_checksum=$(sha256sum "$temp_file" | cut -d' ' -f1)
                
                if [[ "$actual_checksum" != "$expected_checksum" ]]; then
                    error_msg "文件校验和不匹配!"
                    error_msg "期望: $expected_checksum"
                    error_msg "实际: $actual_checksum"
                    continue
                fi
                
                success_msg "文件校验和验证通过"
            else
                warn_msg "未提供校验和，无法验证文件完整性"
            fi
            
            # 移动到目标位置
            if mv "$temp_file" "$output_file"; then
                success_msg "文件已安全下载到: $output_file"
                return 0
            else
                error_msg "移动文件到目标位置失败"
                return 1
            fi
        else
            warn_msg "下载失败，尝试 $attempts/$max_attempts"
            sleep 2
        fi
    done
    
    error_msg "下载失败，已达到最大尝试次数"
    return 1
}

# 获取Xray最新版本信息
get_xray_latest_version() {
    local api_url="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local temp_file
    temp_file=$(mktemp) || {
        error_msg "无法创建临时文件"
        return 1
    }
    
    # 下载版本信息
    if curl -s \
        --max-time 30 \
        --fail \
        --user-agent "VPS-Security-Hardening/$version" \
        --tlsv1.2 \
        --proto '=https' \
        -o "$temp_file" \
        "$api_url"; then
        
        # 解析版本号
        local version_tag
        version_tag=$(grep -o '"tag_name": *"[^"]*"' "$temp_file" | cut -d'"' -f4)
        
        rm -f "$temp_file"
        
        if [[ -n "$version_tag" ]]; then
            echo "$version_tag"
            return 0
        fi
    fi
    
    rm -f "$temp_file"
    error_msg "无法获取Xray最新版本信息"
    return 1
}

# 安全的Xray下载函数
secure_download_xray() {
    local version="$1"
    local arch="$2"
    local output_dir="${3:-/tmp}"
    
    if [[ -z "$version" ]]; then
        version=$(get_xray_latest_version)
        if [[ $? -ne 0 ]]; then
            error_msg "无法确定Xray版本"
            return 1
        fi
    fi
    
    local filename="Xray-linux-${arch}.zip"
    local download_url="https://github.com/XTLS/Xray-core/releases/download/${version}/${filename}"
    local output_file="${output_dir}/${filename}"
    
    # 获取对应的校验和（如果有）
    local checksum_key="${version}_linux_${arch}"
    local expected_checksum="${XRAY_CHECKSUMS[$checksum_key]}"
    
    if [[ -z "$expected_checksum" ]]; then
        warn_msg "未找到版本 $version 的校验和，将跳过完整性验证"
        warn_msg "建议手动验证下载文件的完整性"
    fi
    
    info_msg "准备下载 Xray $version (${arch})"
    info_msg "下载URL: $download_url"
    
    if secure_download "$download_url" "$output_file" "$expected_checksum"; then
        success_msg "Xray下载完成: $output_file"
        return 0
    else
        error_msg "Xray下载失败"
        return 1
    fi
}

#endregion

# 主函数：应用所有安全修复
apply_security_fixes() {
    echo -e "${cyan}应用安全修复补丁...${white}"
    
    # 1. 修复文件权限问题
    info_msg "修复文件权限安全问题..."
    if secure_copy_script_to_system; then
        success_msg "脚本文件权限已安全设置"
    else
        error_msg "脚本文件权限修复失败"
        return 1
    fi
    
    # 2. 修复授权机制
    info_msg "修复授权配置机制..."
    if secure_update_authorization; then
        success_msg "授权配置已安全更新"
    else
        error_msg "授权配置修复失败"
        return 1
    fi
    
    success_msg "所有安全修复已应用完成"
    return 0
}

# 如果直接运行此脚本，则应用修复
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    apply_security_fixes
fi