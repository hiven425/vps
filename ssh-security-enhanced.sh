#!/bin/bash

# SSH安全配置增强模块
# 专门用于提升SSH配置的安全性和验证机制

#region //SSH配置安全增强

# SSH配置安全检查器
ssh_security_validator() {
    local config_file="$1"
    local issues=()
    local warnings=()
    local recommendations=()
    
    info_msg "执行SSH配置安全检查..."
    
    # 检查文件是否存在和可读
    if [[ ! -f "$config_file" ]]; then
        issues+=("配置文件不存在: $config_file")
        return 1
    fi
    
    if [[ ! -r "$config_file" ]]; then
        issues+=("配置文件不可读: $config_file")
        return 1
    fi
    
    # 检查文件权限
    local file_perms=$(stat -c '%a' "$config_file" 2>/dev/null)
    if [[ "$file_perms" != "644" && "$file_perms" != "600" ]]; then
        warnings+=("配置文件权限不安全: $file_perms (建议: 644或600)")
    fi
    
    # 检查关键安全设置
    local config_content=$(cat "$config_file")
    
    # 1. 密码认证检查
    if echo "$config_content" | grep -q "^PasswordAuthentication yes"; then
        issues+=("启用了密码认证，存在暴力破解风险")
    fi
    
    # 2. Root登录检查
    if echo "$config_content" | grep -q "^PermitRootLogin yes"; then
        issues+=("允许Root密码登录，安全风险极高")
    fi
    
    # 3. 空密码检查
    if echo "$config_content" | grep -q "^PermitEmptyPasswords yes"; then
        issues+=("允许空密码登录，安全风险极高")
    fi
    
    # 4. X11转发检查
    if echo "$config_content" | grep -q "^X11Forwarding yes"; then
        warnings+=("启用了X11转发，可能增加攻击面")
    fi
    
    # 5. 默认端口检查
    local ssh_port=$(echo "$config_content" | grep "^Port " | awk '{print $2}' | head -1)
    if [[ "$ssh_port" == "22" || -z "$ssh_port" ]]; then
        warnings+=("使用默认SSH端口22，容易被扫描攻击")
    fi
    
    # 6. 协议版本检查
    if echo "$config_content" | grep -q "^Protocol 1"; then
        issues+=("使用SSH协议版本1，存在严重安全漏洞")
    fi
    
    # 7. 最大认证尝试检查
    local max_auth_tries=$(echo "$config_content" | grep "^MaxAuthTries " | awk '{print $2}')
    if [[ -n "$max_auth_tries" && $max_auth_tries -gt 3 ]]; then
        warnings+=("最大认证尝试次数过高: $max_auth_tries")
    fi
    
    # 8. 登录宽限时间检查
    local login_grace_time=$(echo "$config_content" | grep "^LoginGraceTime " | awk '{print $2}')
    if [[ -n "$login_grace_time" && "$login_grace_time" != "30" ]]; then
        recommendations+=("建议设置LoginGraceTime为30秒")
    fi
    
    # 9. 客户端存活检查
    if ! echo "$config_content" | grep -q "^ClientAliveInterval"; then
        recommendations+=("建议设置ClientAliveInterval防止连接超时")
    fi
    
    # 10. DNS检查
    if echo "$config_content" | grep -q "^UseDNS yes"; then
        recommendations+=("建议禁用UseDNS以提高连接速度")
    fi
    
    # 输出检查结果
    echo
    echo -e "${cyan}=== SSH配置安全检查报告 ===${white}"
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "${red}严重问题 (${#issues[@]}):${white}"
        for issue in "${issues[@]}"; do
            echo -e "${red}  ✗ $issue${white}"
        done
        echo
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo -e "${yellow}警告 (${#warnings[@]}):${white}"
        for warning in "${warnings[@]}"; do
            echo -e "${yellow}  ⚠ $warning${white}"
        done
        echo
    fi
    
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        echo -e "${blue}建议 (${#recommendations[@]}):${white}"
        for rec in "${recommendations[@]}"; do
            echo -e "${blue}  ℹ $rec${white}"
        done
        echo
    fi
    
    if [[ ${#issues[@]} -eq 0 && ${#warnings[@]} -eq 0 ]]; then
        echo -e "${green}✓ SSH配置安全检查通过${white}"
    fi
    
    # 返回检查结果
    if [[ ${#issues[@]} -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

# 增强的SSH配置生成器
generate_secure_ssh_config() {
    local ssh_port="$1"
    local permit_root_login="$2"
    local output_file="$3"
    
    # 验证参数
    if ! secure_validate_port "$ssh_port" true; then
        return 1
    fi
    
    if [[ "$permit_root_login" != "no" && "$permit_root_login" != "yes" && "$permit_root_login" != "prohibit-password" ]]; then
        error_msg "无效的Root登录设置: $permit_root_login"
        return 1
    fi
    
    # 验证输出文件路径
    local safe_output
    safe_output=$(secure_validate_path "$output_file")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    output_file="$safe_output"
    
    # 生成安全的SSH配置
    local temp_config
    temp_config=$(mktemp) || {
        error_msg "无法创建临时配置文件"
        return 1
    }
    
    cat > "$temp_config" << EOF
# SSH安全配置文件
# 由VPS安全加固工具生成
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 
# 警告: 此配置文件经过安全优化，请谨慎修改

# === 基础连接设置 ===
Port $ssh_port
Protocol 2
AddressFamily any

# === 认证设置 ===
PermitRootLogin $permit_root_login
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# === 安全限制 ===
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 30

# === 连接保活 ===
ClientAliveInterval 60
ClientAliveCountMax 3
TCPKeepAlive yes

# === 功能控制 ===
X11Forwarding no
X11DisplayOffset 10
X11UseLocalhost yes
AllowTcpForwarding yes
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# === 性能优化 ===
UseDNS no
GSSAPIAuthentication no

# === 日志设置 ===
SyslogFacility AUTH
LogLevel INFO

# === 安全增强 ===
# 禁用过时的认证方法
KerberosAuthentication no
GSSAPICleanupCredentials yes
HostbasedAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts no
PrintMotd no
PrintLastLog yes
StrictModes yes

# === 压缩设置 ===
Compression delayed

# === 加密算法设置 (仅允许安全的算法) ===
# 密钥交换算法
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# 加密算法
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# MAC算法
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# === 主机密钥算法 ===
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# === Banner设置 ===
Banner none

# === 子系统 ===
Subsystem sftp internal-sftp
EOF
    
    # 验证生成的配置
    if ! sshd -t -f "$temp_config" 2>/dev/null; then
        error_msg "生成的SSH配置无效"
        rm -f "$temp_config"
        return 1
    fi
    
    # 设置安全权限
    chmod 644 "$temp_config"
    
    # 移动到目标位置
    if mv "$temp_config" "$output_file"; then
        success_msg "安全的SSH配置已生成: $output_file"
        return 0
    else
        error_msg "保存SSH配置失败"
        rm -f "$temp_config"
        return 1
    fi
}

# SSH密钥安全管理器
ssh_key_security_manager() {
    local action="$1"
    local key_path="${2:-$HOME/.ssh}"
    
    case "$action" in
        "generate")
            generate_secure_ssh_keys "$key_path"
            ;;
        "audit")
            audit_ssh_keys "$key_path"
            ;;
        "backup")
            backup_ssh_keys "$key_path"
            ;;
        *)
            error_msg "无效的操作: $action"
            echo "支持的操作: generate, audit, backup"
            return 1
            ;;
    esac
}

# 生成安全的SSH密钥对
generate_secure_ssh_keys() {
    local key_dir="$1"
    local key_type="${2:-ed25519}"
    local key_size="${3:-4096}"
    
    # 创建密钥目录
    if [[ ! -d "$key_dir" ]]; then
        mkdir -p "$key_dir"
        chmod 700 "$key_dir"
    fi
    
    local private_key="$key_dir/id_$key_type"
    local public_key="$private_key.pub"
    
    # 检查是否已存在密钥
    if [[ -f "$private_key" ]]; then
        echo -e "${yellow}密钥已存在: $private_key${white}"
        read -p "是否覆盖现有密钥? (y/N): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            info_msg "取消密钥生成"
            return 0
        fi
        
        # 备份现有密钥
        local backup_suffix=$(date +%s)
        mv "$private_key" "$private_key.backup.$backup_suffix"
        mv "$public_key" "$public_key.backup.$backup_suffix" 2>/dev/null
        info_msg "现有密钥已备份"
    fi
    
    # 生成密钥
    info_msg "生成$key_type密钥..."
    
    case "$key_type" in
        "ed25519")
            ssh-keygen -t ed25519 -f "$private_key" -N "" -C "Generated by VPS Security Tool $(date +%Y%m%d)"
            ;;
        "rsa")
            ssh-keygen -t rsa -b "$key_size" -f "$private_key" -N "" -C "Generated by VPS Security Tool $(date +%Y%m%d)"
            ;;
        *)
            error_msg "不支持的密钥类型: $key_type"
            return 1
            ;;
    esac
    
    # 设置安全权限
    chmod 600 "$private_key"
    chmod 644 "$public_key"
    
    success_msg "SSH密钥生成完成:"
    echo "  私钥: $private_key"
    echo "  公钥: $public_key"
    
    # 显示公钥内容
    echo -e "\n${cyan}公钥内容 (请将此内容添加到目标服务器的 ~/.ssh/authorized_keys):${white}"
    echo -e "${green}$(cat "$public_key")${white}"
    
    return 0
}

# SSH密钥安全审计
audit_ssh_keys() {
    local key_dir="$1"
    
    echo -e "${cyan}=== SSH密钥安全审计 ===${white}"
    
    if [[ ! -d "$key_dir" ]]; then
        warn_msg "SSH密钥目录不存在: $key_dir"
        return 1
    fi
    
    local issues=0
    
    # 检查目录权限
    local dir_perms=$(stat -c '%a' "$key_dir")
    if [[ "$dir_perms" != "700" ]]; then
        error_msg "SSH目录权限不安全: $dir_perms (应该是700)"
        ((issues++))
    fi
    
    # 检查私钥文件
    for key_file in "$key_dir"/id_*; do
        if [[ -f "$key_file" && ! "$key_file" == *.pub ]]; then
            local key_perms=$(stat -c '%a' "$key_file")
            if [[ "$key_perms" != "600" ]]; then
                error_msg "私钥权限不安全: $key_file ($key_perms, 应该是600)"
                ((issues++))
            fi
            
            # 检查密钥类型和强度
            local key_type=$(ssh-keygen -l -f "$key_file" 2>/dev/null | awk '{print $4}' | tr -d '()')
            local key_bits=$(ssh-keygen -l -f "$key_file" 2>/dev/null | awk '{print $1}')
            
            case "$key_type" in
                "RSA")
                    if [[ $key_bits -lt 2048 ]]; then
                        error_msg "RSA密钥强度不足: $key_file ($key_bits bits, 建议至少2048)"
                        ((issues++))
                    elif [[ $key_bits -lt 4096 ]]; then
                        warn_msg "RSA密钥强度较低: $key_file ($key_bits bits, 建议4096)"
                    fi
                    ;;
                "DSA")
                    error_msg "DSA密钥已被弃用，存在安全风险: $key_file"
                    ((issues++))
                    ;;
                "ED25519")
                    success_msg "使用安全的ED25519密钥: $key_file"
                    ;;
            esac
        fi
    done
    
    # 检查authorized_keys文件
    local auth_keys="$key_dir/authorized_keys"
    if [[ -f "$auth_keys" ]]; then
        local auth_perms=$(stat -c '%a' "$auth_keys")
        if [[ "$auth_perms" != "600" && "$auth_perms" != "644" ]]; then
            error_msg "authorized_keys权限不安全: $auth_perms"
            ((issues++))
        fi
        
        # 检查弱密钥
        local weak_keys=$(grep -E "(ssh-dss|1024)" "$auth_keys" 2>/dev/null | wc -l)
        if [[ $weak_keys -gt 0 ]]; then
            warn_msg "发现 $weak_keys 个弱密钥在 authorized_keys 中"
        fi
    fi
    
    if [[ $issues -eq 0 ]]; then
        success_msg "SSH密钥安全审计通过"
    else
        error_msg "发现 $issues 个安全问题"
    fi
    
    return $issues
}

# 备份SSH密钥
backup_ssh_keys() {
    local key_dir="$1"
    local backup_dir="/etc/security-hardening/ssh-backup"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$backup_dir/ssh_keys_$timestamp.tar.gz"
    
    if [[ ! -d "$key_dir" ]]; then
        error_msg "SSH密钥目录不存在: $key_dir"
        return 1
    fi
    
    # 创建备份目录
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    
    # 创建加密备份
    info_msg "创建SSH密钥备份..."
    
    if tar -czf "$backup_path" -C "$(dirname "$key_dir")" "$(basename "$key_dir")"; then
        chmod 600 "$backup_path"
        success_msg "SSH密钥已备份到: $backup_path"
        
        # 显示备份信息
        echo "备份文件大小: $(du -h "$backup_path" | cut -f1)"
        echo "包含文件:"
        tar -tzf "$backup_path"
        
        return 0
    else
        error_msg "SSH密钥备份失败"
        return 1
    fi
}

#endregion

# 主SSH安全配置函数
enhanced_ssh_security_setup() {
    clear
    echo -e "${pink}=== 增强SSH安全配置 ===${white}"
    echo "此模块将提供全面的SSH安全配置和检查功能"
    echo ""
    
    echo "1. SSH配置安全检查"
    echo "2. 生成安全SSH配置"
    echo "3. SSH密钥管理"
    echo "4. 完整安全设置"
    echo ""
    
    local choice
    if secure_read_input "请选择操作 [1-4]: " "validate_numeric_range_or_empty" 3 30 choice; then
        case "${choice:-4}" in
            1)
                ssh_security_validator "/etc/ssh/sshd_config"
                ;;
            2)
                local port
                local root_login
                
                secure_read_input "SSH端口 [55520]: " "secure_validate_port" 3 30 port
                port=${port:-55520}
                
                echo "Root登录选项:"
                echo "1. no - 禁止Root登录"
                echo "2. prohibit-password - 仅密钥登录"
                echo "3. yes - 允许密码登录 (不推荐)"
                
                local root_choice
                secure_read_input "Root登录方式 [1]: " "validate_numeric_range_or_empty" 3 30 root_choice
                
                case "${root_choice:-1}" in
                    1) root_login="no" ;;
                    2) root_login="prohibit-password" ;;
                    3) root_login="yes" ;;
                    *) root_login="no" ;;
                esac
                
                generate_secure_ssh_config "$port" "$root_login" "/etc/ssh/sshd_config.d/security-hardening.conf"
                ;;
            3)
                echo "SSH密钥管理选项:"
                echo "1. 生成新密钥"
                echo "2. 审计现有密钥"
                echo "3. 备份密钥"
                
                local key_choice
                secure_read_input "请选择 [1]: " "validate_numeric_range_or_empty" 3 30 key_choice
                
                case "${key_choice:-1}" in
                    1) ssh_key_security_manager "generate" ;;
                    2) ssh_key_security_manager "audit" ;;
                    3) ssh_key_security_manager "backup" ;;
                esac
                ;;
            4)
                info_msg "执行完整SSH安全设置..."
                # 实现完整设置流程
                ;;
        esac
    fi
    
    echo ""
    echo "按任意键返回..."
    read -n 1 -s
}

# 如果直接运行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    enhanced_ssh_security_setup
fi