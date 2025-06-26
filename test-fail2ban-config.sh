#!/bin/bash

# fail2ban 配置测试脚本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# 获取SSH端口
get_ssh_port() {
    local ssh_port=""
    
    # 方法1: 从sshd_config文件获取
    ssh_port=$(grep -E "^Port\s+|^#?Port\s+" /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -1 2>/dev/null)
    
    # 方法2: 从当前SSH连接获取
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(ss -tlnp | grep sshd | awk -F: '{print $2}' | awk '{print $1}' | head -1 2>/dev/null)
    fi
    
    # 方法3: 从环境变量获取
    if [[ -z "$ssh_port" ]] && [[ -n "$SSH_CONNECTION" ]]; then
        ssh_port=$(echo $SSH_CONNECTION | awk '{print $4}')
    fi
    
    # 验证端口有效性
    if [[ -n "$ssh_port" ]] && [[ "$ssh_port" =~ ^[0-9]+$ ]] && [[ "$ssh_port" -ge 1 ]] && [[ "$ssh_port" -le 65535 ]]; then
        echo "$ssh_port"
    else
        echo "22"
    fi
}

print_message "$BLUE" "=== fail2ban 配置测试 ==="
echo

# 检查fail2ban是否安装
if ! command -v fail2ban-client &> /dev/null; then
    print_message "$RED" "fail2ban 未安装"
    exit 1
fi

print_message "$GREEN" "✓ fail2ban 已安装"

# 获取SSH端口
ssh_port=$(get_ssh_port)
print_message "$YELLOW" "检测到SSH端口: $ssh_port"

# 备份现有配置
if [[ -f "/etc/fail2ban/jail.local" ]]; then
    print_message "$YELLOW" "备份现有配置..."
    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.backup.$(date +%s)
fi

# 测试不同级别的配置
echo
print_message "$BLUE" "测试配置级别 1: 最简配置"
cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $ssh_port
EOF

if fail2ban-client -t &>/dev/null; then
    print_message "$GREEN" "✓ 最简配置验证成功"
    level1_ok=true
else
    print_message "$RED" "✗ 最简配置验证失败"
    fail2ban-client -t 2>&1 | head -3
    level1_ok=false
fi

echo
print_message "$BLUE" "测试配置级别 2: 基本配置"
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
EOF

if fail2ban-client -t &>/dev/null; then
    print_message "$GREEN" "✓ 基本配置验证成功"
    level2_ok=true
else
    print_message "$RED" "✗ 基本配置验证失败"
    fail2ban-client -t 2>&1 | head -3
    level2_ok=false
fi

echo
print_message "$BLUE" "测试配置级别 3: 完整配置"
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[ufw-block]
enabled = false
filter = ufw-block
logpath = /var/log/syslog
maxretry = 5
findtime = 600
bantime = 86400
action = ufw
EOF

if fail2ban-client -t &>/dev/null; then
    print_message "$GREEN" "✓ 完整配置验证成功"
    level3_ok=true
else
    print_message "$RED" "✗ 完整配置验证失败"
    fail2ban-client -t 2>&1 | head -5
    level3_ok=false
fi

# 检查过滤器和动作文件
echo
print_message "$BLUE" "检查过滤器和动作文件"

# 检查sshd过滤器
if [[ -f "/etc/fail2ban/filter.d/sshd.conf" ]]; then
    print_message "$GREEN" "✓ sshd 过滤器存在"
else
    print_message "$RED" "✗ sshd 过滤器不存在"
fi

# 检查ufw-block过滤器
if [[ -f "/etc/fail2ban/filter.d/ufw-block.conf" ]]; then
    print_message "$GREEN" "✓ ufw-block 过滤器存在"
else
    print_message "$YELLOW" "⚠ ufw-block 过滤器不存在，创建中..."
    cat > /etc/fail2ban/filter.d/ufw-block.conf << 'EOF'
[Definition]
failregex = ^.*\[UFW BLOCK\].*SRC=<HOST>.*$
ignoreregex =
EOF
    print_message "$GREEN" "✓ ufw-block 过滤器已创建"
fi

# 检查ufw动作
if [[ -f "/etc/fail2ban/action.d/ufw.conf" ]]; then
    print_message "$GREEN" "✓ ufw 动作存在"
else
    print_message "$YELLOW" "⚠ ufw 动作不存在，创建中..."
    cat > /etc/fail2ban/action.d/ufw.conf << 'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = ufw insert 1 deny from <ip> to any
actionunban = ufw delete deny from <ip> to any
EOF
    print_message "$GREEN" "✓ ufw 动作已创建"
fi

# 总结
echo
print_message "$BLUE" "=== 测试总结 ==="
echo "最简配置: $(if [[ "$level1_ok" == true ]]; then echo "✓ 成功"; else echo "✗ 失败"; fi)"
echo "基本配置: $(if [[ "$level2_ok" == true ]]; then echo "✓ 成功"; else echo "✗ 失败"; fi)"
echo "完整配置: $(if [[ "$level3_ok" == true ]]; then echo "✓ 成功"; else echo "✗ 失败"; fi)"

# 推荐配置
echo
if [[ "$level3_ok" == true ]]; then
    print_message "$GREEN" "推荐使用完整配置"
elif [[ "$level2_ok" == true ]]; then
    print_message "$YELLOW" "推荐使用基本配置"
elif [[ "$level1_ok" == true ]]; then
    print_message "$YELLOW" "推荐使用最简配置"
else
    print_message "$RED" "所有配置都失败，需要检查fail2ban安装"
fi

echo
print_message "$BLUE" "测试完成"
