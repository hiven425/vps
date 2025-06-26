#!/bin/bash

# SSH端口检测测试脚本

echo "=== SSH端口检测测试 ==="
echo

# 获取当前SSH端口函数
get_ssh_port() {
    local ssh_port=""
    
    echo "正在尝试检测SSH端口..."
    
    # 方法1: 从sshd_config文件获取
    echo "方法1: 检查sshd_config文件"
    ssh_port=$(grep -E "^Port\s+|^#?Port\s+" /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}' | head -1 2>/dev/null)
    if [[ -n "$ssh_port" ]]; then
        echo "  找到端口: $ssh_port"
    else
        echo "  未找到端口配置"
    fi
    
    # 方法2: 从当前SSH连接获取
    if [[ -z "$ssh_port" ]]; then
        echo "方法2: 检查当前SSH连接"
        ssh_port=$(ss -tlnp | grep sshd | awk -F: '{print $2}' | awk '{print $1}' | head -1 2>/dev/null)
        if [[ -n "$ssh_port" ]]; then
            echo "  找到端口: $ssh_port"
        else
            echo "  未找到SSH连接"
        fi
    fi
    
    # 方法3: 从环境变量获取
    if [[ -z "$ssh_port" ]] && [[ -n "$SSH_CONNECTION" ]]; then
        echo "方法3: 检查环境变量"
        ssh_port=$(echo $SSH_CONNECTION | awk '{print $4}')
        if [[ -n "$ssh_port" ]]; then
            echo "  找到端口: $ssh_port"
        else
            echo "  环境变量中未找到端口"
        fi
    fi
    
    # 方法4: 从netstat获取
    if [[ -z "$ssh_port" ]]; then
        echo "方法4: 检查netstat"
        ssh_port=$(netstat -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
        if [[ -n "$ssh_port" ]]; then
            echo "  找到端口: $ssh_port"
        else
            echo "  netstat中未找到SSH端口"
        fi
    fi
    
    # 验证端口有效性
    if [[ -n "$ssh_port" ]] && [[ "$ssh_port" =~ ^[0-9]+$ ]] && [[ "$ssh_port" -ge 1 ]] && [[ "$ssh_port" -le 65535 ]]; then
        echo "端口验证: 有效"
        echo "$ssh_port"
    else
        echo "端口验证: 无效，使用默认端口22"
        echo "22"
    fi
}

# 显示当前SSH相关信息
echo "当前SSH相关信息:"
echo "1. SSH_CONNECTION: $SSH_CONNECTION"
echo "2. 当前用户: $(whoami)"
echo "3. 当前TTY: $(tty)"
echo

# 显示sshd_config中的端口配置
echo "sshd_config中的端口配置:"
grep -n "Port" /etc/ssh/sshd_config || echo "未找到Port配置"
echo

# 显示当前监听的SSH端口
echo "当前监听的SSH端口:"
ss -tlnp | grep sshd || echo "未找到SSH监听端口"
echo

# 显示netstat结果
echo "netstat中的SSH端口:"
netstat -tlnp 2>/dev/null | grep sshd || echo "未找到SSH端口"
echo

# 测试端口检测函数
echo "=== 端口检测结果 ==="
detected_port=$(get_ssh_port)
echo
echo "最终检测到的SSH端口: $detected_port"

# 验证结果
if [[ "$detected_port" == "22" ]]; then
    echo "状态: 使用默认端口"
else
    echo "状态: 检测到自定义端口"
fi

echo
echo "=== 测试完成 ==="
