#!/bin/bash

# SSH服务安装修复脚本

echo "=== SSH服务安装修复 ==="
echo "检测时间: $(date)"
echo ""

# 颜色定义
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[1;33m'
cyan='\033[0;36m'
white='\033[0m'

# 消息函数
info_msg() {
    echo -e "${cyan}ℹ $1${white}"
}

success_msg() {
    echo -e "${green}✓ $1${white}"
}

warn_msg() {
    echo -e "${yellow}⚠ $1${white}"
}

error_msg() {
    echo -e "${red}✗ $1${white}"
}

# 检查root权限
if [[ $EUID -ne 0 ]]; then
    error_msg "此脚本需要root权限运行"
    echo "请使用: sudo bash $0"
    exit 1
fi

# 检查sshd命令
echo -e "${cyan}1. 检查SSH服务状态${white}"
if command -v sshd >/dev/null 2>&1; then
    success_msg "sshd命令已存在"
    
    # 检查服务状态
    if systemctl is-active sshd >/dev/null 2>&1; then
        success_msg "SSH服务正在运行"
    elif systemctl is-active ssh >/dev/null 2>&1; then
        success_msg "SSH服务正在运行 (ssh)"
    else
        warn_msg "SSH服务未运行"
    fi
else
    warn_msg "sshd命令不存在，需要安装SSH服务"
    
    # 检测包管理器
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
    else
        error_msg "不支持的包管理器"
        exit 1
    fi
    
    echo ""
    echo -e "${cyan}2. 安装SSH服务${white}"
    info_msg "使用包管理器: $PKG_MANAGER"
    
    case $PKG_MANAGER in
        apt)
            info_msg "更新软件包列表..."
            apt-get update -y >/dev/null 2>&1
            info_msg "安装openssh-server..."
            if apt-get install -y openssh-server >/dev/null 2>&1; then
                success_msg "openssh-server安装成功"
            else
                error_msg "openssh-server安装失败"
                exit 1
            fi
            ;;
        yum)
            info_msg "安装openssh-server..."
            if yum install -y openssh-server >/dev/null 2>&1; then
                success_msg "openssh-server安装成功"
            else
                error_msg "openssh-server安装失败"
                exit 1
            fi
            ;;
        dnf)
            info_msg "安装openssh-server..."
            if dnf install -y openssh-server >/dev/null 2>&1; then
                success_msg "openssh-server安装成功"
            else
                error_msg "openssh-server安装失败"
                exit 1
            fi
            ;;
    esac
    
    echo ""
    echo -e "${cyan}3. 启动SSH服务${white}"
    
    # 启用服务
    if systemctl enable sshd >/dev/null 2>&1; then
        success_msg "SSH服务已设置为开机自启"
    elif systemctl enable ssh >/dev/null 2>&1; then
        success_msg "SSH服务已设置为开机自启 (ssh)"
    else
        warn_msg "设置开机自启失败"
    fi
    
    # 启动服务
    if systemctl start sshd >/dev/null 2>&1; then
        success_msg "SSH服务已启动"
    elif systemctl start ssh >/dev/null 2>&1; then
        success_msg "SSH服务已启动 (ssh)"
    else
        warn_msg "SSH服务启动失败"
    fi
fi

echo ""
echo -e "${cyan}4. 验证安装结果${white}"

# 验证sshd命令
if command -v sshd >/dev/null 2>&1; then
    success_msg "sshd命令现在可用"
    
    # 测试配置语法
    if sshd -t >/dev/null 2>&1; then
        success_msg "SSH配置文件语法正确"
    else
        warn_msg "SSH配置文件有语法问题"
        echo "错误详情:"
        sshd -t 2>&1 | sed 's/^/  /'
    fi
    
    # 显示当前端口
    local current_port=$(sshd -T 2>/dev/null | grep -i "^port " | awk '{print $2}' || echo "22")
    info_msg "当前SSH端口: $current_port"
    
else
    error_msg "sshd命令仍不可用"
    exit 1
fi

# 检查服务状态
if systemctl is-active sshd >/dev/null 2>&1; then
    success_msg "SSH服务运行状态: 正常"
elif systemctl is-active ssh >/dev/null 2>&1; then
    success_msg "SSH服务运行状态: 正常 (ssh)"
else
    warn_msg "SSH服务未运行"
fi

echo ""
echo -e "${green}SSH服务修复完成！${white}"
echo ""
echo "现在可以重新运行主脚本:"
echo "bash security-hardening.sh"
