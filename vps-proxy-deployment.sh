#!/bin/bash

# VPS代理部署专用工具
# 版本：3.0.0  
# 专注：VLESS-REALITY代理部署与管理
# 支持协议：VLESS + REALITY

set -euo pipefail

#region //全局配置
version="3.0.0"
script_name="vps-proxy-deployment"

# 颜色定义
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
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

# 配置目录和文件
config_dir="/etc/vps-proxy"
backup_dir="$config_dir/backup"
log_file="/var/log/vps-proxy.log"
xray_config_file="/usr/local/etc/xray/config.json"
xray_service_file="/etc/systemd/system/xray.service"

# 代理配置变量
PROXY_PORT=""
PROXY_UUID=""
PROXY_TARGET=""
PROXY_PRIVATE_KEY=""
PROXY_PUBLIC_KEY=""
PROXY_SHORT_ID=""

# 系统信息
OS=""
OS_VERSION=""
PACKAGE_MANAGER=""
#endregion

#region //基础工具函数
log_operation() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$log_file"
}

error_exit() {
    local message="$1"
    echo -e "${red}✗ 错误: ${message}${white}" >&2
    log_operation "ERROR: $message"
    exit 1
}

success_msg() {
    local message="$1"
    echo -e "${green}✓ ${message}${white}"
    log_operation "SUCCESS: $message"
}

warn_msg() {
    local message="$1"
    echo -e "${yellow}⚠ ${message}${white}"
    log_operation "WARNING: $message"
}

info_msg() {
    local message="$1"
    echo -e "${blue}ℹ ${message}${white}"
    log_operation "INFO: $message"
}

check_root_permission() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "此脚本需要root权限运行。请使用: sudo $0"
    fi
}

create_directories() {
    local dirs=("$config_dir" "$backup_dir" "$(dirname "$log_file")" "/usr/local/etc/xray" "/var/log/xray")
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chmod 750 "$dir"
        fi
    done
}

detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        error_exit "无法检测系统版本"
    fi
    
    case $OS in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel|fedora)
            PACKAGE_MANAGER="yum"
            if command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        *)
            error_exit "不支持的操作系统: $OS"
            ;;
    esac
    
    info_msg "检测到系统: $OS $OS_VERSION"
}

get_server_ip() {
    local ip
    # 尝试多个服务获取外部IP
    ip=$(curl -s --max-time 10 ipv4.ip.sb 2>/dev/null || \
         curl -s --max-time 10 ifconfig.me 2>/dev/null || \
         curl -s --max-time 10 icanhazip.com 2>/dev/null || \
         curl -s --max-time 10 ipinfo.io/ip 2>/dev/null || \
         echo "127.0.0.1")
    echo "$ip"
}

generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

generate_random_string() {
    local length="${1:-8}"
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

validate_port() {
    local port="$1"
    
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    if [[ $port -lt 1 || $port -gt 65535 ]]; then
        return 1
    fi
    
    if ss -tuln 2>/dev/null | grep -q ":$port "; then
        warn_msg "端口 $port 可能已被占用"
        return 1
    fi
    
    return 0
}

check_port_available() {
    local port="$1"
    if ss -tuln | grep -q ":$port "; then
        return 1
    fi
    return 0
}

find_available_port() {
    local preferred_ports=(443 8443 2053 2096 2087 2083)
    
    # 首先尝试推荐端口
    for port in "${preferred_ports[@]}"; do
        if check_port_available "$port"; then
            echo "$port"
            return 0
        fi
    done
    
    # 如果推荐端口都被占用，随机生成
    for i in {1..10}; do
        local random_port=$((RANDOM % 55535 + 10000))
        if check_port_available "$random_port"; then
            echo "$random_port"
            return 0
        fi
    done
    
    error_exit "无法找到可用端口"
}
#endregion

#region //Xray安装模块
download_xray() {
    info_msg "下载Xray-core..."
    
    # 检测系统架构
    local arch
    case $(uname -m) in
        x86_64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        armv7l) arch="arm32-v7a" ;;
        *) error_exit "不支持的系统架构: $(uname -m)" ;;
    esac
    
    # 获取最新版本
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    
    if [[ -z "$latest_version" ]]; then
        error_exit "无法获取Xray最新版本信息"
    fi
    
    info_msg "最新版本: $latest_version"
    
    # 创建临时目录（改进的方式）
    local temp_dir="/tmp/xray-install-$$"
    mkdir -p "$temp_dir" || error_exit "无法创建临时目录"
    
    # 下载文件
    local download_url="https://github.com/XTLS/Xray-core/releases/download/$latest_version/Xray-linux-$arch.zip"
    local zip_file="$temp_dir/xray.zip"
    
    if ! curl -L -o "$zip_file" "$download_url"; then
        rm -rf "$temp_dir"
        error_exit "下载Xray失败"
    fi
    
    # 检查并安装unzip
    if ! command -v unzip >/dev/null 2>&1; then
        info_msg "安装unzip工具..."
        case $PACKAGE_MANAGER in
            apt)
                apt update -qq && apt install -y unzip
                ;;
            yum|dnf)
                $PACKAGE_MANAGER install -y unzip
                ;;
        esac
    fi
    
    # 解压并安装
    cd "$temp_dir"
    if ! unzip -q "$zip_file"; then
        rm -rf "$temp_dir"
        error_exit "解压Xray失败"
    fi
    
    # 安装到系统
    install -m 755 xray /usr/local/bin/
    install -m 644 geoip.dat /usr/local/share/xray/
    install -m 644 geosite.dat /usr/local/share/xray/
    
    # 创建目录
    mkdir -p /usr/local/share/xray /usr/local/etc/xray /var/log/xray
    
    # 清理临时文件
    rm -rf "$temp_dir"
    
    success_msg "Xray-core 安装完成: $latest_version"
}

create_xray_service() {
    info_msg "创建Xray系统服务..."
    
    cat > "$xray_service_file" << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls/xray-core
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable xray
    
    success_msg "Xray系统服务创建完成"
}

install_xray() {
    clear
    echo -e "${cyan}=== Xray-core 安装 ===${white}"
    echo
    
    # 检查是否已安装
    if command -v xray >/dev/null 2>&1; then
        local current_version=$(xray version | head -1 | awk '{print $2}')
        warn_msg "Xray已安装，当前版本: $current_version"
        echo
        read -p "是否重新安装最新版本？(y/N): " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # 安装依赖
    case $PACKAGE_MANAGER in
        apt)
            apt update -qq && apt install -y curl unzip
            ;;
        yum|dnf)
            $PACKAGE_MANAGER install -y curl unzip
            ;;
    esac
    
    # 下载和安装
    download_xray
    create_xray_service
    
    # 验证安装
    if command -v xray >/dev/null 2>&1; then
        local version=$(xray version | head -1 | awk '{print $2}')
        success_msg "Xray安装验证成功: $version"
    else
        error_exit "Xray安装验证失败"
    fi
}
#endregion

#region //密钥生成模块
generate_reality_keypair() {
    info_msg "生成REALITY密钥对..."
    
    if ! command -v xray >/dev/null 2>&1; then
        error_exit "Xray未安装，请先安装Xray"
    fi
    
    # 生成密钥对
    local keys_output
    keys_output=$(xray x25519)
    
    PROXY_PRIVATE_KEY=$(echo "$keys_output" | grep "Private key:" | awk '{print $3}')
    PROXY_PUBLIC_KEY=$(echo "$keys_output" | grep "Public key:" | awk '{print $3}')
    
    if [[ -z "$PROXY_PRIVATE_KEY" || -z "$PROXY_PUBLIC_KEY" ]]; then
        error_exit "密钥生成失败"
    fi
    
    success_msg "REALITY密钥对生成完成"
}

generate_short_id() {
    # 生成8位随机短ID
    printf "%08x" $((RANDOM * RANDOM))
}

select_target_website() {
    info_msg "选择目标网站..."
    
    # 推荐的目标网站列表
    local targets=(
        "www.microsoft.com:443"
        "www.apple.com:443"
        "www.cloudflare.com:443"
        "www.amazon.com:443"
        "www.google.com:443"
        "github.com:443"
        "gitlab.com:443"
    )
    
    echo
    echo "推荐的目标网站:"
    for i in "${!targets[@]}"; do
        echo "  $((i+1)). ${targets[$i]%:*}"
    done
    echo "  8. 自定义网站"
    echo
    
    local choice
    read -p "请选择目标网站 [1-8, 默认: 1]: " choice
    choice=${choice:-1}
    
    case $choice in
        [1-7])
            PROXY_TARGET="${targets[$((choice-1))]%:*}"
            ;;
        8)
            read -p "请输入自定义目标网站 (如: example.com): " custom_target
            if [[ -n "$custom_target" ]]; then
                PROXY_TARGET="$custom_target"
            else
                PROXY_TARGET="www.microsoft.com"
            fi
            ;;
        *)
            PROXY_TARGET="www.microsoft.com"
            ;;
    esac
    
    # 测试目标网站连通性
    info_msg "测试目标网站连通性: $PROXY_TARGET"
    if curl -s --max-time 10 "https://$PROXY_TARGET" >/dev/null; then
        success_msg "目标网站连通性测试通过"
    else
        warn_msg "目标网站可能无法访问，但仍可继续配置"
    fi
    
    info_msg "选择的目标网站: $PROXY_TARGET"
}
#endregion

#region //配置生成模块
generate_xray_config() {
    local port="$1"
    local uuid="$2"
    local target="$3"
    local private_key="$4"
    local short_id="$5"
    
    info_msg "生成Xray配置文件..."
    
    cat > "$xray_config_file" << EOF
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "$target:443",
                    "xver": 0,
                    "serverNames": ["$target"],
                    "privateKey": "$private_key",
                    "shortIds": ["$short_id"]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "routing": {
        "rules": [
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            },
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF
    
    # 设置文件权限
    chmod 644 "$xray_config_file"
    
    success_msg "Xray配置文件生成完成"
}

save_proxy_config() {
    local config_file="$config_dir/proxy.conf"
    
    cat > "$config_file" << EOF
# VPS代理配置信息
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

PROXY_TYPE="VLESS-REALITY"
PROXY_VERSION="$version"
PROXY_PORT="$PROXY_PORT"
PROXY_UUID="$PROXY_UUID"
PROXY_TARGET="$PROXY_TARGET"
PROXY_PRIVATE_KEY="$PROXY_PRIVATE_KEY"
PROXY_PUBLIC_KEY="$PROXY_PUBLIC_KEY"
PROXY_SHORT_ID="$PROXY_SHORT_ID"
SERVER_IP="$(get_server_ip)"
CREATED_TIME="$(date)"
EOF
    
    chmod 600 "$config_file"
    success_msg "代理配置信息已保存"
}

validate_xray_config() {
    info_msg "验证Xray配置..."
    
    if xray test -config "$xray_config_file" >/dev/null 2>&1; then
        success_msg "Xray配置验证通过"
        return 0
    else
        error_exit "Xray配置验证失败"
    fi
}
#endregion

#region //客户端配置生成
generate_client_configs() {
    info_msg "生成客户端配置..."
    
    local server_ip=$(get_server_ip)
    local client_dir="$config_dir/clients"
    
    mkdir -p "$client_dir"
    
    # 生成VLESS链接
    local vless_link="vless://${PROXY_UUID}@${server_ip}:${PROXY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${PROXY_TARGET}&fp=chrome&pbk=${PROXY_PUBLIC_KEY}&type=tcp&headerType=none#VLESS-REALITY-$(date +%Y%m%d)"
    
    echo "$vless_link" > "$client_dir/vless_link.txt"
    
    # 生成客户端JSON配置
    cat > "$client_dir/client_config.json" << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 10808,
            "protocol": "socks",
            "settings": {
                "udp": true
            }
        },
        {
            "port": 10809,
            "protocol": "http"
        }
    ],
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "$server_ip",
                        "port": $PROXY_PORT,
                        "users": [
                            {
                                "id": "$PROXY_UUID",
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "$PROXY_TARGET",
                    "fingerprint": "chrome",
                    "publicKey": "$PROXY_PUBLIC_KEY",
                    "shortId": "$PROXY_SHORT_ID"
                }
            }
        }
    ]
}
EOF
    
    # 生成Clash配置
    cat > "$client_dir/clash_config.yaml" << EOF
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - name: "VLESS-REALITY"
    type: vless
    server: $server_ip
    port: $PROXY_PORT
    uuid: $PROXY_UUID
    network: tcp
    reality-opts:
      public-key: $PROXY_PUBLIC_KEY
      short-id: $PROXY_SHORT_ID
    client-fingerprint: chrome

proxy-groups:
  - name: "代理选择"
    type: select
    proxies:
      - "VLESS-REALITY"
      - DIRECT

rules:
  - GEOIP,CN,DIRECT
  - MATCH,代理选择
EOF
    
    # 生成二维码
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t png -o "$client_dir/qrcode.png" "$vless_link"
        success_msg "二维码已生成: $client_dir/qrcode.png"
    fi
    
    success_msg "客户端配置生成完成"
    echo
    echo -e "${cyan}客户端配置文件位置:${white}"
    echo "  VLESS链接: $client_dir/vless_link.txt"
    echo "  JSON配置: $client_dir/client_config.json"
    echo "  Clash配置: $client_dir/clash_config.yaml"
    if [[ -f "$client_dir/qrcode.png" ]]; then
        echo "  二维码: $client_dir/qrcode.png"
    fi
}

show_client_info() {
    clear
    echo -e "${cyan}=== 客户端连接信息 ===${white}"
    echo
    
    # 加载配置
    if [[ -f "$config_dir/proxy.conf" ]]; then
        source "$config_dir/proxy.conf"
    else
        error_exit "代理配置文件不存在"
    fi
    
    echo -e "${pink}服务器信息:${white}"
    echo "  地址: $SERVER_IP"
    echo "  端口: $PROXY_PORT"
    echo "  协议: VLESS + REALITY"
    echo "  目标网站: $PROXY_TARGET"
    echo
    
    echo -e "${pink}连接参数:${white}"
    echo "  UUID: $PROXY_UUID"
    echo "  流控: xtls-rprx-vision"
    echo "  加密: none"
    echo "  传输: tcp"
    echo
    
    echo -e "${pink}REALITY参数:${white}"
    echo "  公钥: $PROXY_PUBLIC_KEY"
    echo "  短ID: $PROXY_SHORT_ID"
    echo "  SNI: $PROXY_TARGET"
    echo "  指纹: chrome"
    echo
    
    # 显示VLESS链接
    if [[ -f "$config_dir/clients/vless_link.txt" ]]; then
        echo -e "${pink}VLESS链接:${white}"
        echo -e "${green}$(cat "$config_dir/clients/vless_link.txt")${white}"
        echo
    fi
    
    echo -e "${yellow}客户端推荐:${white}"
    echo "  Android: v2rayNG"
    echo "  iOS: Shadowrocket"
    echo "  Windows: v2rayN"
    echo "  macOS: V2RayXS"
    echo "  Linux: Xray"
}
#endregion

#region //服务管理模块
start_xray_service() {
    info_msg "启动Xray服务..."
    
    if systemctl start xray; then
        sleep 2
        if systemctl is-active xray >/dev/null; then
            success_msg "Xray服务启动成功"
            return 0
        fi
    fi
    
    error_exit "Xray服务启动失败"
}

stop_xray_service() {
    info_msg "停止Xray服务..."
    
    if systemctl stop xray; then
        success_msg "Xray服务已停止"
    else
        warn_msg "停止Xray服务失败"
    fi
}

restart_xray_service() {
    info_msg "重启Xray服务..."
    
    if systemctl restart xray; then
        sleep 2
        if systemctl is-active xray >/dev/null; then
            success_msg "Xray服务重启成功"
            return 0
        fi
    fi
    
    error_exit "Xray服务重启失败"
}

check_service_status() {
    clear
    echo -e "${cyan}=== 服务状态检查 ===${white}"
    echo
    
    # Xray服务状态
    echo -e "${pink}Xray服务状态:${white}"
    if systemctl is-active xray >/dev/null; then
        echo -e "  状态: ${green}运行中${white}"
        echo "  开机启动: $(systemctl is-enabled xray 2>/dev/null || echo '未设置')"
        
        # 检查端口监听
        if [[ -f "$config_dir/proxy.conf" ]]; then
            source "$config_dir/proxy.conf"
            if ss -tuln | grep -q ":$PROXY_PORT "; then
                echo -e "  端口监听: ${green}正常 ($PROXY_PORT)${white}"
            else
                echo -e "  端口监听: ${red}异常${white}"
            fi
        fi
    else
        echo -e "  状态: ${red}未运行${white}"
    fi
    echo
    
    # 系统资源使用
    echo -e "${pink}系统资源:${white}"
    echo "  CPU使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d% -f1)%"
    echo "  内存使用: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
    echo "  网络连接: $(ss -tun | wc -l) 个活动连接"
    echo
    
    # 日志摘要
    echo -e "${pink}最近日志:${white}"
    if [[ -f "/var/log/xray/error.log" ]]; then
        echo "  最近错误:"
        tail -3 /var/log/xray/error.log 2>/dev/null | sed 's/^/    /' || echo "    无错误日志"
    fi
    echo
}

manage_xray_service() {
    while true; do
        clear
        echo -e "${cyan}=== Xray服务管理 ===${white}"
        echo
        
        # 显示当前状态
        if systemctl is-active xray >/dev/null; then
            echo -e "当前状态: ${green}运行中${white}"
        else
            echo -e "当前状态: ${red}已停止${white}"
        fi
        echo
        
        echo "服务管理选项:"
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 查看状态"
        echo "5. 查看日志"
        echo "6. 设置开机启动"
        echo "0. 返回主菜单"
        echo
        
        local choice
        read -p "请选择 [0-6]: " choice
        
        case $choice in
            1)
                start_xray_service
                read -p "按任意键继续..." -n 1 -s
                ;;
            2)
                stop_xray_service
                read -p "按任意键继续..." -n 1 -s
                ;;
            3)
                restart_xray_service
                read -p "按任意键继续..." -n 1 -s
                ;;
            4)
                check_service_status
                read -p "按任意键继续..." -n 1 -s
                ;;
            5)
                show_xray_logs
                read -p "按任意键继续..." -n 1 -s
                ;;
            6)
                systemctl enable xray
                success_msg "已设置Xray开机启动"
                read -p "按任意键继续..." -n 1 -s
                ;;
            0)
                break
                ;;
            *)
                warn_msg "无效选择"
                sleep 1
                ;;
        esac
    done
}

show_xray_logs() {
    clear
    echo -e "${cyan}=== Xray日志查看 ===${white}"
    echo
    
    echo "1. 实时日志"
    echo "2. 错误日志"
    echo "3. 访问日志"
    echo "4. 系统日志"
    echo
    
    local choice
    read -p "请选择日志类型 [1-4]: " choice
    
    case $choice in
        1)
            echo "按 Ctrl+C 退出实时日志"
            journalctl -u xray -f
            ;;
        2)
            if [[ -f "/var/log/xray/error.log" ]]; then
                tail -50 /var/log/xray/error.log
            else
                echo "错误日志文件不存在"
            fi
            ;;
        3)
            if [[ -f "/var/log/xray/access.log" ]]; then
                tail -50 /var/log/xray/access.log
            else
                echo "访问日志文件不存在"
            fi
            ;;
        4)
            journalctl -u xray --no-pager -n 50
            ;;
    esac
}
#endregion

#region //代理部署流程
quick_deploy() {
    clear
    echo -e "${cyan}=== 快速代理部署 ===${white}"
    echo "此模式将自动选择最佳配置进行部署"
    echo
    
    # 检查Xray安装
    if ! command -v xray >/dev/null 2>&1; then
        info_msg "Xray未安装，开始安装..."
        install_xray
    fi
    
    # 自动配置参数
    PROXY_PORT=$(find_available_port)
    PROXY_UUID=$(generate_uuid)
    PROXY_TARGET="www.microsoft.com"
    PROXY_SHORT_ID=$(generate_short_id)
    
    # 生成密钥对
    generate_reality_keypair
    
    echo
    echo -e "${cyan}自动选择的配置:${white}"
    echo "  端口: $PROXY_PORT"
    echo "  目标网站: $PROXY_TARGET"
    echo "  UUID: $PROXY_UUID"
    echo
    
    read -p "确认使用以上配置进行部署？(Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        return 0
    fi
    
    # 执行部署
    info_msg "开始快速部署..."
    
    generate_xray_config "$PROXY_PORT" "$PROXY_UUID" "$PROXY_TARGET" "$PROXY_PRIVATE_KEY" "$PROXY_SHORT_ID"
    validate_xray_config
    save_proxy_config
    
    # 配置防火墙
    configure_firewall_for_proxy "$PROXY_PORT"
    
    # 启动服务
    start_xray_service
    
    # 生成客户端配置
    generate_client_configs
    
    echo
    success_msg "快速部署完成！"
    echo
    show_client_info
}

custom_deploy() {
    clear
    echo -e "${cyan}=== 自定义代理部署 ===${white}"
    echo "此模式允许您自定义所有配置参数"
    echo
    
    # 检查Xray安装
    if ! command -v xray >/dev/null 2>&1; then
        info_msg "Xray未安装，开始安装..."
        install_xray
    fi
    
    # 端口配置
    while true; do
        local default_port=$(find_available_port)
        read -p "请输入监听端口 [默认: $default_port]: " port_input
        PROXY_PORT=${port_input:-$default_port}
        
        if validate_port "$PROXY_PORT"; then
            break
        else
            warn_msg "端口 $PROXY_PORT 无效或已被占用，请重新输入"
        fi
    done
    
    # UUID配置
    local default_uuid=$(generate_uuid)
    read -p "请输入UUID [默认: 自动生成]: " uuid_input
    PROXY_UUID=${uuid_input:-$default_uuid}
    
    # 目标网站选择
    select_target_website
    
    # 短ID配置
    local default_short_id=$(generate_short_id)
    read -p "请输入短ID [默认: $default_short_id]: " short_id_input
    PROXY_SHORT_ID=${short_id_input:-$default_short_id}
    
    # 生成密钥对
    generate_reality_keypair
    
    # 显示配置摘要
    echo
    echo -e "${cyan}配置摘要:${white}"
    echo "  端口: $PROXY_PORT"
    echo "  UUID: $PROXY_UUID"
    echo "  目标网站: $PROXY_TARGET"
    echo "  短ID: $PROXY_SHORT_ID"
    echo
    
    read -p "确认使用以上配置进行部署？(Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        return 0
    fi
    
    # 执行部署
    info_msg "开始自定义部署..."
    
    generate_xray_config "$PROXY_PORT" "$PROXY_UUID" "$PROXY_TARGET" "$PROXY_PRIVATE_KEY" "$PROXY_SHORT_ID"
    validate_xray_config
    save_proxy_config
    
    # 配置防火墙
    configure_firewall_for_proxy "$PROXY_PORT"
    
    # 启动服务
    start_xray_service
    
    # 生成客户端配置
    generate_client_configs
    
    echo
    success_msg "自定义部署完成！"
    echo
    show_client_info
}

configure_firewall_for_proxy() {
    local port="$1"
    
    info_msg "配置防火墙规则..."
    
    if command -v ufw >/dev/null 2>&1; then
        # 检查UFW状态
        if ! ufw status | grep -q "Status: active"; then
            warn_msg "UFW防火墙未启用，是否启用？"
            read -p "(Y/n): " enable_ufw
            if [[ ! "$enable_ufw" =~ ^[Nn]$ ]]; then
                ufw --force enable
            fi
        fi
        
        # 添加代理端口规则
        ufw allow "$port/tcp" comment "VPS-Proxy"
        success_msg "UFW防火墙规则已添加: $port/tcp"
        
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # firewalld配置
        if ! systemctl is-active firewalld >/dev/null; then
            systemctl start firewalld
            systemctl enable firewalld
        fi
        
        firewall-cmd --permanent --add-port="$port/tcp"
        firewall-cmd --reload
        success_msg "firewalld防火墙规则已添加: $port/tcp"
        
    else
        warn_msg "未检测到支持的防火墙，请手动开放端口: $port"
        echo "iptables示例: iptables -A INPUT -p tcp --dport $port -j ACCEPT"
    fi
}

remove_proxy() {
    clear
    echo -e "${red}=== 卸载代理服务 ===${white}"
    echo "此操作将完全移除代理配置和服务"
    echo
    
    warn_msg "警告: 此操作不可逆！"
    read -p "确认要卸载代理服务吗？(输入 'YES' 确认): " confirm
    
    if [[ "$confirm" != "YES" ]]; then
        info_msg "取消卸载操作"
        return 0
    fi
    
    info_msg "开始卸载代理服务..."
    
    # 停止服务
    if systemctl is-active xray >/dev/null; then
        systemctl stop xray
    fi
    
    # 禁用服务
    if systemctl is-enabled xray >/dev/null; then
        systemctl disable xray
    fi
    
    # 删除服务文件
    if [[ -f "$xray_service_file" ]]; then
        rm -f "$xray_service_file"
        systemctl daemon-reload
    fi
    
    # 删除Xray程序
    rm -f /usr/local/bin/xray
    rm -rf /usr/local/share/xray
    rm -rf /usr/local/etc/xray
    rm -rf /var/log/xray
    
    # 删除配置目录
    read -p "是否删除所有配置文件？(y/N): " delete_config
    if [[ "$delete_config" =~ ^[Yy]$ ]]; then
        rm -rf "$config_dir"
    fi
    
    # 移除防火墙规则
    if [[ -f "$config_dir/proxy.conf" ]]; then
        source "$config_dir/proxy.conf"
        if command -v ufw >/dev/null 2>&1; then
            ufw delete allow "$PROXY_PORT/tcp" 2>/dev/null || true
        fi
    fi
    
    success_msg "代理服务卸载完成"
}
#endregion

#region //主菜单系统
show_proxy_status() {
    clear
    echo -e "${pink}=== 代理服务状态 ===${white}"
    echo
    
    # 服务状态
    if systemctl is-active xray >/dev/null; then
        echo -e "服务状态: ${green}运行中${white}"
        
        if [[ -f "$config_dir/proxy.conf" ]]; then
            source "$config_dir/proxy.conf"
            echo "配置类型: $PROXY_TYPE"
            echo "服务端口: $PROXY_PORT"
            echo "目标网站: $PROXY_TARGET"
            echo "创建时间: $CREATED_TIME"
            
            # 端口监听检查
            if ss -tuln | grep -q ":$PROXY_PORT "; then
                echo -e "端口状态: ${green}正常监听${white}"
            else
                echo -e "端口状态: ${red}异常${white}"
            fi
        fi
    else
        echo -e "服务状态: ${red}未运行${white}"
    fi
    echo
    
    # 系统信息
    echo -e "${cyan}系统信息:${white}"
    echo "  服务器IP: $(get_server_ip)"
    echo "  操作系统: $OS $OS_VERSION"
    echo "  Xray版本: $(xray version 2>/dev/null | head -1 | awk '{print $2}' || echo '未安装')"
    echo
    
    # 网络状态
    echo -e "${cyan}网络状态:${white}"
    echo "  活动连接: $(ss -tun | wc -l) 个"
    echo "  网络延迟: $(ping -c 1 8.8.8.8 2>/dev/null | grep 'time=' | awk -F'time=' '{print $2}' | awk '{print $1}' || echo '未知')ms"
    echo
}

show_help() {
    clear
    echo -e "${pink}=== VPS代理部署工具 v$version ===${white}"
    echo
    echo "专注于VLESS+REALITY代理协议的部署和管理工具"
    echo
    echo "用法: $0 [选项]"
    echo
    echo "快速操作选项:"
    echo "  --help, -h        显示此帮助信息"
    echo "  --version, -v     显示版本信息"
    echo "  --quick           快速部署代理"
    echo "  --custom          自定义部署代理"
    echo "  --status          显示代理状态"
    echo "  --client          显示客户端信息"
    echo "  --remove          卸载代理服务"
    echo
    echo "主要功能:"
    echo "  • VLESS+REALITY代理部署"
    echo "  • 智能端口和目标网站选择"
    echo "  • 多格式客户端配置生成"
    echo "  • 服务状态监控和管理"
    echo "  • 防火墙自动配置"
    echo "  • 一键卸载功能"
    echo
    echo "支持的客户端:"
    echo "  • v2rayNG (Android)"
    echo "  • Shadowrocket (iOS)"
    echo "  • v2rayN (Windows)"
    echo "  • V2RayXS (macOS)"
    echo "  • Xray (Linux)"
    echo "  • Clash系列"
    echo
}

main_menu() {
    while true; do
        clear
        echo -e "${pink}${bold}╔═══════════════════════════════════════════╗${white}"
        echo -e "${pink}${bold}║        VPS代理部署工具 v$version         ║${white}"
        echo -e "${pink}${bold}╚═══════════════════════════════════════════╝${white}"
        echo
        echo -e "${cyan}🚀 代理部署:${white}"
        echo "  1. 快速部署 (推荐新手)"
        echo "  2. 自定义部署"
        echo "  3. 仅安装Xray"
        echo
        echo -e "${cyan}📊 服务管理:${white}"
        echo "  4. 服务状态"
        echo "  5. 服务管理"
        echo "  6. 查看日志"
        echo
        echo -e "${cyan}📱 客户端配置:${white}"
        echo "  7. 客户端信息"
        echo "  8. 重新生成配置"
        echo "  9. 配置文件下载"
        echo
        echo -e "${cyan}🔧 系统管理:${white}"
        echo "  10. 卸载代理"
        echo "  11. 帮助信息"
        echo
        echo "  0. 退出"
        echo
        
        local choice
        read -p "请选择 [0-11]: " choice
        
        case $choice in
            1) quick_deploy ;;
            2) custom_deploy ;;
            3) install_xray; read -p "按任意键继续..." -n 1 -s ;;
            4) show_proxy_status; read -p "按任意键继续..." -n 1 -s ;;
            5) manage_xray_service ;;
            6) show_xray_logs; read -p "按任意键继续..." -n 1 -s ;;
            7) show_client_info; read -p "按任意键继续..." -n 1 -s ;;
            8) 
                if [[ -f "$config_dir/proxy.conf" ]]; then
                    source "$config_dir/proxy.conf"
                    generate_client_configs
                else
                    warn_msg "代理配置不存在，请先部署代理"
                fi
                read -p "按任意键继续..." -n 1 -s
                ;;
            9)
                echo
                echo "配置文件位置:"
                echo "  $config_dir/clients/"
                echo
                echo "可使用以下命令下载："
                echo "  scp root@your-server:$config_dir/clients/* ./"
                read -p "按任意键继续..." -n 1 -s
                ;;
            10) remove_proxy; read -p "按任意键继续..." -n 1 -s ;;
            11) show_help; read -p "按任意键继续..." -n 1 -s ;;
            0) 
                echo -e "${green}感谢使用VPS代理部署工具！${white}"
                exit 0
                ;;
            *)
                warn_msg "无效选择，请重新选择"
                sleep 1
                ;;
        esac
    done
}
#endregion

#region //主程序入口
handle_arguments() {
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            echo "VPS代理部署工具 v$version"
            exit 0
            ;;
        --quick)
            quick_deploy
            exit 0
            ;;
        --custom)
            custom_deploy
            exit 0
            ;;
        --status)
            show_proxy_status
            exit 0
            ;;
        --client)
            show_client_info
            exit 0
            ;;
        --remove)
            remove_proxy
            exit 0
            ;;
        "")
            # 无参数，进入交互模式
            ;;
        *)
            echo "未知参数: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
}

main() {
    # 检查权限
    check_root_permission
    
    # 创建必要目录
    create_directories
    
    # 处理命令行参数
    handle_arguments "$@"
    
    # 检测系统
    detect_system
    
    # 安装必要依赖
    case $PACKAGE_MANAGER in
        apt)
            if ! command -v curl >/dev/null 2>&1; then
                apt update -qq && apt install -y curl
            fi
            if ! command -v unzip >/dev/null 2>&1; then
                apt install -y unzip 2>/dev/null || true
            fi
            # 安装二维码生成工具
            if ! command -v qrencode >/dev/null 2>&1; then
                apt install -y qrencode 2>/dev/null || true
            fi
            ;;
        yum|dnf)
            if ! command -v curl >/dev/null 2>&1; then
                $PACKAGE_MANAGER install -y curl
            fi
            if ! command -v unzip >/dev/null 2>&1; then
                $PACKAGE_MANAGER install -y unzip 2>/dev/null || true
            fi
            # 安装二维码生成工具
            if ! command -v qrencode >/dev/null 2>&1; then
                $PACKAGE_MANAGER install -y qrencode 2>/dev/null || true
            fi
            ;;
    esac
    
    # 记录启动
    log_operation "VPS代理部署工具 v$version 启动"
    
    # 进入主菜单
    main_menu
}

# 脚本执行入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
#endregion