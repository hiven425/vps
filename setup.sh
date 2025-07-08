#!/bin/bash
#
# VLESS Reality 服务管理面板
# 基于 https://jollyroger.top/sites/223.html
# 作者: 资深 DevOps 工程师
# 版本: 5.0.0
# 功能: 一键部署、配置管理、安全加固、状态监控
# ===========================================================

set -e  # 遇到错误立即退出

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# 全局变量
readonly SCRIPT_VERSION="5.0.0"
readonly CONFIG_DIR="/etc/setup"
readonly CONFIG_FILE="${CONFIG_DIR}/config.ini"
readonly BACKUP_DIR="/root/vless-backups"

# 配置变量
MY_DOMAIN=""
FALLBACK_DOMAIN=""
CF_TOKEN=""
SSH_PORT="22"
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""
INSTALL_DATE=""

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${PURPLE}[DEBUG]${NC} $1"
}

# 错误处理函数
check_result() {
    if [ $? -ne 0 ]; then
        log_error "$1 失败！"
        exit 1
    fi
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 用户运行"
        exit 1
    fi
}

# 检查系统要求
check_system() {
    log_info "检查系统要求..."
    
    # 检查操作系统
    if ! command -v apt &> /dev/null; then
        log_error "此脚本仅支持 Debian/Ubuntu 系统"
        exit 1
    fi
    
    # 检查架构
    local arch=$(uname -m)
    if [[ ! "$arch" =~ ^(x86_64|amd64|aarch64|arm64)$ ]]; then
        log_error "不支持的系统架构: $arch"
        exit 1
    fi
    
    log_success "系统要求检查通过"
}

# 域名格式验证
validate_domain() {
    local domain=$1
    if [[ -z "$domain" ]]; then
        return 1
    fi
    
    # 基本域名格式检查
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    
    # 检查不能以点或连字符开头/结尾
    if [[ "$domain" == .* ]] || [[ "$domain" == *. ]] || [[ "$domain" == -* ]] || [[ "$domain" == *- ]]; then
        return 1
    fi
    
    return 0
}

# 保存配置
save_config() {
    log_info "保存配置信息..."
    
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# VLESS Reality 配置文件
MY_DOMAIN="$MY_DOMAIN"
FALLBACK_DOMAIN="$FALLBACK_DOMAIN"
CF_TOKEN="$CF_TOKEN"
SSH_PORT="$SSH_PORT"
UUID="$UUID"
PRIVATE_KEY="$PRIVATE_KEY"
PUBLIC_KEY="$PUBLIC_KEY"
SHORT_ID="$SHORT_ID"
INSTALL_DATE="$INSTALL_DATE"
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "配置已保存到 $CONFIG_FILE"
}

# 加载配置
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        return 0
    else
        return 1
    fi
}

# 创建备份
create_backup() {
    local backup_name="backup_$(date +%Y%m%d_%H%M%S)"
    local backup_path="${BACKUP_DIR}/${backup_name}"
    
    log_info "创建配置备份..."
    mkdir -p "$backup_path"
    
    # 备份配置文件
    [[ -f "/usr/local/etc/xray/config.json" ]] && cp "/usr/local/etc/xray/config.json" "$backup_path/"
    [[ -f "/etc/nginx/nginx.conf" ]] && cp "/etc/nginx/nginx.conf" "$backup_path/"
    [[ -f "$CONFIG_FILE" ]] && cp "$CONFIG_FILE" "$backup_path/"
    
    log_success "备份已创建: $backup_path"
}

# 主菜单显示
show_main_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              VLESS Reality 服务管理面板 v${SCRIPT_VERSION}              ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  1. 首次安装或完整重装服务                                      ║${NC}"
    echo -e "${WHITE}║  2. 修改服务配置                                                ║${NC}"
    echo -e "${WHITE}║  3. 安全与防火墙管理                                            ║${NC}"
    echo -e "${WHITE}║  4. 检查服务运行状态                                            ║${NC}"
    echo -e "${WHITE}║  5. 查看客户端连接信息                                          ║${NC}"
    echo -e "${WHITE}║  6. 卸载服务                                                    ║${NC}"
    echo -e "${WHITE}║  7. 修改SSH端口                                                 ║${NC}"
    echo -e "${WHITE}║  8. 退出                                                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ========================================
# 功能1: 首次安装或完整重装服务
# ========================================

get_user_input() {
    echo -e "${CYAN}=== 配置参数收集 ===${NC}"
    echo ""
    
    # 获取主域名
    while true; do
        read -p "请输入您的主域名 (例如: example.com): " MY_DOMAIN
        if validate_domain "$MY_DOMAIN"; then
            log_success "主域名: $MY_DOMAIN"
            break
        else
            log_error "域名格式无效，请重新输入"
        fi
    done
    
    # 获取伪装域名
    echo ""
    echo "请选择伪装回落域名:"
    echo "1. www.kcrw.com (推荐)"
    echo "2. www.lovelive-anime.jp"
    echo "3. www.microsoft.com"
    echo "4. 自定义"
    echo ""
    
    while true; do
        read -p "请选择 [1-4]: " choice
        case $choice in
            1)
                FALLBACK_DOMAIN="www.kcrw.com"
                break
                ;;
            2)
                FALLBACK_DOMAIN="www.lovelive-anime.jp"
                break
                ;;
            3)
                FALLBACK_DOMAIN="www.microsoft.com"
                break
                ;;
            4)
                while true; do
                    read -p "请输入自定义伪装域名: " FALLBACK_DOMAIN
                    if validate_domain "$FALLBACK_DOMAIN"; then
                        break
                    else
                        log_error "域名格式无效，请重新输入"
                    fi
                done
                break
                ;;
            *)
                log_error "无效选择，请输入 1-4"
                ;;
        esac
    done
    
    log_success "伪装域名: $FALLBACK_DOMAIN"
    
    # 获取 Cloudflare API Token
    echo ""
    while true; do
        read -p "请输入 Cloudflare API Token: " CF_TOKEN
        if [[ -n "$CF_TOKEN" && ${#CF_TOKEN} -gt 10 ]]; then
            log_success "Cloudflare API Token 已获取"
            break
        else
            log_error "API Token 无效，请输入有效的 Cloudflare API Token"
        fi
    done
    
    # 获取SSH端口
    echo ""
    read -p "请输入SSH端口 (默认22): " input_ssh_port
    SSH_PORT=${input_ssh_port:-22}
    log_success "SSH端口: $SSH_PORT"
    
    echo ""
    log_success "配置参数收集完成"
}

update_system() {
    log_info "更新系统并安装依赖..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    check_result "系统更新"
    
    apt upgrade -y
    check_result "系统升级"
    
    # 安装基础依赖
    apt install -y curl wget unzip socat cron sudo ufw fail2ban openssl jq
    check_result "基础依赖安装"
    
    # 安装 Nginx
    apt install -y nginx
    check_result "Nginx 安装"
    systemctl enable nginx
    
    log_success "系统更新和依赖安装完成"
}

install_xray() {
    log_info "安装 Xray..."
    
    # 检查是否已安装
    if [[ -f "/usr/local/bin/xray" ]]; then
        log_info "Xray 已安装，跳过..."
        return 0
    fi
    
    # 使用官方安装脚本
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    check_result "Xray 安装"
    
    # 启用服务
    systemctl enable xray
    
    log_success "Xray 安装完成"
}

install_acme() {
    log_info "安装 acme.sh..."
    
    # 检查是否已安装
    if [[ -f "/root/.acme.sh/acme.sh" ]]; then
        log_info "acme.sh 已安装，跳过..."
        return 0
    fi
    
    # 安装 acme.sh
    curl https://get.acme.sh | sh
    check_result "acme.sh 安装"
    
    # 重新加载环境变量
    source ~/.bashrc
    
    log_success "acme.sh 安装完成"
}

generate_keys() {
    log_info "生成加密密钥..."
    
    # 生成 UUID
    UUID=$(/usr/local/bin/xray uuid)
    
    # 生成 X25519 密钥对
    local keypair=$(/usr/local/bin/xray x25519)
    PRIVATE_KEY=$(echo "$keypair" | grep "Private key:" | cut -d' ' -f3)
    PUBLIC_KEY=$(echo "$keypair" | grep "Public key:" | cut -d' ' -f3)
    
    # 生成 16 位十六进制 shortId
    SHORT_ID=$(openssl rand -hex 8)
    
    INSTALL_DATE=$(date)
    
    log_success "密钥生成完成"
    log_debug "UUID: $UUID"
    log_debug "Public Key: $PUBLIC_KEY"
    log_debug "Short ID: $SHORT_ID"
}

setup_ssl_certificate() {
    log_info "配置 SSL 证书..."
    
    # 创建证书目录
    mkdir -p /etc/ssl/private
    
    # 设置 Cloudflare API Token
    export CF_Token="$CF_TOKEN"
    
    # 设置默认 CA 为 Let's Encrypt 并注册账户
    log_info "设置 Let's Encrypt CA..."
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --register-account -m "admin@${MY_DOMAIN}" --server letsencrypt
    
    # 使用 DNS 验证申请证书
    log_info "申请 SSL 证书 (DNS 验证)..."
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --server letsencrypt
    check_result "SSL 证书申请"
    
    # 安装证书到指定位置
    log_info "安装证书..."
    ~/.acme.sh/acme.sh --install-cert -d "$MY_DOMAIN" \
        --key-file /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --reloadcmd "sudo systemctl force-reload nginx"
    check_result "SSL 证书安装"
    
    # 设置权限
    chmod 600 /etc/ssl/private/private.key
    chmod 644 /etc/ssl/private/fullchain.cer
    
    log_success "SSL 证书配置完成"
}

configure_xray() {
    log_info "配置 Xray..."
    
    # 创建配置目录
    mkdir -p /usr/local/etc/xray
    
    # 生成 Xray 配置文件 (严格按照最终确定的正确逻辑)
    cat > /usr/local/etc/xray/config.json << EOF
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
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
          "dest": "127.0.0.1:8003",
          "xver": 0,
          "serverNames": [
            "$MY_DOMAIN"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF
    
    # 设置权限
    chmod 644 /usr/local/etc/xray/config.json
    
    log_success "Xray 配置完成"
}

configure_nginx() {
    log_info "配置 Nginx..."
    
    # 备份原配置
    if [[ -f "/etc/nginx/nginx.conf" ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    fi
    
    # 生成新的 nginx.conf (严格按照最终确定的正确逻辑)
    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL 设置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # 日志设置
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip 设置
    gzip on;

    # HTTP 重定向到 HTTPS
    server {
        listen 80;
        server_name $MY_DOMAIN;
        return 301 https://\$server_name\$request_uri;
    }

    # Xray Reality 回落服务器 (关键配置)
    server {
        listen 127.0.0.1:8003 ssl proxy_protocol;

        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;

        server_name $MY_DOMAIN;

        ssl_certificate /etc/ssl/private/fullchain.cer;
        ssl_certificate_key /etc/ssl/private/private.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256;
        ssl_session_tickets on;

        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 1.1.1.1 valid=60s;
        resolver_timeout 2s;

        location / {
            sub_filter \$proxy_host \$host;
            sub_filter_once off;
            
            set \$website $FALLBACK_DOMAIN;
            proxy_pass https://\$website;
            resolver 1.1.1.1;
            proxy_set_header Host \$website;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Accept-Encoding "";
            proxy_redirect off;
        }
    }

    # 主 HTTPS 服务器 (可选)
    server {
        listen 443 ssl http2;
        server_name $MY_DOMAIN;

        ssl_certificate /etc/ssl/private/fullchain.cer;
        ssl_certificate_key /etc/ssl/private/private.key;

        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 5m;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        location / {
            set \$website $FALLBACK_DOMAIN;
            proxy_pass https://\$website;
            proxy_ssl_server_name on;
            proxy_ssl_name \$website;
            proxy_set_header Host \$website;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_redirect off;
            
            resolver 1.1.1.1 8.8.8.8 valid=300s;
            resolver_timeout 10s;
        }
    }
}
EOF
    
    log_success "Nginx 配置完成"
}

configure_firewall() {
    log_info "配置 UFW 防火墙..."
    
    # 重置防火墙
    ufw --force reset
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许 SSH 和 HTTPS
    ufw allow "$SSH_PORT"/tcp
    ufw allow 443/tcp
    
    # 启用防火墙
    ufw --force enable
    
    log_success "防火墙配置完成"
}

start_services() {
    log_info "启动和配置服务..."
    
    # 测试 Nginx 配置
    if ! nginx -t; then
        log_error "Nginx 配置测试失败"
        exit 1
    fi
    
    # 启动服务
    systemctl restart nginx
    check_result "Nginx 重启"
    
    systemctl restart xray
    check_result "Xray 重启"
    
    systemctl enable nginx xray
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    if systemctl is-active --quiet nginx && systemctl is-active --quiet xray; then
        log_success "所有服务启动成功"
    else
        log_error "服务启动失败"
        log_info "Nginx 状态: $(systemctl is-active nginx)"
        log_info "Xray 状态: $(systemctl is-active xray)"
        exit 1
    fi
}

generate_client_config() {
    log_info "生成客户端配置..."
    
    # 创建配置目录
    mkdir -p /root/client-configs
    
    # 生成 VLESS 链接
    local vless_link="vless://${UUID}@${MY_DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${MY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#Reality-${MY_DOMAIN}"
    
    # 保存配置信息
    cat > /root/client-configs/config.txt << EOF
=== VLESS Reality 配置信息 ===

服务器地址: $MY_DOMAIN
端口: 443
UUID: $UUID
Flow: xtls-rprx-vision
传输安全: reality
SNI: $MY_DOMAIN
Fingerprint: chrome
PublicKey: $PUBLIC_KEY
ShortId: $SHORT_ID
伪装域名: $FALLBACK_DOMAIN

=== 一键导入链接 ===
$vless_link

配置生成时间: $(date)
EOF
    
    # 保存 VLESS 链接
    echo "$vless_link" > /root/client-configs/vless-link.txt
    
    # 设置权限
    chmod 600 /root/client-configs/*
    
    log_success "客户端配置生成完成"
}

# 首次安装主函数
first_install() {
    log_info "开始首次安装或完整重装..."
    
    # 如果存在配置，创建备份
    if [[ -f "$CONFIG_FILE" ]]; then
        create_backup
    fi
    
    get_user_input
    update_system
    install_xray
    install_acme
    generate_keys
    setup_ssl_certificate
    configure_xray
    configure_nginx
    configure_firewall
    start_services
    generate_client_config
    save_config
    
    log_success "安装完成！"
    echo ""
    
    # 显示客户端连接信息
    show_client_info
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========================================
# 功能2: 修改服务配置
# ========================================

show_config_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 修改服务配置 ===${NC}"
        echo ""
        echo "1. 更换主域名"
        echo "2. 更换伪装域名"
        echo "3. 重新生成 UUID"
        echo "4. 重新生成 Reality 密钥对"
        echo "5. 重新生成 ShortId"
        echo "6. 返回主菜单"
        echo ""
        
        read -p "请选择 [1-6]: " choice
        
        case $choice in
            1) change_main_domain ;;
            2) change_fallback_domain ;;
            3) regenerate_uuid ;;
            4) regenerate_reality_keys ;;
            5) regenerate_short_id ;;
            6) return 0 ;;
            *) log_error "无效选择，请重新输入" ; sleep 2 ;;
        esac
    done
}

change_main_domain() {
    log_info "更换主域名..."
    
    if ! load_config; then
        log_error "未找到配置文件，请先进行安装"
        read -p "按回车键继续..."
        return 1
    fi
    
    echo "当前主域名: $MY_DOMAIN"
    echo ""
    
    while true; do
        read -p "请输入新的主域名: " new_domain
        if validate_domain "$new_domain"; then
            break
        else
            log_error "域名格式无效，请重新输入"
        fi
    done
    
    log_info "开始更换主域名到: $new_domain"
    
    # 申请新证书
    export CF_Token="$CF_TOKEN"
    ~/.acme.sh/acme.sh --register-account -m "admin@${new_domain}" --server letsencrypt 2>/dev/null || true
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$new_domain" --server letsencrypt
    check_result "新域名证书申请"
    
    # 安装新证书
    ~/.acme.sh/acme.sh --install-cert -d "$new_domain" \
        --key-file /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --reloadcmd "sudo systemctl force-reload nginx" --server letsencrypt
    check_result "新域名证书安装"
    
    # 更新配置文件
    sed -i "s/$MY_DOMAIN/$new_domain/g" /usr/local/etc/xray/config.json
    sed -i "s/$MY_DOMAIN/$new_domain/g" /etc/nginx/nginx.conf
    
    # 更新变量并保存配置
    MY_DOMAIN="$new_domain"
    save_config
    
    # 重启服务
    systemctl restart nginx xray
    check_result "服务重启"
    
    # 重新生成客户端配置
    generate_client_config
    
    log_success "主域名已成功更换为: $new_domain"
    read -p "按回车键继续..."
}

change_fallback_domain() {
    log_info "更换伪装域名..."
    
    if ! load_config; then
        log_error "未找到配置文件，请先进行安装"
        read -p "按回车键继续..."
        return 1
    fi
    
    echo "当前伪装域名: $FALLBACK_DOMAIN"
    echo ""
    echo "请选择新的伪装域名:"
    echo "1. www.kcrw.com"
    echo "2. www.lovelive-anime.jp"
    echo "3. www.microsoft.com"
    echo "4. 自定义"
    echo ""
    
    while true; do
        read -p "请选择 [1-4]: " choice
        case $choice in
            1)
                local new_fallback="www.kcrw.com"
                break
                ;;
            2)
                local new_fallback="www.lovelive-anime.jp"
                break
                ;;
            3)
                local new_fallback="www.microsoft.com"
                break
                ;;
            4)
                while true; do
                    read -p "请输入自定义伪装域名: " new_fallback
                    if validate_domain "$new_fallback"; then
                        break
                    else
                        log_error "域名格式无效"
                    fi
                done
                break
                ;;
            *)
                log_error "无效选择"
                ;;
        esac
    done
    
    log_info "更换伪装域名到: $new_fallback"
    
    # 更新 Nginx 配置
    sed -i "s/$FALLBACK_DOMAIN/$new_fallback/g" /etc/nginx/nginx.conf
    
    # 更新变量并保存配置
    FALLBACK_DOMAIN="$new_fallback"
    save_config
    
    # 重载 Nginx
    systemctl reload nginx
    check_result "Nginx 重载"
    
    # 重新生成客户端配置
    generate_client_config
    
    log_success "伪装域名已成功更换为: $new_fallback"
    read -p "按回车键继续..."
}

regenerate_uuid() {
    log_info "重新生成 UUID..."
    
    if ! load_config; then
        log_error "未找到配置文件，请先进行安装"
        read -p "按回车键继续..."
        return 1
    fi
    
    # 生成新 UUID
    local new_uuid=$(/usr/local/bin/xray uuid)
    
    log_info "新 UUID: $new_uuid"
    
    # 更新 Xray 配置
    sed -i "s/\"id\": \"$UUID\"/\"id\": \"$new_uuid\"/g" /usr/local/etc/xray/config.json
    
    # 更新变量并保存配置
    UUID="$new_uuid"
    save_config
    
    # 重启 Xray
    systemctl restart xray
    check_result "Xray 重启"
    
    # 重新生成客户端配置
    generate_client_config
    
    log_success "UUID 已成功更换为: $new_uuid"
    read -p "按回车键继续..."
}

regenerate_reality_keys() {
    log_info "重新生成 Reality 密钥对..."
    
    if ! load_config; then
        log_error "未找到配置文件，请先进行安装"
        read -p "按回车键继续..."
        return 1
    fi
    
    # 生成新密钥对
    local keypair=$(/usr/local/bin/xray x25519)
    local new_private_key=$(echo "$keypair" | grep "Private key:" | cut -d' ' -f3)
    local new_public_key=$(echo "$keypair" | grep "Public key:" | cut -d' ' -f3)
    
    log_info "新私钥: $new_private_key"
    log_info "新公钥: $new_public_key"
    
    # 更新 Xray 配置
    sed -i "s/\"privateKey\": \"$PRIVATE_KEY\"/\"privateKey\": \"$new_private_key\"/g" /usr/local/etc/xray/config.json
    
    # 更新变量并保存配置
    PRIVATE_KEY="$new_private_key"
    PUBLIC_KEY="$new_public_key"
    save_config
    
    # 重启 Xray
    systemctl restart xray
    check_result "Xray 重启"
    
    # 重新生成客户端配置
    generate_client_config
    
    log_success "Reality 密钥对已成功更换"
    read -p "按回车键继续..."
}

regenerate_short_id() {
    log_info "重新生成 ShortId..."
    
    if ! load_config; then
        log_error "未找到配置文件，请先进行安装"
        read -p "按回车键继续..."
        return 1
    fi
    
    # 生成新 ShortId
    local new_short_id=$(openssl rand -hex 8)
    
    log_info "新 ShortId: $new_short_id"
    
    # 更新 Xray 配置
    sed -i "s/\"$SHORT_ID\"/\"$new_short_id\"/g" /usr/local/etc/xray/config.json
    
    # 更新变量并保存配置
    SHORT_ID="$new_short_id"
    save_config
    
    # 重启 Xray
    systemctl restart xray
    check_result "Xray 重启"
    
    # 重新生成客户端配置
    generate_client_config
    
    log_success "ShortId 已成功更换为: $new_short_id"
    read -p "按回车键继续..."
}

# ========================================
# 功能3: 安全与防火墙管理
# ========================================

show_security_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 安全与防火墙管理 ===${NC}"
        echo ""
        echo "1. 配置 Fail2ban 防暴力破解"
        echo "2. 管理 UFW 防火墙"
        echo "3. 返回主菜单"
        echo ""
        
        read -p "请选择 [1-3]: " choice
        
        case $choice in
            1) configure_fail2ban ;;
            2) manage_ufw ;;
            3) return 0 ;;
            *) log_error "无效选择，请重新输入" ; sleep 2 ;;
        esac
    done
}

configure_fail2ban() {
    log_info "配置 Fail2ban 防暴力破解..."
    
    # 加载配置获取 SSH 端口
    if load_config; then
        local ssh_port="$SSH_PORT"
    else
        read -p "请输入 SSH 端口号 (默认22): " ssh_port
        ssh_port=${ssh_port:-22}
    fi
    
    # 检查并安装 fail2ban
    if ! command -v fail2ban-server &> /dev/null; then
        log_info "安装 Fail2ban..."
        apt install -y fail2ban
        check_result "Fail2ban 安装"
    fi
    
    # 创建 jail.local 配置
    log_info "创建 Fail2ban 配置..."
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 忽略的IP地址
ignoreip = 127.0.0.1/8 ::1

# 封禁时间 (秒)
bantime = 600

# 查找时间窗口 (秒)
findtime = 300

# 最大重试次数
maxretry = 5

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 300
bantime = 600
EOF
    
    # 重启 fail2ban 服务
    systemctl restart fail2ban
    check_result "Fail2ban 重启"
    
    systemctl enable fail2ban
    
    log_success "Fail2ban 配置完成"
    log_info "SSH 端口: $ssh_port"
    log_info "最大重试次数: 5"
    log_info "封禁时间: 600秒"
    
    echo ""
    log_info "Fail2ban 状态:"
    fail2ban-client status
    
    read -p "按回车键继续..."
}

manage_ufw() {
    while true; do
        clear
        echo -e "${CYAN}=== UFW 防火墙管理 ===${NC}"
        echo ""
        
        # 显示当前状态
        echo -e "${BLUE}当前防火墙状态:${NC}"
        ufw status verbose
        echo ""
        
        echo "1. 启用防火墙"
        echo "2. 禁用防火墙"
        echo "3. 开放端口"
        echo "4. 关闭端口"
        echo "5. 重置防火墙"
        echo "6. 返回上级菜单"
        echo ""
        
        read -p "请选择 [1-6]: " choice
        
        case $choice in
            1)
                ufw --force enable
                # 自动校验重要端口
                auto_verify_ports
                log_success "防火墙已启用"
                ;;
            2)
                ufw disable
                log_success "防火墙已禁用"
                ;;
            3)
                read -p "请输入要开放的端口: " port
                read -p "协议 (tcp/udp) [tcp]: " protocol
                protocol=${protocol:-tcp}
                ufw allow "$port/$protocol"
                log_success "端口 $port/$protocol 已开放"
                ;;
            4)
                read -p "请输入要关闭的端口: " port
                ufw delete allow "$port"
                log_success "端口 $port 已关闭"
                ;;
            5)
                read -p "确认重置防火墙？这将删除所有规则 (y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    ufw --force reset
                    ufw default deny incoming
                    ufw default allow outgoing
                    log_success "防火墙已重置"
                fi
                ;;
            6)
                return 0
                ;;
            *)
                log_error "无效选择"
                sleep 2
                ;;
        esac
        
        if [[ $choice != 6 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

auto_verify_ports() {
    log_info "自动校验重要端口..."
    
    # 加载配置获取 SSH 端口
    if load_config; then
        local ssh_port="$SSH_PORT"
    else
        ssh_port="22"
    fi
    
    # 检查 SSH 端口
    if ! ufw status | grep -q "$ssh_port/tcp"; then
        log_warn "SSH 端口 $ssh_port 未开放，正在添加..."
        ufw allow "$ssh_port/tcp"
    fi
    
    # 检查 HTTPS 端口
    if ! ufw status | grep -q "443/tcp"; then
        log_warn "HTTPS 端口 443 未开放，正在添加..."
        ufw allow 443/tcp
    fi
    
    log_success "端口校验完成"
}

# ========================================
# 功能4: 检查服务运行状态
# ========================================

check_service_status() {
    clear
    echo -e "${CYAN}=== 服务运行状态检查 ===${NC}"
    echo ""
    
    # 检查 Nginx 状态
    echo -e "${BLUE}Nginx 服务状态:${NC}"
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✓ Nginx: 运行中${NC}"
    else
        echo -e "${RED}✗ Nginx: 未运行${NC}"
    fi
    
    # 检查 Xray 状态
    echo -e "${BLUE}Xray 服务状态:${NC}"
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}✓ Xray: 运行中${NC}"
    else
        echo -e "${RED}✗ Xray: 未运行${NC}"
    fi
    
    # 检查 Fail2ban 状态
    echo -e "${BLUE}Fail2ban 服务状态:${NC}"
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}✓ Fail2ban: 运行中${NC}"
    else
        echo -e "${YELLOW}⚠ Fail2ban: 未运行或未安装${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}详细状态信息:${NC}"
    echo "----------------------------------------"
    
    # 端口监听状态
    echo -e "${BLUE}端口监听状态:${NC}"
    if ss -tlnp | grep -q ":443"; then
        echo -e "${GREEN}✓ 443端口: 正在监听${NC}"
    else
        echo -e "${RED}✗ 443端口: 未监听${NC}"
    fi
    
    # 防火墙状态
    echo -e "${BLUE}防火墙状态:${NC}"
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✓ UFW: 已启用${NC}"
    else
        echo -e "${YELLOW}⚠ UFW: 未启用${NC}"
    fi
    
    # SSL 证书状态
    if load_config && [[ -f "/etc/ssl/private/fullchain.cer" ]]; then
        echo -e "${BLUE}SSL 证书状态:${NC}"
        if openssl x509 -checkend 86400 -noout -in /etc/ssl/private/fullchain.cer; then
            echo -e "${GREEN}✓ SSL证书: 有效 (24小时内不会过期)${NC}"
        else
            echo -e "${RED}⚠ SSL证书: 即将过期或已过期${NC}"
        fi
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========================================
# 功能5: 查看客户端连接信息
# ========================================

show_client_info() {
    clear
    echo -e "${CYAN}=== 客户端连接信息 ===${NC}"
    echo ""
    
    if ! load_config; then
        log_error "未找到配置文件，请先进行安装"
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    # 从配置文件读取参数
    if [[ -f "/usr/local/etc/xray/config.json" ]]; then
        echo -e "${BLUE}=== VLESS Reality 配置参数 ===${NC}"
        echo "服务器地址: $MY_DOMAIN"
        echo "端口: 443"
        echo "UUID: $UUID"
        echo "Flow: xtls-rprx-vision"
        echo "传输安全: reality"
        echo "SNI: $MY_DOMAIN"
        echo "Fingerprint: chrome"
        echo "PublicKey: $PUBLIC_KEY"
        echo "ShortId: $SHORT_ID"
        echo "伪装域名: $FALLBACK_DOMAIN"
        echo ""
        
        # 生成 VLESS 链接
        local vless_link="vless://${UUID}@${MY_DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${MY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#Reality-${MY_DOMAIN}"
        
        echo -e "${BLUE}=== 一键导入链接 ===${NC}"
        echo "$vless_link"
        echo ""
        
        # 选项菜单
        echo "1. 保存配置到文件"
        echo "2. 重新生成客户端配置"
        echo "3. 返回主菜单"
        echo ""
        
        read -p "请选择 [1-3]: " choice
        
        case $choice in
            1)
                generate_client_config
                log_success "配置已保存到 /root/client-configs/"
                ;;
            2)
                generate_client_config
                log_success "客户端配置已重新生成"
                ;;
            3)
                return 0
                ;;
        esac
    else
        log_error "未找到 Xray 配置文件"
    fi
    
    read -p "按回车键返回主菜单..."
}

# ========================================
# 功能6: 卸载服务
# ========================================

uninstall_service() {
    clear
    echo -e "${RED}=== 卸载 VLESS Reality 服务 ===${NC}"
    echo ""
    
    echo -e "${YELLOW}警告: 此操作将完全移除以下内容:${NC}"
    echo "- Xray 程序和配置"
    echo "- Nginx VLESS 相关配置"
    echo "- SSL 证书"
    echo "- 客户端配置文件"
    echo "- 相关的 cron 任务"
    echo ""
    
    read -p "确认卸载？请输入 'UNINSTALL' 以确认: " confirm
    if [[ "$confirm" != "UNINSTALL" ]]; then
        log_info "卸载操作已取消"
        read -p "按回车键返回主菜单..."
        return 0
    fi
    
    log_info "开始卸载服务..."
    
    # 停止服务
    log_info "停止相关服务..."
    systemctl stop xray nginx fail2ban 2>/dev/null || true
    systemctl disable xray nginx fail2ban 2>/dev/null || true
    
    # 删除 Xray
    log_info "卸载 Xray..."
    if command -v /usr/local/bin/xray &> /dev/null; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null || true
    fi
    
    # 删除配置文件
    log_info "删除配置文件..."
    rm -rf /usr/local/etc/xray
    rm -rf /root/client-configs
    rm -rf "$CONFIG_DIR"
    rm -rf "$BACKUP_DIR"
    
    # 恢复 Nginx 配置
    if [[ -f "/etc/nginx/nginx.conf.backup" ]]; then
        mv /etc/nginx/nginx.conf.backup /etc/nginx/nginx.conf
    fi
    
    # 删除 SSL 证书
    rm -f /etc/ssl/private/fullchain.cer
    rm -f /etc/ssl/private/private.key
    
    # 删除 acme.sh 证书
    if load_config && [[ -d "/root/.acme.sh" ]]; then
        ~/.acme.sh/acme.sh --remove -d "$MY_DOMAIN" 2>/dev/null || true
    fi
    
    # 删除 cron 任务
    crontab -l | grep -v "acme.sh" | crontab - 2>/dev/null || true
    
    # 询问是否删除软件包
    echo ""
    read -p "是否同时卸载相关软件包 (nginx, fail2ban, ufw)? (y/N): " remove_packages
    if [[ "$remove_packages" =~ ^[Yy]$ ]]; then
        apt remove --purge -y nginx fail2ban ufw 2>/dev/null || true
        apt autoremove -y 2>/dev/null || true
    fi
    
    # 重启 nginx (如果还存在)
    systemctl restart nginx 2>/dev/null || true
    
    log_success "卸载完成！"
    log_info "系统已恢复到安装前状态"
    
    read -p "按回车键返回主菜单..."
}

# ========================================
# 功能7: 修改SSH端口
# ========================================

change_ssh_port() {
    clear
    echo -e "${CYAN}=== 修改 SSH 端口 ===${NC}"
    echo ""
    
    # 显示当前 SSH 配置
    echo -e "${BLUE}当前 SSH 配置:${NC}"
    echo "端口: $(sudo sshd -T | grep -i "Port" | cut -d' ' -f2)"
    echo "Root登录: $(sudo sshd -T | grep -i "PermitRootLogin" | cut -d' ' -f2)"
    echo "密码认证: $(sudo sshd -T | grep -i "PasswordAuthentication" | cut -d' ' -f2)"
    echo ""
    
    # 获取新端口
    while true; do
        read -p "请输入新的 SSH 端口 (1024-65535): " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1024 ] && [ "$new_port" -le 65535 ]; then
            break
        else
            log_error "端口无效，请输入 1024-65535 之间的数字"
        fi
    done
    
    echo ""
    log_warn "修改 SSH 端口可能导致连接中断！"
    read -p "确认修改 SSH 端口到 $new_port ? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "操作已取消"
        read -p "按回车键返回主菜单..."
        return 0
    fi
    
    log_info "修改 SSH 端口到 $new_port ..."
    
    # 备份 SSH 配置
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # 修改 SSH 配置
    sed -i "s/^#*Port .*/Port $new_port/" /etc/ssh/sshd_config
    
    # 确保配置中有 Port 行
    if ! grep -q "^Port $new_port" /etc/ssh/sshd_config; then
        echo "Port $new_port" >> /etc/ssh/sshd_config
    fi
    
    # 测试 SSH 配置
    if ! sshd -t; then
        log_error "SSH 配置测试失败，恢复备份"
        cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    # 更新防火墙规则
    log_info "更新防火墙规则..."
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        # 获取当前 SSH 端口
        if load_config; then
            local old_port="$SSH_PORT"
        else
            old_port="22"
        fi
        
        # 添加新端口
        ufw allow "$new_port/tcp"
        
        # 询问是否删除旧端口
        if [[ "$old_port" != "$new_port" ]]; then
            read -p "是否从防火墙中删除旧的 SSH 端口 $old_port ? (y/N): " remove_old
            if [[ "$remove_old" =~ ^[Yy]$ ]]; then
                ufw delete allow "$old_port/tcp"
            fi
        fi
    fi
    
    # 更新 fail2ban 配置 (如果存在)
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        log_info "更新 Fail2ban 配置..."
        sed -i "s/port = .*/port = $new_port/" /etc/fail2ban/jail.local
        systemctl restart fail2ban 2>/dev/null || true
    fi
    
    # 更新配置文件
    if load_config; then
        SSH_PORT="$new_port"
        save_config
    fi
    
    # 重启 SSH 服务
    log_info "重启 SSH 服务..."
    systemctl restart ssh
    check_result "SSH 服务重启"
    
    log_success "SSH 端口已成功修改为: $new_port"
    log_warn "请使用新端口重新连接: ssh -p $new_port user@server"
    log_info "旧的连接会话在断开后无法重连"
    
    read -p "按回车键返回主菜单..."
}

# ========================================
# 主程序逻辑
# ========================================

main() {
    # 检查权限和系统
    check_root
    check_system
    
    while true; do
        show_main_menu
        read -p "请输入选项 [1-8]: " choice
        
        case $choice in
            1) first_install ;;
            2) show_config_menu ;;
            3) show_security_menu ;;
            4) check_service_status ;;
            5) show_client_info ;;
            6) uninstall_service ;;
            7) change_ssh_port ;;
            8) 
                log_info "感谢使用 VLESS Reality 服务管理面板！"
                exit 0
                ;;
            *)
                log_error "无效选择，请输入 1-8"
                sleep 2
                ;;
        esac
    done
}

# 运行主程序
main "$@"