#!/bin/bash
#
# VLESS + Reality + Nginx 一键安装脚本
# 基于 https://jollyroger.top/sites/223.html
# 作者: DevOps 专家
# 版本: 3.0.0
# ===========================================

set -e  # 遇到错误立即退出

# 颜色输出定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
MY_DOMAIN=""
FALLBACK_DOMAIN=""
CF_TOKEN=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""

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

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 用户运行"
        exit 1
    fi
    log_success "权限检查通过"
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

# 获取用户输入（最小化交互）
get_user_input() {
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║              VLESS + Reality + Nginx 一键安装脚本                  ║"
    echo "║              基于 jollyroger.top 文档配置标准                      ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "开始收集配置参数..."
    echo ""
    
    # 获取用户域名
    while true; do
        read -p "请输入您的域名 (例如: edudo.090910.xyz): " MY_DOMAIN
        if validate_domain "$MY_DOMAIN"; then
            log_success "用户域名: $MY_DOMAIN"
            break
        else
            log_error "域名格式无效，请重新输入"
        fi
    done
    
    # 获取伪装域名
    echo ""
    echo "请选择伪装域名 (用于流量回落):"
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
    
    echo ""
    log_success "配置参数收集完成"
}

# 更新系统并安装依赖
update_system() {
    log_info "更新系统包..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y
    
    log_info "安装必要依赖..."
    apt install -y curl wget unzip socat cron sudo ufw openssl
    
    # 安装 Nginx
    log_info "安装 Nginx..."
    apt install -y nginx
    systemctl enable nginx
    
    log_success "系统更新和依赖安装完成"
}

# 安装 Xray
install_xray() {
    log_info "安装 Xray..."
    
    # 检查是否已安装
    if [[ -f "/usr/local/bin/xray" ]]; then
        log_info "Xray 已安装，跳过..."
        return 0
    fi
    
    # 使用官方安装脚本
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # 启用服务
    systemctl enable xray
    
    log_success "Xray 安装完成"
}

# 安装 acme.sh
install_acme() {
    log_info "安装 acme.sh..."
    
    # 检查是否已安装
    if [[ -f "/root/.acme.sh/acme.sh" ]]; then
        log_info "acme.sh 已安装，跳过..."
        return 0
    fi
    
    # 安装 acme.sh
    curl https://get.acme.sh | sh
    
    # 重新加载环境变量
    source ~/.bashrc
    
    log_success "acme.sh 安装完成"
}

# 生成加密密钥
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
    
    log_success "密钥生成完成"
    log_info "UUID: $UUID"
    log_info "Public Key: $PUBLIC_KEY"
    log_info "Short ID: $SHORT_ID"
}

# 申请和安装 SSL 证书
setup_ssl_certificate() {
    log_info "配置 SSL 证书..."
    
    # 创建证书目录
    mkdir -p /etc/ssl/private
    
    # 设置 Cloudflare API Token
    export CF_Token="$CF_TOKEN"
    
    # 使用 DNS 验证申请证书
    log_info "申请 SSL 证书 (DNS 验证)..."
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN"
    
    # 安装证书到指定位置
    log_info "安装证书..."
    ~/.acme.sh/acme.sh --install-cert -d "$MY_DOMAIN" \
        --key-file /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --reloadcmd "sudo systemctl force-reload nginx"
    
    # 设置权限
    chmod 600 /etc/ssl/private/private.key
    chmod 644 /etc/ssl/private/fullchain.cer
    
    log_success "SSL 证书配置完成"
}

# 配置 Xray
configure_xray() {
    log_info "配置 Xray..."
    
    # 创建配置目录
    mkdir -p /usr/local/etc/xray
    
    # 生成 Xray 配置文件
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

# 配置 Nginx
configure_nginx() {
    log_info "配置 Nginx..."
    
    # 备份原配置
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # 生成新的 nginx.conf
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

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    # 重置防火墙
    ufw --force reset
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许 SSH 和 HTTPS
    ufw allow ssh
    ufw allow 443/tcp
    
    # 启用防火墙
    ufw --force enable
    
    log_success "防火墙配置完成"
}

# 启动服务
start_services() {
    log_info "启动和配置服务..."
    
    # 测试 Nginx 配置
    if ! nginx -t; then
        log_error "Nginx 配置测试失败"
        exit 1
    fi
    
    # 启动 Nginx
    systemctl restart nginx
    systemctl enable nginx
    
    # 启动 Xray
    systemctl restart xray
    systemctl enable xray
    
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

# 生成客户端配置
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

# 显示最终结果
display_results() {
    clear
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                       安装配置完成！                              ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    
    echo -e "${GREEN}=== 配置信息 ===${NC}"
    echo "服务器域名: $MY_DOMAIN"
    echo "伪装域名: $FALLBACK_DOMAIN"
    echo "UUID: $UUID"
    echo "PublicKey: $PUBLIC_KEY"
    echo "ShortId: $SHORT_ID"
    echo ""
    
    echo -e "${GREEN}=== 服务状态 ===${NC}"
    echo "Nginx: $(systemctl is-active nginx)"
    echo "Xray: $(systemctl is-active xray)"
    echo "防火墙: $(ufw status | head -n1 | cut -d' ' -f2)"
    echo ""
    
    echo -e "${GREEN}=== 客户端链接 ===${NC}"
    cat /root/client-configs/vless-link.txt
    echo ""
    
    echo -e "${BLUE}配置文件位置:${NC}"
    echo "- 完整配置: /root/client-configs/config.txt"
    echo "- Nginx 配置: /etc/nginx/nginx.conf"
    echo "- Xray 配置: /usr/local/etc/xray/config.json"
    echo ""
    
    log_success "VLESS + Reality + Nginx 部署完成！"
    log_info "请将上述 VLESS 链接导入到您的客户端中"
}

# 主函数
main() {
    # 检查权限和系统
    check_root
    check_system
    
    # 获取用户输入
    get_user_input
    
    # 执行安装配置
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
    
    # 显示结果
    display_results
}

# 运行主函数
main "$@"