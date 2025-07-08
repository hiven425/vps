#!/bin/bash
#
# VLESS-Reality Setup Script (Optimized)
# Based on: https://jollyroger.top/sites/223.html
# Author: Claude Code Assistant
# Version: 3.0.0
# =================================================================================

# Strict error handling
set -e -o pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
USER_DOMAIN=""
MASK_DOMAIN=""
CF_TOKEN=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""

# Logging functions
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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Validate domain format
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

# Get user input
get_user_input() {
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              VLESS-Reality 配置向导                              ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Get user domain
    while true; do
        read -p "请输入您的域名 (例如: example.com): " USER_DOMAIN
        if validate_domain "$USER_DOMAIN"; then
            log_info "域名: $USER_DOMAIN"
            break
        else
            log_error "域名格式无效，请重新输入"
        fi
    done
    
    # Get mask domain with predefined options
    echo ""
    echo "请选择伪装域名:"
    echo "1. www.kcrw.com (推荐)"
    echo "2. www.lovelive-anime.jp"
    echo "3. www.microsoft.com"
    echo "4. 自定义"
    
    while true; do
        read -p "请选择 [1-4]: " choice
        case $choice in
            1)
                MASK_DOMAIN="www.kcrw.com"
                break
                ;;
            2)
                MASK_DOMAIN="www.lovelive-anime.jp"
                break
                ;;
            3)
                MASK_DOMAIN="www.microsoft.com"
                break
                ;;
            4)
                while true; do
                    read -p "请输入自定义伪装域名: " MASK_DOMAIN
                    if validate_domain "$MASK_DOMAIN"; then
                        break
                    else
                        log_error "域名格式无效"
                    fi
                done
                break
                ;;
            *)
                log_error "无效选择，请输入 1-4"
                ;;
        esac
    done
    
    # Get Cloudflare token
    echo ""
    read -p "请输入 Cloudflare API Token: " CF_TOKEN
    if [[ -z "$CF_TOKEN" ]]; then
        log_error "CF Token 不能为空"
        exit 1
    fi
    
    log_success "配置信息收集完成"
}

# Update system
update_system() {
    log_info "更新系统..."
    apt update -y
    apt install -y curl wget unzip socat cron
}

# Install Nginx
install_nginx() {
    log_info "安装 Nginx..."
    apt install -y nginx
    systemctl enable nginx
}

# Install Xray
install_xray() {
    log_info "安装 Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
}

# Install acme.sh
install_acme() {
    log_info "安装 acme.sh..."
    curl https://get.acme.sh | sh
    source ~/.bashrc
}

# Generate cryptographic keys
generate_keys() {
    log_info "生成加密密钥..."
    
    # Generate UUID
    UUID=$(/usr/local/bin/xray uuid)
    
    # Generate X25519 key pair
    local keypair=$(/usr/local/bin/xray x25519)
    PRIVATE_KEY=$(echo "$keypair" | grep "Private key:" | cut -d' ' -f3)
    PUBLIC_KEY=$(echo "$keypair" | grep "Public key:" | cut -d' ' -f3)
    
    # Generate short ID (2-16 hex characters, even length)
    SHORT_ID=$(openssl rand -hex 4)
    
    log_success "密钥生成完成"
    log_info "UUID: $UUID"
    log_info "Public Key: $PUBLIC_KEY"
    log_info "Short ID: $SHORT_ID"
}

# Configure Nginx (按文档格式)
configure_nginx() {
    log_info "配置 Nginx..."
    
    # Backup original config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # Create new nginx.conf based on documentation
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

    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Logging Settings
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip Settings
    gzip on;

    # HTTP server (redirect to HTTPS)
    server {
        listen 80;
        server_name $USER_DOMAIN;
        return 301 https://\$server_name\$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name $USER_DOMAIN;

        ssl_certificate /etc/ssl/private/${USER_DOMAIN}.crt;
        ssl_certificate_key /etc/ssl/private/${USER_DOMAIN}.key;

        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 5m;

        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        location / {
            set \$website $MASK_DOMAIN;
            proxy_pass https://\$website;
            proxy_ssl_server_name on;
            proxy_ssl_name \$website;
            proxy_set_header Host \$website;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_redirect off;
        }
    }

    # Reality masking server
    server {
        listen 127.0.0.1:8003 ssl;
        server_name $USER_DOMAIN;

        ssl_certificate /etc/ssl/private/${USER_DOMAIN}.crt;
        ssl_certificate_key /etc/ssl/private/${USER_DOMAIN}.key;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 5m;

        location / {
            set \$website $MASK_DOMAIN;
            proxy_pass https://\$website;
            proxy_ssl_server_name on;
            proxy_ssl_name \$website;
            proxy_set_header Host \$website;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_redirect off;
        }
    }
}
EOF

    log_success "Nginx 配置完成"
}

# Configure Xray (按文档格式)
configure_xray() {
    log_info "配置 Xray..."
    
    # Create Xray config directory
    mkdir -p /usr/local/etc/xray
    
    # Create xray config.json based on documentation
    cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {
        "loglevel": "warning"
    },
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
                    "dest": "8003",
                    "xver": 1,
                    "serverNames": [
                        "$USER_DOMAIN"
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
        }
    ]
}
EOF

    log_success "Xray 配置完成"
}

# Setup SSL certificates
setup_ssl() {
    log_info "配置 SSL 证书..."
    
    # Create SSL directory
    mkdir -p /etc/ssl/private
    
    # Set Cloudflare API token
    export CF_Token="$CF_TOKEN"
    
    # Issue certificate using acme.sh
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$USER_DOMAIN"
    
    # Install certificate
    ~/.acme.sh/acme.sh --install-cert -d "$USER_DOMAIN" \
        --key-file /etc/ssl/private/${USER_DOMAIN}.key \
        --fullchain-file /etc/ssl/private/${USER_DOMAIN}.crt \
        --reloadcmd "systemctl reload nginx"
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/${USER_DOMAIN}.key
    chmod 644 /etc/ssl/private/${USER_DOMAIN}.crt
    
    log_success "SSL 证书配置完成"
}

# Configure firewall
configure_firewall() {
    log_info "配置防火墙..."
    
    # Install and configure UFW
    apt install -y ufw
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    
    log_success "防火墙配置完成"
}

# Start services
start_services() {
    log_info "启动服务..."
    
    # Test configurations
    if ! nginx -t; then
        log_error "Nginx 配置测试失败"
        exit 1
    fi
    
    # Start services
    systemctl restart nginx
    systemctl restart xray
    systemctl enable nginx
    systemctl enable xray
    
    # Check status
    if systemctl is-active --quiet nginx && systemctl is-active --quiet xray; then
        log_success "服务启动成功"
    else
        log_error "服务启动失败"
        exit 1
    fi
}

# Generate client configuration
generate_client_config() {
    log_info "生成客户端配置..."
    
    mkdir -p /root/client-configs
    
    # Generate VLESS Reality link
    local vless_link="vless://${UUID}@${USER_DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${USER_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${USER_DOMAIN}-Reality"
    
    # Save configuration
    cat > /root/client-configs/config.txt << EOF
=== VLESS Reality 配置信息 ===

服务器域名: $USER_DOMAIN
端口: 443
UUID: $UUID
Flow: xtls-rprx-vision
传输安全: reality
SNI: $USER_DOMAIN
Fingerprint: chrome
PublicKey: $PUBLIC_KEY
ShortId: $SHORT_ID

=== 一键导入链接 ===
$vless_link

=== 伪装域名 ===
$MASK_DOMAIN

配置完成时间: $(date)
EOF
    
    echo "$vless_link" > /root/client-configs/vless-link.txt
    
    log_success "客户端配置已生成: /root/client-configs/"
}

# Display final summary
display_summary() {
    clear
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                     安装配置完成！                               ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║ 服务器域名: $USER_DOMAIN"
    echo "║ 伪装域名:   $MASK_DOMAIN"
    echo "║ UUID:       $UUID"
    echo "║ PublicKey:  $PUBLIC_KEY"
    echo "║ ShortId:    $SHORT_ID"
    echo "║"
    echo "║ 配置文件位置:"
    echo "║ - Nginx:    /etc/nginx/nginx.conf"
    echo "║ - Xray:     /usr/local/etc/xray/config.json"
    echo "║ - 客户端:   /root/client-configs/"
    echo "║"
    echo "║ 服务状态:"
    echo "║ - Nginx:    $(systemctl is-active nginx)"
    echo "║ - Xray:     $(systemctl is-active xray)"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    log_info "VLESS 链接:"
    cat /root/client-configs/vless-link.txt
    echo ""
    
    log_info "请将上述链接导入到您的 V2Ray 客户端中"
    log_info "完整配置信息请查看: /root/client-configs/config.txt"
}

# Main function
main() {
    clear
    echo "VLESS-Reality 自动安装脚本"
    echo "基于文档: https://jollyroger.top/sites/223.html"
    echo ""
    
    check_root
    get_user_input
    
    log_info "开始安装配置..."
    
    update_system
    install_nginx
    install_xray
    install_acme
    generate_keys
    configure_nginx
    configure_xray
    setup_ssl
    configure_firewall
    start_services
    generate_client_config
    display_summary
    
    log_success "VLESS-Reality 配置完成！"
}

# Run main function
main "$@"