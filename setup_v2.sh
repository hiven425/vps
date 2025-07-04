#!/bin/bash
#
# Title:         Enhanced VLESS-gRPC-REALITY Setup & Management Script  
# Author:        AI Senior DevOps Engineer
# Description:   Installs, configures, and manages a secure proxy on Debian/Ubuntu
# Version:       2.0.0
# =================================================================================

# Strict error handling
set -e -o pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Global variables
DOMAIN=""
EMAIL=""
CF_API_TOKEN=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""
MASK_DOMAIN="www.lovelive-anime.jp"  # 伪装域名
NGINX_CONF_PATH="/etc/nginx/sites-available/default"
XRAY_CONF_PATH="/usr/local/etc/xray/config.json"
TEMP_DIR="/tmp/vless-setup"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Cleanup function
cleanup() {
    local exit_code=$?
    echo -e "${YELLOW}[CLEANUP]${NC} 清理临时文件..."
    rm -rf "$TEMP_DIR"
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} 脚本执行失败，退出码: $exit_code"
        echo -e "${YELLOW}[INFO]${NC} 请检查上方的详细错误信息"
    fi
    exit $exit_code
}

# Set up trap for cleanup
trap cleanup EXIT INT TERM

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

log_debug() {
    echo -e "${PURPLE}[DEBUG]${NC} $1"
}

# Check if running as root
check_privileges() {
    log_info "检查权限..."
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 权限运行"
        exit 1
    fi
    log_success "权限检查通过"
}

# Check system requirements
check_system_requirements() {
    log_info "检查系统要求..."
    
    # Check if running on Debian/Ubuntu
    if ! command -v apt &> /dev/null; then
        log_error "此脚本需要 Debian/Ubuntu 系统"
        exit 1
    fi
    
    # Check system architecture
    local arch=$(uname -m)
    if [[ ! "$arch" =~ ^(x86_64|amd64|aarch64|arm64)$ ]]; then
        log_error "不支持的系统架构: $arch"
        exit 1
    fi
    
    log_success "系统要求检查通过"
}

# Enhanced domain validation
validate_domain() {
    local domain=$1
    
    # 基本检查：不能为空
    if [[ -z "$domain" ]]; then
        return 1
    fi
    
    # 检查域名长度不超过253字符
    if [[ ${#domain} -gt 253 ]]; then
        return 1
    fi
    
    # 检查包含至少一个点
    if [[ ! "$domain" == *.* ]]; then
        return 1
    fi
    
    # 检查没有连续的点
    if [[ "$domain" == *..* ]]; then
        return 1
    fi
    
    # 检查不以点开头或结尾
    if [[ "$domain" == .* ]] || [[ "$domain" == *. ]]; then
        return 1
    fi
    
    # 检查不以连字符开头或结尾
    if [[ "$domain" == -* ]] || [[ "$domain" == *- ]]; then
        return 1
    fi
    
    # 检查顶级域名是字母且至少2位
    local tld="${domain##*.}"
    if [[ ! "$tld" =~ ^[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    
    # 检查域名只包含允许的字符：字母、数字、点、连字符
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        return 1
    fi
    
    return 0
}

# Validate email format
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

# Get user input with validation
get_user_input() {
    log_info "收集配置参数..."
    
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                        配置向导                                  ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} 请准备以下信息："
    echo -e "${CYAN}║${NC}   1. 您的域名 (在 Cloudflare 中管理)"
    echo -e "${CYAN}║${NC}   2. 邮箱地址 (用于 SSL 证书申请)"
    echo -e "${CYAN}║${NC}   3. Cloudflare API Token (Zone:DNS:Edit 权限)"
    echo -e "${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} 注意: 系统将使用 ${MASK_DOMAIN} 作为流量伪装"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get domain
    while true; do
        read -p "请输入您的域名 (例如: example.com): " DOMAIN
        if validate_domain "$DOMAIN"; then
            log_info "将为域名 $DOMAIN 配置 VLESS 代理服务"
            break
        else
            log_error "域名格式无效，请输入有效的域名"
        fi
    done
    
    # Get email
    while true; do
        read -p "请输入您的邮箱地址: " EMAIL
        if validate_email "$EMAIL"; then
            break
        else
            log_error "邮箱格式无效，请输入有效的邮箱地址"
        fi
    done
    
    # Get Cloudflare API token
    while true; do
        read -p "请输入 Cloudflare API Token: " CF_API_TOKEN
        if [[ -n "$CF_API_TOKEN" && ${#CF_API_TOKEN} -gt 10 ]]; then
            break
        else
            log_error "API Token 无效，请输入有效的 Cloudflare API Token"
        fi
    done
    
    log_success "配置参数收集完成"
}

# Update system packages
update_system() {
    log_info "更新系统软件包..."
    
    # Check if update is needed (idempotency)
    if [[ -f "/var/log/vless-setup-updated" ]]; then
        log_info "系统已更新，跳过..."
        return 0
    fi
    
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y
    apt install -y curl wget unzip sudo ufw jq openssl socat cron
    
    # Install latest Nginx
    apt install -y nginx
    
    # Mark as updated
    touch "/var/log/vless-setup-updated"
    log_success "系统软件包更新完成"
}

# Install Nginx
install_nginx() {
    log_info "配置 Nginx..."
    
    # Check if already installed
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Nginx 已安装并运行"
    else
        systemctl enable nginx
        log_success "Nginx 安装完成"
    fi
}

# Install Xray
install_xray() {
    log_info "安装 Xray..."
    
    # Check if already installed
    if [[ -f "/usr/local/bin/xray" ]]; then
        log_info "Xray 已安装"
        return 0
    fi
    
    # Install Xray using official script
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta
    
    # Enable Xray service
    systemctl enable xray
    log_success "Xray 安装完成"
}

# Install ACME.sh
install_acme() {
    log_info "安装 ACME.sh..."
    
    # Check if already installed
    if [[ -f "/root/.acme.sh/acme.sh" ]]; then
        log_info "ACME.sh 已安装"
        return 0
    fi
    
    curl https://get.acme.sh | sh -s email="$EMAIL"
    
    # Set auto-upgrade
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    
    log_success "ACME.sh 安装完成"
}

# Generate cryptographic keys
generate_keys() {
    log_info "生成加密密钥..."
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # Generate UUID
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # Generate X25519 key pair
    local keypair=$(/usr/local/bin/xray x25519)
    PRIVATE_KEY=$(echo "$keypair" | grep "Private key:" | cut -d' ' -f3)
    PUBLIC_KEY=$(echo "$keypair" | grep "Public key:" | cut -d' ' -f3)
    
    # Generate short ID (8 hex characters)
    SHORT_ID=$(openssl rand -hex 4)
    
    log_debug "UUID: $UUID"
    log_debug "私钥: $PRIVATE_KEY"
    log_debug "公钥: $PUBLIC_KEY" 
    log_debug "Short ID: $SHORT_ID"
    
    log_success "加密密钥生成完成"
}

# Configure Nginx with enhanced security and masking
configure_nginx() {
    log_info "配置 Nginx..."
    
    # Create SSL directory
    mkdir -p /etc/ssl/private
    
    # Generate Nginx configuration with masking capability
    cat > "$NGINX_CONF_PATH" << EOF
# Nginx Configuration for VLESS-gRPC-REALITY
# Version: 2.0

# Rate limiting
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
limit_conn_zone \$binary_remote_addr zone=addr:10m;

# Main server block for SSL termination
server {
    listen 80;
    server_name $DOMAIN;
    
    # ACME challenge location
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Redirect all HTTP to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server with Reality masking
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/private/${DOMAIN}.crt;
    ssl_certificate_key /etc/ssl/private/${DOMAIN}.key;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Rate limiting
    limit_req zone=api burst=20 nodelay;
    limit_conn addr 10;
    
    # VLESS Reality endpoint (hidden)
    location /api/v1/reality {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
    
    # gRPC endpoint
    location /grpc {
        grpc_pass grpc://127.0.0.1:8081;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto \$scheme;
        
        # gRPC specific settings
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
        client_body_timeout 60s;
        client_max_body_size 0;
    }
    
    # Default masking - proxy to real website
    location / {
        # Fallback to masking site
        proxy_pass https://$MASK_DOMAIN;
        proxy_ssl_server_name on;
        proxy_ssl_name $MASK_DOMAIN;
        proxy_set_header Host $MASK_DOMAIN;
        proxy_set_header User-Agent \$http_user_agent;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Accept-Encoding "";
        proxy_redirect off;
        
        # DNS resolver
        resolver 1.1.1.1 8.8.8.8 valid=300s;
        resolver_timeout 10s;
        
        # Caching for better performance
        proxy_cache_bypass \$http_pragma \$http_authorization;
        proxy_no_cache \$http_pragma \$http_authorization;
        
        # Timeout settings
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}

# Dedicated server for Reality masking on port 8003
server {
    listen 127.0.0.1:8003 ssl;
    server_name $MASK_DOMAIN;
    
    # Use real certificate for masking
    ssl_certificate /etc/ssl/private/${DOMAIN}.crt;
    ssl_certificate_key /etc/ssl/private/${DOMAIN}.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Proxy all traffic to the masking website
    location / {
        proxy_pass https://$MASK_DOMAIN;
        proxy_ssl_server_name on;
        proxy_ssl_name $MASK_DOMAIN;
        proxy_set_header Host $MASK_DOMAIN;
        proxy_set_header User-Agent \$http_user_agent;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        resolver 1.1.1.1 8.8.8.8;
        resolver_timeout 10s;
    }
}
EOF
    
    # Test nginx configuration
    if nginx -t; then
        log_success "Nginx 配置文件创建成功"
    else
        log_error "Nginx 配置文件测试失败"
        exit 1
    fi
}

# Configure Xray with proper Reality settings
configure_xray() {
    log_info "配置 Xray..."
    
    # Create Xray configuration with correct Reality settings
    cat > "$XRAY_CONF_PATH" << EOF
{
    "log": {
        "loglevel": "info",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "blocked"
            },
            {
                "type": "field", 
                "ip": ["geoip:cn"],
                "outboundTag": "blocked"
            },
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            },
            {
                "type": "field",
                "port": "443",
                "network": "udp",
                "outboundTag": "blocked"
            }
        ]
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 8080,
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
                    "serverNames": ["$MASK_DOMAIN"],
                    "privateKey": "$PRIVATE_KEY",
                    "shortIds": ["$SHORT_ID", ""]
                }
            }
        },
        {
            "listen": "127.0.0.1", 
            "port": 8081,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "grpc",
                    "multiMode": false
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct",
            "settings": {
                "domainStrategy": "UseIP"
            }
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ],
    "dns": {
        "servers": [
            "1.1.1.1",
            "8.8.8.8"
        ]
    }
}
EOF
    
    # Create log directory
    mkdir -p /var/log/xray
    chown nobody:nogroup /var/log/xray
    
    # Set proper permissions
    chmod 644 "$XRAY_CONF_PATH"
    
    log_success "Xray 配置文件创建成功"
}

# Setup SSL certificates
setup_ssl() {
    log_info "配置 SSL 证书..."
    
    # Set Cloudflare API token
    export CF_Token="$CF_API_TOKEN"
    
    # Create acme.sh config directory
    mkdir -p /root/.acme.sh
    
    # Issue certificate using DNS validation
    /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" \
        --key-file /etc/ssl/private/${DOMAIN}.key \
        --fullchain-file /etc/ssl/private/${DOMAIN}.crt \
        --reloadcmd "systemctl reload nginx" \
        --force
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/${DOMAIN}.key
    chmod 644 /etc/ssl/private/${DOMAIN}.crt
    
    log_success "SSL 证书配置完成"
}

# Configure firewall
configure_firewall() {
    log_info "配置防火墙..."
    
    # Reset UFW to default
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (be careful not to lock yourself out)
    ufw allow ssh
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 443/udp
    
    # Enable firewall
    ufw --force enable
    
    log_success "防火墙配置完成"
}

# Start services
start_services() {
    log_info "启动服务..."
    
    # Start and enable Nginx
    systemctl restart nginx
    systemctl enable nginx
    
    # Start and enable Xray
    systemctl restart xray
    systemctl enable xray
    
    # Wait a moment for services to start
    sleep 3
    
    # Check service status
    if systemctl is-active --quiet nginx && systemctl is-active --quiet xray; then
        log_success "所有服务启动成功"
    else
        log_error "部分服务启动失败"
        log_info "Nginx 状态: $(systemctl is-active nginx)"
        log_info "Xray 状态: $(systemctl is-active xray)"
        
        if ! systemctl is-active --quiet nginx; then
            log_error "Nginx 启动失败，查看详细信息:"
            systemctl status nginx --no-pager -l
        fi
        
        if ! systemctl is-active --quiet xray; then
            log_error "Xray 启动失败，查看详细信息:"
            systemctl status xray --no-pager -l
        fi
        
        exit 1
    fi
}

# Generate client configurations
generate_client_config() {
    log_info "生成客户端配置文件..."
    
    # Create client config directory
    mkdir -p /root/client-configs
    
    # Generate VLESS Reality config
    cat > /root/client-configs/vless-reality.json << EOF
{
    "remarks": "VLESS-Reality-${DOMAIN}",
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "$DOMAIN",
                        "port": 443,
                        "users": [
                            {
                                "id": "$UUID",
                                "flow": "xtls-rprx-vision",
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "$MASK_DOMAIN",
                    "fingerprint": "chrome",
                    "show": false,
                    "publicKey": "$PUBLIC_KEY",
                    "shortId": "$SHORT_ID"
                }
            }
        }
    ]
}
EOF
    
    # Generate VLESS gRPC config
    cat > /root/client-configs/vless-grpc.json << EOF
{
    "remarks": "VLESS-gRPC-${DOMAIN}",
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "$DOMAIN",
                        "port": 443,
                        "users": [
                            {
                                "id": "$UUID",
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "$DOMAIN",
                    "allowInsecure": false
                },
                "grpcSettings": {
                    "serviceName": "grpc",
                    "multiMode": false
                }
            }
        }
    ]
}
EOF
    
    # Generate share links
    local reality_link="vless://${UUID}@${DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${MASK_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#Reality-${DOMAIN}"
    local grpc_link="vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&type=grpc&serviceName=grpc&mode=gun#gRPC-${DOMAIN}"
    
    # Save share links
    echo "$reality_link" > /root/client-configs/reality-share-link.txt
    echo "$grpc_link" > /root/client-configs/grpc-share-link.txt
    
    # Generate QR codes if qrencode is available
    if command -v qrencode &> /dev/null; then
        qrencode -t ANSIUTF8 "$reality_link" > /root/client-configs/reality-qr.txt
        qrencode -t ANSIUTF8 "$grpc_link" > /root/client-configs/grpc-qr.txt
    fi
    
    # Set proper permissions
    chmod 600 /root/client-configs/*
    
    log_success "客户端配置文件生成完成"
}

# Save configuration for management
save_config() {
    cat > /root/.vless-config << EOF
DOMAIN="$DOMAIN"
EMAIL="$EMAIL"
UUID="$UUID"
PRIVATE_KEY="$PRIVATE_KEY"
PUBLIC_KEY="$PUBLIC_KEY"
SHORT_ID="$SHORT_ID"
MASK_DOMAIN="$MASK_DOMAIN"
INSTALL_DATE="$(date)"
EOF
    chmod 600 /root/.vless-config
}

# Display summary
display_summary() {
    log_success "安装配置完成！"
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                        配置信息汇总                                            ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} 域名:           $DOMAIN"
    echo -e "${CYAN}║${NC} UUID:             $UUID"
    echo -e "${CYAN}║${NC} 私钥:      $PRIVATE_KEY"
    echo -e "${CYAN}║${NC} 公钥:       $PUBLIC_KEY"
    echo -e "${CYAN}║${NC} Short ID:         $SHORT_ID"
    echo -e "${CYAN}║${NC} 伪装域名:         $MASK_DOMAIN"
    echo -e "${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} 客户端配置:   /root/client-configs/"
    echo -e "${CYAN}║${NC} Nginx 配置:     $NGINX_CONF_PATH"
    echo -e "${CYAN}║${NC} Xray 配置:      $XRAY_CONF_PATH"
    echo -e "${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} 服务状态:"
    echo -e "${CYAN}║${NC} - Nginx:          $(systemctl is-active nginx)"
    echo -e "${CYAN}║${NC} - Xray:           $(systemctl is-active xray)"
    echo -e "${CYAN}║${NC} - 防火墙:       $(ufw status | head -n1 | cut -d' ' -f2)"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}                                          分享链接                                               "
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Reality 链接:"
    echo -e "${GREEN}$(cat /root/client-configs/reality-share-link.txt)${NC}"
    echo -e "${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} gRPC 链接:"
    echo -e "${GREEN}$(cat /root/client-configs/grpc-share-link.txt)${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_info "配置文件已保存在 /root/client-configs/ 目录中"
    log_info "管理脚本: 再次运行此脚本进入管理菜单"
    log_info "日志文件: /var/log/xray/"
}

# ================================================================================
# MANAGEMENT FUNCTIONS
# ================================================================================

# Load existing configuration
load_config() {
    if [[ -f "/root/.vless-config" ]]; then
        source /root/.vless-config
        return 0
    else
        return 1
    fi
}

# Show current configuration
show_config() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                        当前配置信息                              ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} 域名:           $DOMAIN"
    echo -e "${CYAN}║${NC} UUID:             $UUID"
    echo -e "${CYAN}║${NC} 私钥:      $PRIVATE_KEY"
    echo -e "${CYAN}║${NC} 公钥:       $PUBLIC_KEY"
    echo -e "${CYAN}║${NC} Short ID:         $SHORT_ID"
    echo -e "${CYAN}║${NC} 伪装域名:         $MASK_DOMAIN"
    echo -e "${CYAN}║${NC} 安装日期:         $INSTALL_DATE"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${BLUE}服务状态:${NC}"
    echo "- Nginx: $(systemctl is-active nginx) ($(systemctl is-enabled nginx))"
    echo "- Xray: $(systemctl is-active xray) ($(systemctl is-enabled xray))"
    echo "- 防火墙: $(ufw status | head -n1 | cut -d' ' -f2)"
    echo ""
    
    echo -e "${BLUE}分享链接:${NC}"
    if [[ -f "/root/client-configs/reality-share-link.txt" ]]; then
        echo -e "${GREEN}Reality:${NC} $(cat /root/client-configs/reality-share-link.txt)"
    fi
    if [[ -f "/root/client-configs/grpc-share-link.txt" ]]; then
        echo -e "${GREEN}gRPC:${NC} $(cat /root/client-configs/grpc-share-link.txt)"
    fi
}

# Change UUID
change_uuid() {
    log_info "更换 UUID..."
    
    # Generate new UUID
    local new_uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # Update Xray config
    sed -i "s/\"id\": \"$UUID\"/\"id\": \"$new_uuid\"/g" "$XRAY_CONF_PATH"
    
    # Update saved config
    sed -i "s/UUID=\"$UUID\"/UUID=\"$new_uuid\"/" /root/.vless-config
    
    # Update global variable
    UUID="$new_uuid"
    
    # Restart Xray
    systemctl restart xray
    
    # Regenerate client configs
    generate_client_config
    
    log_success "UUID 已更换为: $new_uuid"
    log_info "Xray 服务已重启，新的配置文件已生成"
}

# Change Reality keys
change_reality_keys() {
    log_info "更换 Reality 密钥对..."
    
    # Generate new key pair
    local keypair=$(/usr/local/bin/xray x25519)
    local new_private_key=$(echo "$keypair" | grep "Private key:" | cut -d' ' -f3)
    local new_public_key=$(echo "$keypair" | grep "Public key:" | cut -d' ' -f3)
    
    # Update Xray config
    sed -i "s/\"privateKey\": \"$PRIVATE_KEY\"/\"privateKey\": \"$new_private_key\"/" "$XRAY_CONF_PATH"
    
    # Update saved config
    sed -i "s/PRIVATE_KEY=\"$PRIVATE_KEY\"/PRIVATE_KEY=\"$new_private_key\"/" /root/.vless-config
    sed -i "s/PUBLIC_KEY=\"$PUBLIC_KEY\"/PUBLIC_KEY=\"$new_public_key\"/" /root/.vless-config
    
    # Update global variables
    PRIVATE_KEY="$new_private_key"
    PUBLIC_KEY="$new_public_key"
    
    # Restart Xray
    systemctl restart xray
    
    # Regenerate client configs
    generate_client_config
    
    log_success "Reality 密钥对已更换"
    log_info "新私钥: $new_private_key"
    log_info "新公钥: $new_public_key"
    log_info "Xray 服务已重启，新的配置文件已生成"
}

# Restart Xray service
restart_xray() {
    log_info "重启 Xray 服务..."
    
    systemctl restart xray
    sleep 2
    
    if systemctl is-active --quiet xray; then
        log_success "Xray 服务重启成功"
    else
        log_error "Xray 服务重启失败"
        systemctl status xray --no-pager -l
    fi
}

# Show Xray logs
show_xray_logs() {
    echo -e "${BLUE}实时 Xray 日志 (按 Ctrl+C 退出):${NC}"
    echo "----------------------------------------"
    journalctl -u xray -f --no-pager
}

# Uninstall Xray
uninstall_xray() {
    echo -e "${RED}警告: 这将完全删除 Xray 和相关配置文件！${NC}"
    read -p "您确定要卸载吗？(输入 'yes' 确认): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        log_info "卸载操作已取消"
        return
    fi
    
    log_info "开始卸载 Xray..."
    
    # Stop services
    systemctl stop xray nginx
    systemctl disable xray nginx
    
    # Remove Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
    
    # Remove configuration files
    rm -rf /usr/local/etc/xray
    rm -rf /var/log/xray
    rm -rf /root/client-configs
    rm -f /root/.vless-config
    
    # Remove Nginx config
    rm -f "$NGINX_CONF_PATH"
    
    # Remove SSL certificates
    rm -rf /etc/ssl/private/${DOMAIN}.*
    
    # Reset firewall
    ufw --force reset
    ufw --force disable
    
    log_success "Xray 卸载完成"
}

# Management menu
show_management_menu() {
    while true; do
        clear
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    VLESS 管理面板                               ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║${NC}  1. 查看配置信息"
        echo -e "${CYAN}║${NC}  2. 更换 VLESS UUID"
        echo -e "${CYAN}║${NC}  3. 更换 REALITY 密钥对"
        echo -e "${CYAN}║${NC}  4. 重启 Xray 服务"
        echo -e "${CYAN}║${NC}  5. 查看 Xray 实时日志"
        echo -e "${CYAN}║${NC}  6. 卸载 Xray"
        echo -e "${CYAN}║${NC}  7. 退出管理面板"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "请选择操作 [1-7]: " choice
        
        case $choice in
            1)
                show_config
                read -p "按回车键继续..."
                ;;
            2)
                change_uuid
                read -p "按回车键继续..."
                ;;
            3)
                change_reality_keys
                read -p "按回车键继续..."
                ;;
            4)
                restart_xray
                read -p "按回车键继续..."
                ;;
            5)
                show_xray_logs
                ;;
            6)
                uninstall_xray
                read -p "按回车键继续..."
                ;;
            7)
                log_info "退出管理面板"
                exit 0
                ;;
            *)
                log_error "无效选择，请输入 1-7"
                sleep 2
                ;;
        esac
    done
}

# ================================================================================
# MAIN EXECUTION
# ================================================================================

# Main execution function
main() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              VLESS-gRPC-REALITY 增强版安装脚本                  ║"
    echo "║                        Version 2.0                            ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_privileges
    
    # Check if already installed
    if load_config; then
        log_info "检测到已安装的配置"
        echo ""
        echo "检测到现有安装，您想要："
        echo "1. 进入管理菜单"
        echo "2. 重新安装 (将删除现有配置)"
        echo "3. 退出"
        echo ""
        read -p "请选择 [1-3]: " choice
        
        case $choice in
            1)
                show_management_menu
                ;;
            2)
                log_warn "将重新安装并覆盖现有配置"
                read -p "确认继续？(y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    rm -f /root/.vless-config
                else
                    exit 0
                fi
                ;;
            3)
                exit 0
                ;;
            *)
                log_error "无效选择"
                exit 1
                ;;
        esac
    fi
    
    log_info "开始 VLESS-gRPC-REALITY 安装配置..."
    
    check_system_requirements
    get_user_input
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
    save_config
    display_summary
    
    echo ""
    read -p "安装完成！是否进入管理菜单？(Y/n): " enter_menu
    if [[ ! "$enter_menu" =~ ^[Nn]$ ]]; then
        show_management_menu
    fi
    
    log_success "脚本执行完成！"
}

# Run main function
main "$@"