#!/bin/bash
#
# Title:         VLESS-gRPC-REALITY Setup Script
# Author:        AI DevOps Expert
# Description:   Automates the setup of a secure VLESS+Reality proxy on Debian/Ubuntu
# Version:       1.0.0
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
DOMAIN=""
EMAIL=""
CF_API_TOKEN=""
MASK_DOMAIN=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""
NGINX_CONF_PATH="/etc/nginx/sites-available/default"
XRAY_CONF_PATH="/usr/local/etc/xray/config.json"
TEMP_DIR="/tmp/vless-setup"
SCRIPT_VERSION="2.1.0"

# Cleanup function
cleanup() {
    local exit_code=$?
    echo -e "${YELLOW}[CLEANUP]${NC} Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Script failed with exit code $exit_code"
        echo -e "${YELLOW}[INFO]${NC} Check the logs above for detailed error information"
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

# Check if running as root
check_privileges() {
    log_info "Checking privileges..."
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    log_success "Running as root"
}

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check if running on Debian/Ubuntu
    if ! command -v apt &> /dev/null; then
        log_error "This script requires a Debian/Ubuntu system"
        exit 1
    fi
    
    # Check system architecture
    local arch=$(uname -m)
    if [[ ! "$arch" =~ ^(x86_64|amd64|aarch64|arm64)$ ]]; then
        log_error "Unsupported architecture: $arch"
        exit 1
    fi
    
    log_success "System requirements met"
}

# Validate domain format
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
    log_info "正在收集配置参数..."
    
    echo -e "${BLUE}[说明]${NC} 请准备以下信息："
    echo "  1. 您在 Cloudflare 中配置的域名 (非伪装域名)"
    echo "  2. 用于申请 SSL 证书的邮箱地址"
    echo "  3. Cloudflare API Token (用于自动申请和续期 SSL 证书)"
    echo "     - 需要具备 Zone:DNS:Edit 权限"
    echo "     - 用于通过 DNS 验证方式申请 Let's Encrypt 证书"
    echo "  4. 伪装域名 (用于 Reality 流量伪装，提高安全性)"
    echo ""
    
    # Get domain
    while true; do
        read -p "请输入您的域名 (例如: example.com, test.cn): " DOMAIN
        if validate_domain "$DOMAIN"; then
            log_info "将为域名 $DOMAIN 配置 VLESS 代理服务"
            break
        else
            log_error "域名格式无效，请输入有效的域名格式"
        fi
    done
    
    # Get email
    while true; do
        read -p "请输入您的邮箱地址 (用于 SSL 证书申请): " EMAIL
        if validate_email "$EMAIL"; then
            break
        else
            log_error "邮箱格式无效，请输入有效的邮箱地址"
        fi
    done
    
    # Get Cloudflare API token
    while true; do
        read -p "请输入您的 Cloudflare API Token (明文显示): " CF_API_TOKEN
        if [[ -n "$CF_API_TOKEN" && ${#CF_API_TOKEN} -gt 10 ]]; then
            break
        else
            log_error "API Token 无效，请输入有效的 Cloudflare API Token"
        fi
    done
    
    # Get mask domain
    echo ""
    echo -e "${BLUE}[伪装域名配置]${NC}"
    echo "伪装域名用于 Reality 协议的流量伪装，建议使用知名网站域名"
    echo "推荐选项："
    echo "  1. www.kcrw.com (推荐)"
    echo "  2. www.lovelive-anime.jp"
    echo "  3. 自定义域名"
    echo ""
    
    while true; do
        read -p "请选择伪装域名 [1-3]: " mask_choice
        case $mask_choice in
            1)
                MASK_DOMAIN="www.kcrw.com"
                break
                ;;
            2)
                MASK_DOMAIN="www.lovelive-anime.jp"
                break
                ;;
            3)
                while true; do
                    read -p "请输入自定义伪装域名 (例如: www.example.com): " MASK_DOMAIN
                    if validate_domain "$MASK_DOMAIN"; then
                        # Test if the domain is accessible
                        if curl -I "https://$MASK_DOMAIN" --connect-timeout 10 --max-time 15 &>/dev/null; then
                            log_success "伪装域名 $MASK_DOMAIN 可访问"
                            break 2
                        else
                            log_warn "伪装域名 $MASK_DOMAIN 无法访问，建议选择其他域名"
                            read -p "是否继续使用此域名？(y/N): " continue_choice
                            if [[ "$continue_choice" =~ ^[Yy]$ ]]; then
                                break 2
                            fi
                        fi
                    else
                        log_error "域名格式无效，请输入有效的域名格式"
                    fi
                done
                ;;
            *)
                log_error "无效选择，请输入 1-3"
                ;;
        esac
    done
    
    log_info "选择的伪装域名: $MASK_DOMAIN"
    
    log_success "配置参数收集完成"
}

# Update system packages
update_system() {
    log_info "正在更新系统软件包..."
    
    # Check if update is needed (idempotency)
    if [[ -f "/var/log/vless-setup-updated" ]]; then
        log_info "系统已经更新，跳过..."
        return 0
    fi
    
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y
    apt install -y curl wget unzip sudo ufw jq openssl socat cron
    
    # Mark as updated
    touch "/var/log/vless-setup-updated"
    log_success "系统软件包更新完成"
}

# Install Nginx
install_nginx() {
    log_info "正在安装 Nginx..."
    
    # Check if already installed
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Nginx 已经安装并运行"
        return 0
    fi
    
    apt install -y nginx
    systemctl enable nginx
    log_success "Nginx 安装完成"
}

# Install Xray
install_xray() {
    log_info "正在安装 Xray..."
    
    # Check if already installed
    if [[ -f "/usr/local/bin/xray" ]]; then
        log_info "Xray 已经安装"
        return 0
    fi
    
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    log_success "Xray 安装完成"
}

# Install ACME.sh
install_acme() {
    log_info "正在安装 ACME.sh..."
    
    # Check if already installed
    if [[ -f "/root/.acme.sh/acme.sh" ]]; then
        log_info "ACME.sh 已经安装"
        return 0
    fi
    
    curl https://get.acme.sh | sh -s email="$EMAIL"
    source ~/.bashrc
    log_success "ACME.sh 安装完成"
}

# Generate cryptographic keys
generate_keys() {
    log_info "正在生成加密密钥..."
    
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
    
    log_success "加密密钥生成完成"
}

# Configure Nginx
configure_nginx() {
    log_info "正在配置 Nginx..."
    
    # Create SSL directory
    mkdir -p /etc/ssl/private
    
    # Generate Nginx configuration
    cat > "$NGINX_CONF_PATH" << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/ssl/private/${DOMAIN}.crt;
    ssl_certificate_key /etc/ssl/private/${DOMAIN}.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
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
    
    # Block direct access to Reality (should not be accessible via HTTP)
    location ~ ^/(reality|vless|trojan) {
        return 404;
    }
    
    # gRPC endpoint
    location /grpc {
        grpc_pass grpc://127.0.0.1:8081;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Default masking - proxy to mask domain
    location / {
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
    }
}

# Dedicated server for Reality masking on port 8003
server {
    listen 127.0.0.1:8003 ssl;
    server_name $DOMAIN;
    
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
    
    # Test nginx configuration (skip if SSL certificates don't exist yet)
    if [[ -f "/etc/ssl/private/${DOMAIN}.crt" && -f "/etc/ssl/private/${DOMAIN}.key" ]]; then
        if nginx -t; then
            log_success "Nginx 配置文件创建成功"
        else
            log_error "Nginx 配置文件测试失败"
            exit 1
        fi
    else
        log_info "SSL 证书文件尚未生成，跳过 Nginx 配置测试"
        log_success "Nginx 配置文件创建成功"
    fi
}

# Configure Xray
configure_xray() {
    log_info "正在配置 Xray..."
    
    # Create Xray configuration
    cat > "$XRAY_CONF_PATH" << EOF
{
    "log": {
        "loglevel": "warning",
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
                "domain": ["geosite:cn"],
                "outboundTag": "direct"
            },
            {
                "type": "field",
                "ip": ["geoip:cn"],
                "outboundTag": "direct"
            },
            {
                "type": "field",
                "port": "443",
                "network": "udp",
                "outboundTag": "blocked"
            },
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            }
        ]
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
                    "xver": 0,
                    "serverNames": ["$DOMAIN"],
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
                    "serviceName": "grpc"
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
            "8.8.8.8",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888"
        ],
        "queryStrategy": "UseIP",
        "disableCache": false,
        "disableFallback": false
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
    log_info "正在配置 SSL 证书..."
    
    # Check if certificates already exist and are valid
    if [[ -f "/etc/ssl/private/${DOMAIN}.crt" && -f "/etc/ssl/private/${DOMAIN}.key" ]]; then
        # Check certificate expiry (more than 30 days remaining)
        if openssl x509 -checkend 2592000 -noout -in "/etc/ssl/private/${DOMAIN}.crt" 2>/dev/null; then
            log_info "SSL 证书已存在且有效，跳过申请"
            log_success "SSL 证书配置完成"
            return 0
        else
            log_warn "SSL 证书即将到期或已过期，重新申请..."
        fi
    fi
    
    # Set Cloudflare API token
    export CF_Token="$CF_API_TOKEN"
    
    # Issue or renew certificate with explicit error handling
    log_info "正在申请/更新 SSL 证书..."
    
    # Temporarily disable error exit to handle ACME.sh return codes
    set +e
    /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --key-file /etc/ssl/private/${DOMAIN}.key --fullchain-file /etc/ssl/private/${DOMAIN}.crt --reloadcmd "systemctl reload nginx"
    local acme_exit_code=$?
    set -e
    
    # Handle different ACME.sh exit codes
    case $acme_exit_code in
        0)
            log_success "SSL 证书申请成功"
            ;;
        2)
            log_info "SSL 证书已存在且有效，无需重新申请"
            # Try to install existing certificate if files don't exist
            if [[ ! -f "/etc/ssl/private/${DOMAIN}.crt" ]]; then
                log_info "安装现有证书到指定路径..."
                /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --key-file /etc/ssl/private/${DOMAIN}.key --fullchain-file /etc/ssl/private/${DOMAIN}.crt --reloadcmd "systemctl reload nginx"
            fi
            ;;
        *)
            log_error "SSL 证书申请失败，退出码: $acme_exit_code"
            exit 1
            ;;
    esac
    
    # Ensure certificate files exist
    if [[ ! -f "/etc/ssl/private/${DOMAIN}.crt" || ! -f "/etc/ssl/private/${DOMAIN}.key" ]]; then
        log_error "SSL 证书文件不存在，无法继续"
        exit 1
    fi
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/${DOMAIN}.key
    chmod 644 /etc/ssl/private/${DOMAIN}.crt
    
    log_success "SSL 证书配置完成"
}

# Configure firewall
configure_firewall() {
    log_info "正在配置防火墙..."
    
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
    
    # Enable firewall
    ufw --force enable
    
    log_success "防火墙配置完成"
}

# Start services
start_services() {
    log_info "正在启动服务..."
    
    # Verify SSL certificates exist before starting Nginx
    if [[ ! -f "/etc/ssl/private/${DOMAIN}.crt" || ! -f "/etc/ssl/private/${DOMAIN}.key" ]]; then
        log_error "SSL 证书文件不存在，无法启动 Nginx"
        log_error "证书路径: /etc/ssl/private/${DOMAIN}.crt"
        log_error "私钥路径: /etc/ssl/private/${DOMAIN}.key"
        exit 1
    fi
    
    # Test nginx configuration before restart
    if ! nginx -t; then
        log_error "Nginx 配置文件测试失败"
        exit 1
    fi
    
    # Gracefully reload Nginx (faster and safer than restart)
    if systemctl is-active --quiet nginx; then
        log_info "Nginx 已运行，执行优雅重载..."
        systemctl reload nginx
    else
        log_info "Nginx 未运行，启动服务..."
        systemctl start nginx
    fi
    systemctl enable nginx
    
    # Restart Xray (configuration changes require restart)
    log_info "重启 Xray 服务..."
    systemctl restart xray
    systemctl enable xray
    
    # Wait for services to stabilize
    sleep 3
    
    # Check service status
    if systemctl is-active --quiet nginx && systemctl is-active --quiet xray; then
        log_success "所有服务启动成功"
    else
        log_error "部分服务启动失败"
        systemctl status nginx --no-pager
        systemctl status xray --no-pager
        exit 1
    fi
}

# Generate client configurations
generate_client_config() {
    log_info "正在生成客户端配置文件..."
    
    # Create client config directory
    mkdir -p /root/client-configs
    
    # Generate VLESS Reality config
    cat > /root/client-configs/vless-reality.json << EOF
{
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
                    "serverName": "$DOMAIN",
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
                    "serviceName": "grpc"
                }
            }
        }
    ]
}
EOF
    
    # Generate share links
    local reality_link="vless://${UUID}@${DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#Reality-${DOMAIN}"
    local grpc_link="vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&type=grpc&serviceName=grpc&mode=gun#gRPC-${DOMAIN}"
    
    # Save share links
    echo "$reality_link" > /root/client-configs/reality-share-link.txt
    echo "$grpc_link" > /root/client-configs/grpc-share-link.txt
    
    # Set proper permissions
    chmod 600 /root/client-configs/*
    
    log_success "Client configurations generated"
}

# Display summary
display_summary() {
    log_success "安装配置完成！"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                        配置信息汇总                                            ║"
    echo "╠════════════════════════════════════════════════════════════════════════════════════════════════╣"
    echo "║ 域名:           $DOMAIN"
    echo "║ 伪装域名:         $MASK_DOMAIN"
    echo "║ UUID:             $UUID"
    echo "║ 私钥:      $PRIVATE_KEY"
    echo "║ 公钥:       $PUBLIC_KEY"
    echo "║ Short ID:         $SHORT_ID"
    echo "║"
    echo "║ 客户端配置:   /root/client-configs/"
    echo "║ Nginx 配置:     $NGINX_CONF_PATH"
    echo "║ Xray 配置:      $XRAY_CONF_PATH"
    echo "║"
    echo "║ 服务状态:"
    echo "║ - Nginx:          $(systemctl is-active nginx)"
    echo "║ - Xray:           $(systemctl is-active xray)"
    echo "║ - 防火墙:       $(ufw status | head -n1 | cut -d' ' -f2)"
    echo "╠════════════════════════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                          分享链接                                               ║"
    echo "╠════════════════════════════════════════════════════════════════════════════════════════════════╣"
    echo "║ Reality 链接:     $(cat /root/client-configs/reality-share-link.txt)"
    echo "║"
    echo "║ gRPC 链接:        $(cat /root/client-configs/grpc-share-link.txt)"
    echo "╚════════════════════════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    log_info "配置文件已保存在 /root/client-configs/ 目录中"
    log_info "如需技术支持和故障排查，请检查 /var/log/xray/ 中的日志文件"
    echo ""
    
    # Ask if user wants to enter management menu
    read -p "是否进入管理菜单？(Y/n): " enter_menu
    if [[ ! "$enter_menu" =~ ^[Nn]$ ]]; then
        show_management_menu
    fi
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

# Save configuration for management
save_config() {
    cat > /root/.vless-config << EOF
DOMAIN="$DOMAIN"
EMAIL="$EMAIL"
MASK_DOMAIN="$MASK_DOMAIN"
UUID="$UUID"
PRIVATE_KEY="$PRIVATE_KEY"
PUBLIC_KEY="$PUBLIC_KEY"
SHORT_ID="$SHORT_ID"
INSTALL_DATE="$(date)"
EOF
    chmod 600 /root/.vless-config
}

# Delete all configurations and files
delete_configuration() {
    echo -e "${RED}⚠️  警告：删除配置操作${NC}"
    echo "此操作将完全删除以下内容："
    echo "  1. Xray 服务和配置文件"
    echo "  2. Nginx VLESS 相关配置"
    echo "  3. SSL 证书文件"
    echo "  4. 客户端配置文件"
    echo "  5. 防火墙规则"
    echo "  6. 系统服务配置"
    echo ""
    echo -e "${YELLOW}注意：此操作不可逆！${NC}"
    echo ""
    
    # 三重确认
    read -p "确认删除所有配置？请输入 'DELETE' (大写): " confirm1
    if [[ "$confirm1" != "DELETE" ]]; then
        log_info "操作已取消"
        return 0
    fi
    
    read -p "再次确认删除？请输入您的域名 '$DOMAIN': " confirm2
    if [[ "$confirm2" != "$DOMAIN" ]]; then
        log_error "域名输入不匹配，操作已取消"
        return 1
    fi
    
    read -p "最后确认：确定要删除所有配置吗？(yes/no): " confirm3
    if [[ "$confirm3" != "yes" ]]; then
        log_info "操作已取消"
        return 0
    fi
    
    log_info "开始删除配置..."
    
    # 停止服务
    log_info "停止相关服务..."
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    
    # 删除 Xray
    log_info "删除 Xray..."
    if command -v /usr/local/bin/xray &> /dev/null; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null || true
    fi
    
    # 删除配置文件
    log_info "删除配置文件..."
    rm -rf /usr/local/etc/xray 2>/dev/null || true
    rm -rf /var/log/xray 2>/dev/null || true
    rm -rf /root/client-configs 2>/dev/null || true
    rm -f /root/.vless-config 2>/dev/null || true
    
    # 备份并恢复默认 Nginx 配置
    log_info "恢复 Nginx 默认配置..."
    if [[ -f "/etc/nginx/sites-available/default" ]]; then
        cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.vless.backup.$(date +%Y%m%d_%H%M%S)
        cat > /etc/nginx/sites-available/default << 'EOF'
##
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# https://www.nginx.com/resources/wiki/start/
# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
# https://wiki.debian.org/Nginx/DirectoryStructure
#
# In most cases, administrators will remove this file from sites-enabled/ and
# leave it as reference inside of sites-available where it will continue to be
# updated by the nginx packaging team.
#
# This file will automatically load configuration files provided by other
# applications, such as Drupal or Wordpress. These applications will be made
# available underneath a path with that package name, such as /drupal8.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

# Default server configuration
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}
}
EOF
    fi
    
    # 删除 SSL 证书
    log_info "删除 SSL 证书..."
    if [[ -n "$DOMAIN" ]]; then
        rm -f /etc/ssl/private/${DOMAIN}.* 2>/dev/null || true
        # 删除 ACME 证书
        if [[ -d "/root/.acme.sh" ]]; then
            /root/.acme.sh/acme.sh --remove -d "$DOMAIN" 2>/dev/null || true
        fi
    fi
    
    # 重置防火墙
    log_info "重置防火墙配置..."
    ufw --force reset 2>/dev/null || true
    ufw default deny incoming 2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true
    ufw allow ssh 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    
    # 删除安装标记
    rm -f /var/log/vless-setup-updated 2>/dev/null || true
    
    # 重启 Nginx 应用默认配置
    if systemctl is-active --quiet nginx; then
        nginx -t && systemctl reload nginx || log_warn "Nginx 配置测试失败，请手动检查"
    else
        systemctl start nginx 2>/dev/null || true
    fi
    
    log_success "配置删除完成！"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                        删除完成报告                              ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║ ✅ Xray 服务已删除"
    echo "║ ✅ 配置文件已清理"
    echo "║ ✅ SSL 证书已删除"
    echo "║ ✅ 防火墙已重置为默认状态"
    echo "║ ✅ Nginx 已恢复默认配置"
    echo "║"
    echo "║ 📁 备份文件位置："
    echo "║   - Nginx 配置备份: /etc/nginx/sites-available/default.vless.backup.*"
    echo "║"
    echo "║ 🔧 如需重新安装，请重新运行此脚本"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
}

# Firewall port management
manage_firewall() {
    while true; do
        clear
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║                        防火墙端口管理                            ║"
        echo "╠════════════════════════════════════════════════════════════════╣"
        
        # 显示当前防火墙状态
        local ufw_status=$(ufw status 2>/dev/null || echo "inactive")
        echo "║ 防火墙状态: $ufw_status"
        echo "║"
        
        if [[ "$ufw_status" != "inactive" ]]; then
            echo "║ 当前开放的端口:"
            ufw status numbered 2>/dev/null | grep -E "^\[[0-9]+\]" | while read line; do
                echo "║   $line"
            done | head -10
            if [[ $(ufw status numbered 2>/dev/null | grep -c "^\[[0-9]+\]") -gt 10 ]]; then
                echo "║   ... (更多端口，使用查看详情功能查看完整列表)"
            fi
        else
            echo "║ 防火墙未启用"
        fi
        
        echo "║"
        echo "║ 可用操作:"
        echo "║  1. 查看详细防火墙状态"
        echo "║  2. 开放端口"
        echo "║  3. 关闭端口"
        echo "║  4. 启用/禁用防火墙"
        echo "║  5. 重置防火墙为默认安全配置"
        echo "║  6. 添加IP白名单"
        echo "║  7. 删除防火墙规则"
        echo "║  8. 返回主菜单"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo ""
        
        read -p "请选择操作 [1-8]: " fw_choice
        
        case $fw_choice in
            1)
                echo ""
                echo "=== 详细防火墙状态 ==="
                ufw status verbose 2>/dev/null || echo "防火墙未启用"
                echo ""
                echo "=== 端口监听状态 ==="
                ss -tlnp | grep -E ":(22|80|443|8080|8081|8003)" || echo "未发现常用端口监听"
                echo ""
                read -p "按回车键继续..."
                ;;
            2)
                echo ""
                echo "开放端口选项:"
                echo "1. HTTP (80/tcp)"
                echo "2. HTTPS (443/tcp)"
                echo "3. SSH (22/tcp)"
                echo "4. 自定义端口"
                echo ""
                read -p "请选择 [1-4]: " port_choice
                
                case $port_choice in
                    1)
                        ufw allow 80/tcp
                        log_success "HTTP 端口 (80) 已开放"
                        ;;
                    2)
                        ufw allow 443/tcp
                        log_success "HTTPS 端口 (443) 已开放"
                        ;;
                    3)
                        ufw allow ssh
                        log_success "SSH 端口已开放"
                        ;;
                    4)
                        read -p "请输入端口号: " custom_port
                        read -p "协议 (tcp/udp/both) [tcp]: " protocol
                        protocol=${protocol:-tcp}
                        
                        if [[ "$protocol" == "both" ]]; then
                            ufw allow $custom_port
                        else
                            ufw allow $custom_port/$protocol
                        fi
                        log_success "端口 $custom_port/$protocol 已开放"
                        ;;
                    *)
                        log_error "无效选择"
                        ;;
                esac
                read -p "按回车键继续..."
                ;;
            3)
                echo ""
                echo "当前防火墙规则:"
                ufw status numbered 2>/dev/null || echo "防火墙未启用"
                echo ""
                read -p "请输入要删除的规则编号 (或输入端口号): " rule_input
                
                if [[ "$rule_input" =~ ^[0-9]+$ ]] && [[ ${#rule_input} -le 2 ]]; then
                    # 规则编号
                    echo "y" | ufw delete $rule_input 2>/dev/null && log_success "规则已删除" || log_error "删除失败"
                else
                    # 端口号
                    ufw delete allow $rule_input 2>/dev/null && log_success "端口 $rule_input 已关闭" || log_error "关闭失败"
                fi
                read -p "按回车键继续..."
                ;;
            4)
                if ufw status | grep -q "Status: active"; then
                    read -p "确认禁用防火墙？(y/N): " disable_confirm
                    if [[ "$disable_confirm" =~ ^[Yy]$ ]]; then
                        ufw disable
                        log_success "防火墙已禁用"
                    fi
                else
                    ufw enable
                    log_success "防火墙已启用"
                fi
                read -p "按回车键继续..."
                ;;
            5)
                echo ""
                echo -e "${RED}警告：这将重置所有防火墙规则！${NC}"
                read -p "确认重置防火墙？(y/N): " reset_confirm
                if [[ "$reset_confirm" =~ ^[Yy]$ ]]; then
                    ufw --force reset
                    ufw default deny incoming
                    ufw default allow outgoing
                    ufw allow ssh
                    ufw --force enable
                    log_success "防火墙已重置为默认安全配置"
                fi
                read -p "按回车键继续..."
                ;;
            6)
                echo ""
                read -p "请输入要加入白名单的IP地址: " whitelist_ip
                if [[ -n "$whitelist_ip" ]]; then
                    ufw allow from $whitelist_ip
                    log_success "IP $whitelist_ip 已加入白名单"
                fi
                read -p "按回车键继续..."
                ;;
            7)
                echo ""
                echo "当前防火墙规则:"
                ufw status numbered 2>/dev/null || echo "防火墙未启用"
                echo ""
                read -p "请输入要删除的规则编号: " del_rule
                if [[ "$del_rule" =~ ^[0-9]+$ ]]; then
                    echo "y" | ufw delete $del_rule 2>/dev/null && log_success "规则已删除" || log_error "删除失败"
                fi
                read -p "按回车键继续..."
                ;;
            8)
                return 0
                ;;
            *)
                log_error "无效选择，请输入 1-8"
                sleep 2
                ;;
        esac
    done
}

# Show current configuration
show_config() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                        当前配置信息                              ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║ 域名:           $DOMAIN"
    echo "║ 伪装域名:         $MASK_DOMAIN"
    echo "║ UUID:             $UUID"
    echo "║ 私钥:      $PRIVATE_KEY"
    echo "║ 公钥:       $PUBLIC_KEY"
    echo "║ Short ID:         $SHORT_ID"
    echo "║ 安装日期:         $INSTALL_DATE"
    echo "╚════════════════════════════════════════════════════════════════╝"
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
    
    # Check if jq is available for safer JSON editing
    if command -v jq &> /dev/null; then
        # Use jq for safer JSON manipulation
        local temp_file=$(mktemp)
        jq --arg new_uuid "$new_uuid" '(.inbounds[].settings.clients[].id) = $new_uuid' "$XRAY_CONF_PATH" > "$temp_file" && mv "$temp_file" "$XRAY_CONF_PATH"
    else
        # Fallback to sed
        sed -i "s/\"id\": \"$UUID\"/\"id\": \"$new_uuid\"/g" "$XRAY_CONF_PATH"
    fi
    
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
    if command -v jq &> /dev/null; then
        local temp_file=$(mktemp)
        jq --arg private_key "$new_private_key" '(.inbounds[0].streamSettings.realitySettings.privateKey) = $private_key' "$XRAY_CONF_PATH" > "$temp_file" && mv "$temp_file" "$XRAY_CONF_PATH"
    else
        sed -i "s/\"privateKey\": \"$PRIVATE_KEY\"/\"privateKey\": \"$new_private_key\"/" "$XRAY_CONF_PATH"
    fi
    
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

# Change mask domain
change_mask_domain() {
    log_info "更换伪装域名..."
    
    echo "当前伪装域名: $MASK_DOMAIN"
    echo ""
    echo "推荐伪装域名："
    echo "  1. www.kcrw.com"
    echo "  2. www.lovelive-anime.jp"
    echo "  3. www.microsoft.com"
    echo "  4. 自定义域名"
    echo ""
    
    local new_mask_domain=""
    while true; do
        read -p "请选择伪装域名 [1-4]: " mask_choice
        case $mask_choice in
            1)
                new_mask_domain="www.kcrw.com"
                break
                ;;
            2)
                new_mask_domain="www.lovelive-anime.jp"
                break
                ;;
            3)
                new_mask_domain="www.microsoft.com"
                break
                ;;
            4)
                while true; do
                    read -p "请输入自定义伪装域名: " new_mask_domain
                    if validate_domain "$new_mask_domain"; then
                        if curl -I "https://$new_mask_domain" --connect-timeout 10 --max-time 15 &>/dev/null; then
                            log_success "伪装域名 $new_mask_domain 可访问"
                            break 2
                        else
                            log_warn "伪装域名 $new_mask_domain 无法访问，建议选择其他域名"
                            read -p "是否继续使用此域名？(y/N): " continue_choice
                            if [[ "$continue_choice" =~ ^[Yy]$ ]]; then
                                break 2
                            fi
                        fi
                    else
                        log_error "域名格式无效"
                    fi
                done
                ;;
            *)
                log_error "无效选择，请输入 1-4"
                ;;
        esac
    done
    
    # Update Xray config
    if command -v jq &> /dev/null; then
        local temp_file=$(mktemp)
        jq --arg mask_domain "$new_mask_domain" '(.inbounds[0].streamSettings.realitySettings.serverNames) = [$mask_domain]' "$XRAY_CONF_PATH" > "$temp_file" && mv "$temp_file" "$XRAY_CONF_PATH"
    else
        sed -i "s/\"serverNames\": \\[\"$MASK_DOMAIN\"\\]/\"serverNames\": [\"$new_mask_domain\"]/" "$XRAY_CONF_PATH"
    fi
    
    # Update Nginx config
    sed -i "s/$MASK_DOMAIN/$new_mask_domain/g" "$NGINX_CONF_PATH"
    
    # Update saved config
    sed -i "s/MASK_DOMAIN=\"$MASK_DOMAIN\"/MASK_DOMAIN=\"$new_mask_domain\"/" /root/.vless-config
    
    # Update global variable
    MASK_DOMAIN="$new_mask_domain"
    
    # Restart services
    systemctl restart nginx xray
    
    # Regenerate client configs
    generate_client_config
    
    log_success "伪装域名已更换为: $new_mask_domain"
    log_info "Nginx 和 Xray 服务已重启，新的配置文件已生成"
}

# Run connection diagnostics
run_connection_test() {
    log_info "运行连接诊断..."
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                        连接诊断报告                              ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    
    # Check services
    echo "║ 服务状态检查:"
    echo "║ - Nginx: $(systemctl is-active nginx) ($(systemctl is-enabled nginx))"
    echo "║ - Xray: $(systemctl is-active xray) ($(systemctl is-enabled xray))"
    
    # Check ports
    echo "║"
    echo "║ 端口监听检查:"
    if ss -tlnp | grep -q ":443"; then
        echo "║ - 443/tcp: ✓ 正在监听"
    else
        echo "║ - 443/tcp: ✗ 未监听"
    fi
    
    if ss -tlnp | grep -q "127.0.0.1:8080"; then
        echo "║ - 8080/tcp (Reality): ✓ 正在监听"
    else
        echo "║ - 8080/tcp (Reality): ✗ 未监听"
    fi
    
    if ss -tlnp | grep -q "127.0.0.1:8081"; then
        echo "║ - 8081/tcp (gRPC): ✓ 正在监听"
    else
        echo "║ - 8081/tcp (gRPC): ✗ 未监听"
    fi
    
    if ss -tlnp | grep -q "127.0.0.1:8003"; then
        echo "║ - 8003/tcp (伪装): ✓ 正在监听"
    else
        echo "║ - 8003/tcp (伪装): ✗ 未监听"
    fi
    
    # Check firewall
    echo "║"
    echo "║ 防火墙检查:"
    local ufw_status=$(ufw status | head -n1 | cut -d' ' -f2)
    echo "║ - UFW: $ufw_status"
    if ufw status | grep -q "443"; then
        echo "║ - 443端口: ✓ 已开放"
    else
        echo "║ - 443端口: ⚠ 可能未开放"
    fi
    
    # Check SSL certificate
    echo "║"
    echo "║ SSL 证书检查:"
    if [[ -f "/etc/ssl/private/${DOMAIN}.crt" ]]; then
        local cert_expiry=$(openssl x509 -in "/etc/ssl/private/${DOMAIN}.crt" -noout -enddate | cut -d= -f2)
        echo "║ - 证书文件: ✓ 存在"
        echo "║ - 证书到期: $cert_expiry"
    else
        echo "║ - 证书文件: ✗ 不存在"
    fi
    
    # Check DNS resolution
    echo "║"
    echo "║ DNS 解析检查:"
    if nslookup "$DOMAIN" 1.1.1.1 &>/dev/null; then
        echo "║ - 域名解析: ✓ 正常"
    else
        echo "║ - 域名解析: ✗ 失败"
    fi
    
    if nslookup "$MASK_DOMAIN" 1.1.1.1 &>/dev/null; then
        echo "║ - 伪装域名解析: ✓ 正常"
    else
        echo "║ - 伪装域名解析: ✗ 失败"
    fi
    
    # Check time sync
    echo "║"
    echo "║ 时间同步检查:"
    if systemctl is-active --quiet systemd-timesyncd; then
        echo "║ - 时间同步服务: ✓ 运行中"
    else
        echo "║ - 时间同步服务: ⚠ 未运行"
    fi
    
    # Check recent Xray logs for errors
    echo "║"
    echo "║ Xray 错误检查:"
    local error_count=$(journalctl -u xray --since "1 hour ago" | grep -c "error\|ERROR\|fail\|FAIL" || echo "0")
    if [[ "$error_count" -eq 0 ]]; then
        echo "║ - 最近1小时错误: ✓ 无错误"
    else
        echo "║ - 最近1小时错误: ⚠ $error_count 个错误"
        echo "║   建议查看详细日志: journalctl -u xray -f"
    fi
    
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Provide recommendations
    echo "诊断建议:"
    if ! systemctl is-active --quiet nginx || ! systemctl is-active --quiet xray; then
        echo "- 🔴 关键服务未运行，请检查服务状态和配置"
    fi
    
    if ! ss -tlnp | grep -q ":443"; then
        echo "- 🔴 443端口未监听，请检查 Nginx 配置"
    fi
    
    if [[ ! -f "/etc/ssl/private/${DOMAIN}.crt" ]]; then
        echo "- 🔴 SSL证书缺失，请重新申请证书"
    fi
    
    if [[ "$error_count" -gt 0 ]]; then
        echo "- 🟡 发现 Xray 错误，建议查看详细日志"
    fi
    
    echo "- 📋 如需进一步诊断，请查看 Xray 实时日志"
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

# Management menu
show_management_menu() {
    while true; do
        clear
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║                    VLESS 管理面板 v${SCRIPT_VERSION}                     ║"
        echo "╠════════════════════════════════════════════════════════════════╣"
        echo "║  1. 查看配置信息"
        echo "║  2. 更换 VLESS UUID"
        echo "║  3. 更换 REALITY 密钥对"
        echo "║  4. 更换伪装域名 (SNI)"
        echo "║  5. 重启 Xray 服务"
        echo "║  6. 查看 Xray 实时日志"
        echo "║  7. 运行连接诊断"
        echo "║  8. 防火墙端口管理"
        echo "║  9. 删除所有配置"
        echo "║ 10. 退出管理面板"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo ""
        
        read -p "请选择操作 [1-10]: " choice
        
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
                change_mask_domain
                read -p "按回车键继续..."
                ;;
            5)
                restart_xray
                read -p "按回车键继续..."
                ;;
            6)
                show_xray_logs
                ;;
            7)
                run_connection_test
                read -p "按回车键继续..."
                ;;
            8)
                manage_firewall
                ;;
            9)
                delete_configuration
                read -p "按回车键继续..."
                ;;
            10)
                log_info "退出管理面板"
                exit 0
                ;;
            *)
                log_error "无效选择，请输入 1-10"
                sleep 2
                ;;
        esac
    done
}

# Main execution function
main() {
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
    
    log_success "安装配置完成！"
}

# Run main function
main "$@"