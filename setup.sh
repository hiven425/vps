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
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""
NGINX_CONF_PATH="/etc/nginx/sites-available/default"
XRAY_CONF_PATH="/usr/local/etc/xray/config.json"
TEMP_DIR="/tmp/vless-setup"

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
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}$ ]]; then
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
    log_info "Collecting configuration parameters..."
    
    # Get domain
    while true; do
        read -p "Enter your domain (e.g., example.com): " DOMAIN
        if validate_domain "$DOMAIN"; then
            break
        else
            log_error "Invalid domain format. Please enter a valid domain."
        fi
    done
    
    # Get email
    while true; do
        read -p "Enter your email for SSL certificate: " EMAIL
        if validate_email "$EMAIL"; then
            break
        else
            log_error "Invalid email format. Please enter a valid email address."
        fi
    done
    
    # Get Cloudflare API token
    while true; do
        read -s -p "Enter your Cloudflare API Token: " CF_API_TOKEN
        echo
        if [[ -n "$CF_API_TOKEN" && ${#CF_API_TOKEN} -gt 10 ]]; then
            break
        else
            log_error "Invalid API token. Please enter a valid Cloudflare API token."
        fi
    done
    
    log_success "Configuration parameters collected"
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    
    # Check if update is needed (idempotency)
    if [[ -f "/var/log/vless-setup-updated" ]]; then
        log_info "System already updated, skipping..."
        return 0
    fi
    
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y
    apt install -y curl wget unzip sudo ufw
    
    # Mark as updated
    touch "/var/log/vless-setup-updated"
    log_success "System packages updated"
}

# Install Nginx
install_nginx() {
    log_info "Installing Nginx..."
    
    # Check if already installed
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Nginx already installed and running"
        return 0
    fi
    
    apt install -y nginx
    systemctl enable nginx
    log_success "Nginx installed"
}

# Install Xray
install_xray() {
    log_info "Installing Xray..."
    
    # Check if already installed
    if [[ -f "/usr/local/bin/xray" ]]; then
        log_info "Xray already installed"
        return 0
    fi
    
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    log_success "Xray installed"
}

# Install ACME.sh
install_acme() {
    log_info "Installing ACME.sh..."
    
    # Check if already installed
    if [[ -f "/root/.acme.sh/acme.sh" ]]; then
        log_info "ACME.sh already installed"
        return 0
    fi
    
    curl https://get.acme.sh | sh -s email="$EMAIL"
    source ~/.bashrc
    log_success "ACME.sh installed"
}

# Generate cryptographic keys
generate_keys() {
    log_info "Generating cryptographic keys..."
    
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
    
    log_success "Keys generated successfully"
}

# Configure Nginx
configure_nginx() {
    log_info "Configuring Nginx..."
    
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
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }
    
    location /grpc {
        grpc_pass grpc://127.0.0.1:8081;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    # Test nginx configuration
    if nginx -t; then
        log_success "Nginx configuration created successfully"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
}

# Configure Xray
configure_xray() {
    log_info "Configuring Xray..."
    
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
                "ip": ["geoip:cn"],
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
                    "dest": "127.0.0.1:443",
                    "xver": 0,
                    "serverNames": ["$DOMAIN"],
                    "privateKey": "$PRIVATE_KEY",
                    "shortIds": ["$SHORT_ID"]
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
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ]
}
EOF
    
    # Create log directory
    mkdir -p /var/log/xray
    chown nobody:nogroup /var/log/xray
    
    # Set proper permissions
    chmod 644 "$XRAY_CONF_PATH"
    
    log_success "Xray configuration created successfully"
}

# Setup SSL certificates
setup_ssl() {
    log_info "Setting up SSL certificates..."
    
    # Set Cloudflare API token
    export CF_Token="$CF_API_TOKEN"
    
    # Issue certificate
    /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --key-file /etc/ssl/private/${DOMAIN}.key --fullchain-file /etc/ssl/private/${DOMAIN}.crt --reloadcmd "systemctl reload nginx"
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/${DOMAIN}.key
    chmod 644 /etc/ssl/private/${DOMAIN}.crt
    
    log_success "SSL certificates configured"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
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
    
    log_success "Firewall configured"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    # Start and enable Nginx
    systemctl restart nginx
    systemctl enable nginx
    
    # Start and enable Xray
    systemctl restart xray
    systemctl enable xray
    
    # Check service status
    if systemctl is-active --quiet nginx && systemctl is-active --quiet xray; then
        log_success "All services started successfully"
    else
        log_error "Some services failed to start"
        systemctl status nginx --no-pager
        systemctl status xray --no-pager
        exit 1
    fi
}

# Generate client configurations
generate_client_config() {
    log_info "Generating client configurations..."
    
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
    log_success "Setup completed successfully!"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                    CONFIGURATION SUMMARY                                      ║"
    echo "╠════════════════════════════════════════════════════════════════════════════════════════════════╣"
    echo "║ Domain:           $DOMAIN"
    echo "║ UUID:             $UUID"
    echo "║ Private Key:      $PRIVATE_KEY"
    echo "║ Public Key:       $PUBLIC_KEY"
    echo "║ Short ID:         $SHORT_ID"
    echo "║"
    echo "║ Client Configs:   /root/client-configs/"
    echo "║ Nginx Config:     $NGINX_CONF_PATH"
    echo "║ Xray Config:      $XRAY_CONF_PATH"
    echo "║"
    echo "║ Services Status:"
    echo "║ - Nginx:          $(systemctl is-active nginx)"
    echo "║ - Xray:           $(systemctl is-active xray)"
    echo "║ - Firewall:       $(ufw status | head -n1 | cut -d' ' -f2)"
    echo "╠════════════════════════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                      SHARE LINKS                                               ║"
    echo "╠════════════════════════════════════════════════════════════════════════════════════════════════╣"
    echo "║ Reality Link:     $(cat /root/client-configs/reality-share-link.txt)"
    echo "║"
    echo "║ gRPC Link:        $(cat /root/client-configs/grpc-share-link.txt)"
    echo "╚════════════════════════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    log_info "Configuration files saved in /root/client-configs/"
    log_info "For support and troubleshooting, check the logs in /var/log/xray/"
}

# Main execution function
main() {
    log_info "Starting VLESS-gRPC-REALITY setup..."
    
    check_privileges
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
    display_summary
    
    log_success "Setup completed successfully!"
}

# Run main function
main "$@"