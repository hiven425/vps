#!/bin/bash
#
# VLESS Reality 终极版部署脚本
# 基于: https://jollyroger.top/sites/223.html
# 版本: 4.0.0 - 终极稳定版
# 作者: 顶级 DevOps 工程师
# 特点: 彻底解决 "Nginx 成功，Xray 失败" 问题
# =================================================================================

# 严格错误处理
set -e -o pipefail

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
readonly SCRIPT_VERSION="4.0.0"
readonly CONFIG_DIR="/etc/setup"
readonly CONFIG_FILE="${CONFIG_DIR}/config.ini"

# 配置变量
MY_DOMAIN=""
FALLBACK_DOMAIN=""
CF_TOKEN=""
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

# 获取用户输入
get_user_input() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              VLESS Reality 终极版配置向导                         ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  请准备以下信息：                                              ║${NC}"
    echo -e "${WHITE}║  1. 您的域名 (在 Cloudflare 中管理)                           ║${NC}"
    echo -e "${WHITE}║  2. Cloudflare API Token (Zone:DNS:Edit 权限)                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
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
    
    echo ""
    log_success "配置参数收集完成"
}

# 更新系统
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
    check_result "Xray 安装"
    
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
    check_result "acme.sh 安装"
    
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
    
    INSTALL_DATE=$(date)
    
    log_success "密钥生成完成"
    log_debug "UUID: $UUID"
    log_debug "Public Key: $PUBLIC_KEY"
    log_debug "Short ID: $SHORT_ID"
}

# 配置 SSL 证书
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
    
    # 直接使用 --force 参数，避免跳过已存在的证书
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --server letsencrypt --force
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

# 创建健壮的 Xray systemd 服务文件
create_xray_service() {
    log_info "创建 Xray systemd 服务文件..."
    
    cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
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

    log_success "Xray systemd 服务文件创建完成"
}

# 配置 Xray
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
    
    # 关键修正：设置正确的文件权限
    log_info "设置 Xray 配置文件权限..."
    chown -R nobody:nogroup /usr/local/etc/xray
    chmod 644 /usr/local/etc/xray/config.json
    
    log_success "Xray 配置完成"
}

# 配置 Nginx
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

# 配置防火墙和安全
configure_security() {
    log_info "配置防火墙和安全设置..."
    
    # 配置 UFW
    log_info "配置 UFW 防火墙..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 443/tcp
    ufw --force enable
    
    # 配置 Fail2ban
    log_info "配置 Fail2ban..."
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 600
findtime = 300
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 300
bantime = 600
EOF
    
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log_success "安全配置完成"
}

# 严谨的启动与验证流程
start_and_verify_services() {
    log_info "执行严谨的服务启动与验证流程..."
    
    # 第一步：验证配置
    log_info "第一步：验证配置文件..."
    
    # 验证 Nginx 配置
    log_info "验证 Nginx 配置..."
    if ! nginx -t; then
        log_error "Nginx 配置文件验证失败！"
        exit 1
    fi
    log_success "Nginx 配置验证通过"
    
    # 验证 Xray 配置
    log_info "验证 Xray 配置..."
    if ! /usr/local/bin/xray test -c /usr/local/etc/xray/config.json; then
        log_error "Xray 配置文件验证失败！"
        exit 1
    fi
    log_success "Xray 配置验证通过"
    
    # 第二步：重载并启动
    log_info "第二步：重载 systemd 并启动服务..."
    
    # 重载 systemd 配置
    systemctl daemon-reload
    check_result "systemd daemon-reload"
    
    # 启用服务
    systemctl enable xray
    systemctl enable nginx
    
    # 启动 Xray 服务
    log_info "启动 Xray 服务..."
    systemctl restart xray
    check_result "Xray 服务启动"
    
    # 启动 Nginx 服务
    log_info "启动 Nginx 服务..."
    systemctl restart nginx
    check_result "Nginx 服务启动"
    
    # 第三步：延时等待
    log_info "第三步：等待服务完全启动..."
    sleep 3
    
    # 第四步：检查最终状态
    log_info "第四步：检查服务最终状态..."
    
    local xray_status=$(systemctl is-active xray)
    local nginx_status=$(systemctl is-active nginx)
    
    log_info "Xray 状态: $xray_status"
    log_info "Nginx 状态: $nginx_status"
    
    if [[ "$xray_status" != "active" ]]; then
        log_error "Xray 服务未能正常启动！"
        log_error "Xray 服务日志:"
        journalctl -u xray -n 10 --no-pager
        exit 1
    fi
    
    if [[ "$nginx_status" != "active" ]]; then
        log_error "Nginx 服务未能正常启动！"
        log_error "Nginx 服务日志:"
        journalctl -u nginx -n 10 --no-pager
        exit 1
    fi
    
    log_success "所有服务启动成功！"
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

# 保存配置
save_config() {
    log_info "保存配置信息..."
    
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# VLESS Reality 配置文件
MY_DOMAIN="$MY_DOMAIN"
FALLBACK_DOMAIN="$FALLBACK_DOMAIN"
CF_TOKEN="$CF_TOKEN"
UUID="$UUID"
PRIVATE_KEY="$PRIVATE_KEY"
PUBLIC_KEY="$PUBLIC_KEY"
SHORT_ID="$SHORT_ID"
INSTALL_DATE="$INSTALL_DATE"
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "配置已保存到 $CONFIG_FILE"
}

# 显示最终总结
display_final_summary() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              VLESS Reality 终极版部署完成！                       ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  域名:           $MY_DOMAIN${NC}"
    echo -e "${WHITE}║  伪装域名:       $FALLBACK_DOMAIN${NC}"
    echo -e "${WHITE}║  UUID:           $UUID${NC}"
    echo -e "${WHITE}║  PublicKey:      $PUBLIC_KEY${NC}"
    echo -e "${WHITE}║  ShortId:        $SHORT_ID${NC}"
    echo -e "${WHITE}║${NC}"
    echo -e "${WHITE}║  服务状态:${NC}"
    echo -e "${WHITE}║  - Nginx:        $(systemctl is-active nginx)${NC}"
    echo -e "${WHITE}║  - Xray:         $(systemctl is-active xray)${NC}"
    echo -e "${WHITE}║  - UFW:          $(ufw status | head -n1 | cut -d' ' -f2)${NC}"
    echo -e "${WHITE}║  - Fail2ban:     $(systemctl is-active fail2ban)${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║                           连接信息                               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${GREEN}VLESS Reality 连接链接:${NC}"
    cat /root/client-configs/vless-link.txt
    echo ""
    
    echo -e "${BLUE}配置文件位置:${NC}"
    echo "- 客户端配置: /root/client-configs/"
    echo "- Nginx 配置: /etc/nginx/nginx.conf"
    echo "- Xray 配置:  /usr/local/etc/xray/config.json"
    echo "- 系统配置:   $CONFIG_FILE"
    echo ""
    
    log_success "部署完成！请将上述 VLESS 链接导入到您的客户端中"
}

# 主函数
main() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              VLESS Reality 终极版部署脚本                       ║"
    echo "║                        Version $SCRIPT_VERSION                         ║"
    echo "║              彻底解决 Xray 启动失败问题                         ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    # 检查权限和系统
    check_root
    check_system
    
    # 收集用户输入
    get_user_input
    
    log_info "开始执行终极版部署流程..."
    
    # 执行部署步骤
    update_system
    install_xray
    install_acme
    create_xray_service
    generate_keys
    setup_ssl_certificate
    configure_xray
    configure_nginx
    configure_security
    start_and_verify_services
    generate_client_config
    save_config
    
    # 显示最终结果
    display_final_summary
    
    log_success "VLESS Reality 终极版部署完成！"
}

# 运行主程序
main "$@"