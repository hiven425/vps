#!/bin/bash

# Reality一键搭建和管理脚本
# 支持VLESS-HTTP2-REALITY协议配置
# 作者: VPS Security Tools
# 版本: 1.0

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置目录
CONFIG_DIR="/etc/reality-config"
NGINX_CONFIG="/etc/nginx/nginx.conf"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
NGINX_SERVICE="/lib/systemd/system/nginx.service"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 创建配置目录
create_config_dir() {
    if [[ ! -d "$CONFIG_DIR" ]]; then
        mkdir -p "$CONFIG_DIR"
        log_info "创建配置目录: $CONFIG_DIR"
    fi
}

# 预设伪装网站列表
show_fake_sites() {
    echo -e "${BLUE}预设伪装网站列表:${NC}"
    echo "1.  www.csgo.com (游戏)"
    echo "2.  shopify.com (电商)"
    echo "3.  time.is (工具)"
    echo "4.  icook.hk (生活)"
    echo "5.  icook.tw (生活)"
    echo "6.  ip.sb (工具)"
    echo "7.  japan.com (地区)"
    echo "8.  malaysia.com (地区)"
    echo "9.  russia.com (地区)"
    echo "10. singapore.com (地区)"
    echo "11. skk.moe (技术)"
    echo "12. www.visa.com.sg (金融)"
    echo "13. www.visa.com.hk (金融)"
    echo "14. www.visa.com.tw (金融)"
    echo "15. www.visa.co.jp (金融)"
    echo "16. www.visakorea.com (金融)"
    echo "17. www.gco.gov.qa (政府)"
    echo "18. www.gov.se (政府)"
    echo "19. www.gov.ua (政府)"
    echo "20. linux.do (技术社区)"
    echo "21. 自定义输入"
}

# 获取伪装网站
get_fake_site() {
    local sites=(
        "www.csgo.com" "shopify.com" "time.is" "icook.hk" "icook.tw"
        "ip.sb" "japan.com" "malaysia.com" "russia.com" "singapore.com"
        "skk.moe" "www.visa.com.sg" "www.visa.com.hk" "www.visa.com.tw"
        "www.visa.co.jp" "www.visakorea.com" "www.gco.gov.qa"
        "www.gov.se" "www.gov.ua" "linux.do"
    )
    
    show_fake_sites
    echo
    read -p "请选择伪装网站 (1-21): " choice
    
    if [[ "$choice" == "21" ]]; then
        read -p "请输入自定义伪装网站域名: " fake_site
        if [[ -z "$fake_site" ]]; then
            log_error "伪装网站不能为空"
            return 1
        fi
    elif [[ "$choice" =~ ^[1-9]$|^1[0-9]$|^20$ ]]; then
        fake_site="${sites[$((choice-1))]}"
    else
        log_error "无效选择"
        return 1
    fi
    
    echo "$fake_site" > "$CONFIG_DIR/fake-site.conf"
    log_success "伪装网站设置为: $fake_site"
}

# 收集用户输入
collect_user_input() {
    log_info "开始收集配置信息..."
    
    # 域名输入
    read -p "请输入你的域名 (例如: example.com): " domain
    if [[ -z "$domain" ]]; then
        log_error "域名不能为空"
        exit 1
    fi
    echo "$domain" > "$CONFIG_DIR/domain.conf"
    
    # CF Token输入
    read -p "请输入Cloudflare API Token: " cf_token
    if [[ -z "$cf_token" ]]; then
        log_error "Cloudflare API Token不能为空"
        exit 1
    fi
    echo "$cf_token" > "$CONFIG_DIR/cf-token.conf"
    
    # 伪装网站选择
    get_fake_site
    
    log_success "配置信息收集完成"
}

# 生成UUID
generate_uuid() {
    if command -v xray >/dev/null 2>&1; then
        local uuid=$(xray uuid)
        echo "$uuid" > "$CONFIG_DIR/uuid.conf"
        log_success "UUID生成完成: $uuid"
        return 0
    else
        log_error "Xray未安装，无法生成UUID"
        return 1
    fi
}

# 生成密钥对
generate_keys() {
    if command -v xray >/dev/null 2>&1; then
        local keys_output=$(xray x25519)
        local private_key=$(echo "$keys_output" | grep "Private key:" | awk '{print $3}')
        local public_key=$(echo "$keys_output" | grep "Public key:" | awk '{print $3}')
        
        echo "$private_key" > "$CONFIG_DIR/private-key.conf"
        echo "$public_key" > "$CONFIG_DIR/public-key.conf"
        
        log_success "密钥对生成完成"
        log_info "私钥: $private_key"
        log_info "公钥: $public_key"
        return 0
    else
        log_error "Xray未安装，无法生成密钥对"
        return 1
    fi
}

# 生成shortIds
generate_short_ids() {
    local ids=()
    for i in {1..3}; do
        local length=$((RANDOM % 7 + 2))  # 2-8字符长度
        local id=$(openssl rand -hex $length | cut -c1-$((length*2)))
        ids+=("\"$id\"")
    done
    
    local short_ids_json="[$(IFS=','; echo "${ids[*]}")]"
    echo "$short_ids_json" > "$CONFIG_DIR/shortids.conf"
    log_success "ShortIds生成完成: $short_ids_json"
}

# 安装系统依赖
install_dependencies() {
    log_info "安装系统依赖..."

    # 更新系统并安装基础工具
    apt update && apt-get install -y curl vim ufw

    # 系统升级和编译依赖安装
    apt-get update && sudo apt-get upgrade && sudo apt update && sudo apt upgrade -y
    apt-get install -y gcc g++ libpcre3 libpcre3-dev zlib1g zlib1g-dev \
        openssl libssl-dev wget sudo make curl socat cron

    log_success "系统依赖安装完成"
}

# 安装Nginx
install_nginx() {
    log_info "开始安装Nginx..."
    
    # 下载、编译和安装Nginx（一条命令完成）
    wget https://nginx.org/download/nginx-1.27.1.tar.gz && \
    tar -xvf nginx-1.27.1.tar.gz && \
    cd nginx-1.27.1 && \
    ./configure --prefix=/usr/local/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --with-http_stub_status_module \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_sub_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-http_v2_module && \
    make && make install && cd ~
    
    log_success "Nginx编译安装完成"
}

# 创建Nginx服务文件
create_nginx_service() {
    log_info "创建Nginx systemd服务..."
    
    cat > "$NGINX_SERVICE" << 'EOF'
[Unit]
Description=A high performance web server and a reverse proxy server
Documentation=man:nginx(8)
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/usr/local/nginx/logs/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable nginx.service
    
    log_success "Nginx服务配置完成"
}

# 安装acme.sh
install_acme() {
    log_info "安装acme.sh证书工具..."
    
    curl https://get.acme.sh | sh
    ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
    acme.sh --set-default-ca --server letsencrypt
    
    log_success "acme.sh安装完成"
}

# 验证域名解析
verify_domain_resolution() {
    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local server_ip=$(curl -s ifconfig.me)

    log_info "验证域名解析..."
    log_info "服务器IP: $server_ip"

    local resolved_ip=$(dig +short "$domain" @8.8.8.8)
    if [[ "$resolved_ip" == "$server_ip" ]]; then
        log_success "域名解析验证成功"
        return 0
    else
        log_warning "域名解析可能未生效，解析IP: $resolved_ip，服务器IP: $server_ip"
        read -p "是否继续安装？(y/N): " continue_install
        if [[ "$continue_install" != "y" && "$continue_install" != "Y" ]]; then
            log_info "安装已取消"
            return 1
        fi
    fi
}

# 申请SSL证书
request_certificate() {
    log_info "申请SSL证书..."

    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local cf_token=$(cat "$CONFIG_DIR/cf-token.conf")

    export CF_Token="$cf_token"

    # 申请证书
    if acme.sh --issue --dns dns_cf -d "$domain"; then
        log_success "证书申请成功"
    else
        log_error "证书申请失败"
        return 1
    fi

    # 安装证书
    mkdir -p /etc/ssl/private
    if acme.sh --install-cert -d "$domain" --ecc \
        --key-file /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --reloadcmd "systemctl force-reload nginx"; then
        log_success "SSL证书安装完成"
    else
        log_error "证书安装失败"
        return 1
    fi
}

# 安装Xray
install_xray() {
    log_info "安装Xray..."

    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root

    log_success "Xray安装完成"
}

# 创建Nginx配置文件
create_nginx_config() {
    log_info "创建Nginx配置文件..."

    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local fake_site=$(cat "$CONFIG_DIR/fake-site.conf")

    cat > "$NGINX_CONFIG" << EOF
user root;
worker_processes auto;

error_log /usr/local/nginx/logs/error.log notice;
pid /usr/local/nginx/logs/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '[\$time_local] \$proxy_protocol_addr "\$http_referer" "\$http_user_agent"';
    access_log /usr/local/nginx/logs/access.log main;

    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ""      close;
    }

    map \$proxy_protocol_addr \$proxy_forwarded_elem {
        ~^[0-9.]+\$        "for=\$proxy_protocol_addr";
        ~^[0-9A-Fa-f:.]+\$ "for=\"[\$proxy_protocol_addr]\"";
        default           "for=unknown";
    }

    map \$http_forwarded \$proxy_add_forwarded {
        "~^(,[ \\\\t]*)*([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?(;([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?)*([ \\\\t]*,([ \\\\t]*([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?(;([!#\$%&'*+.^_\`|~0-9A-Za-z-]+=([!#\$%&'*+.^_\`|~0-9A-Za-z-]+|\"([\\\\t \\\\x21\\\\x23-\\\\x5B\\\\x5D-\\\\x7E\\\\x80-\\\\xFF]|\\\\\\\\[\\\\t \\\\x21-\\\\x7E\\\\x80-\\\\xFF])*\"))?)*)?)*\$" "\$http_forwarded, \$proxy_forwarded_elem";
        default "\$proxy_forwarded_elem";
    }

    server {
        listen 80;
        listen [::]:80;
        return 301 https://\$host\$request_uri;
    }

    server {
        listen                  127.0.0.1:8003 ssl default_server;
        ssl_reject_handshake    on;
        ssl_protocols           TLSv1.2 TLSv1.3;
        ssl_session_timeout     1h;
        ssl_session_cache       shared:SSL:10m;
        ssl_early_data          on;
    }

    server {
        listen                     127.0.0.1:8003 ssl proxy_protocol;
        set_real_ip_from           127.0.0.1;
        real_ip_header             proxy_protocol;
        server_name                $domain;

        ssl_certificate            /etc/ssl/private/fullchain.cer;
        ssl_certificate_key        /etc/ssl/private/private.key;
        ssl_protocols              TLSv1.2 TLSv1.3;
        ssl_ciphers                TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
        ssl_session_tickets        on;
        ssl_stapling               on;
        ssl_stapling_verify        on;
        resolver                   1.1.1.1 valid=60s;
        resolver_timeout           2s;

        location / {
            sub_filter                            \$proxy_host \$host;
            sub_filter_once                       off;
            set \$website                          $fake_site;
            proxy_pass                            https://\$website;
            resolver                              1.1.1.1;
            proxy_set_header Host                 \$proxy_host;
            proxy_http_version                    1.1;
            proxy_cache_bypass                    \$http_upgrade;
            proxy_ssl_server_name                 on;
            proxy_set_header Upgrade              \$http_upgrade;
            proxy_set_header Connection           \$connection_upgrade;
            proxy_set_header X-Real-IP            \$proxy_protocol_addr;
            proxy_set_header Forwarded            \$proxy_add_forwarded;
            proxy_set_header X-Forwarded-For      \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto    \$scheme;
            proxy_set_header X-Forwarded-Host     \$host;
            proxy_set_header X-Forwarded-Port     \$server_port;
            proxy_connect_timeout                 60s;
            proxy_send_timeout                    60s;
            proxy_read_timeout                    60s;
            proxy_set_header Early-Data           \$ssl_early_data;
        }
    }
}
EOF

    log_success "Nginx配置文件创建完成"
}

# 创建Xray配置文件
create_xray_config() {
    log_info "创建Xray配置文件..."

    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local uuid=$(cat "$CONFIG_DIR/uuid.conf")
    local private_key=$(cat "$CONFIG_DIR/private-key.conf")
    local short_ids=$(cat "$CONFIG_DIR/shortids.conf")

    cat > "$XRAY_CONFIG" << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "port": "443",
                "network": "udp",
                "outboundTag": "block"
            },
            {
                "type": "field",
                "ip": [
                    "geoip:cn",
                    "geoip:private"
                ],
                "outboundTag": "block"
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
                    "dest": "8003",
                    "xver": 1,
                    "serverNames": [
                        "$domain"
                    ],
                    "privateKey": "$private_key",
                    "shortIds": $short_ids
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
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
    ],
    "policy": {
        "levels": {
            "0": {
                "handshake": 2,
                "connIdle": 120
            }
        }
    }
}
EOF

    log_success "Xray配置文件创建完成"
}

# 生成VLESS链接
generate_vless_link() {
    log_info "生成VLESS链接..."

    if [[ ! -f "$CONFIG_DIR/domain.conf" ]] || [[ ! -f "$CONFIG_DIR/uuid.conf" ]] || [[ ! -f "$CONFIG_DIR/public-key.conf" ]] || [[ ! -f "$CONFIG_DIR/shortids.conf" ]]; then
        log_error "配置文件不完整，请先完成安装"
        return 1
    fi

    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local uuid=$(cat "$CONFIG_DIR/uuid.conf")
    local public_key=$(cat "$CONFIG_DIR/public-key.conf")
    local short_ids_json=$(cat "$CONFIG_DIR/shortids.conf")

    # 提取第一个shortId
    local first_short_id=$(echo "$short_ids_json" | sed 's/\["\([^"]*\)".*/\1/')

    local vless_link="vless://${uuid}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${domain}&fp=chrome&pbk=${public_key}&sid=${first_short_id}&type=tcp&headerType=none#Reality-${domain}"

    echo
    echo -e "${GREEN}=== VLESS链接 ===${NC}"
    echo "$vless_link"
    echo
    echo -e "${BLUE}=== 重要参数记录 ===${NC}"
    echo "域名: $domain"
    echo "UUID: $uuid"
    echo "公钥: $public_key"
    echo "ShortIds: $short_ids_json"
    echo

    # 保存到文件
    echo "$vless_link" > "$CONFIG_DIR/vless-link.txt"
    log_success "VLESS链接已保存到: $CONFIG_DIR/vless-link.txt"
}

# 卸载Reality服务
uninstall_reality() {
    log_info "开始卸载Reality服务..."

    # 停止服务
    systemctl stop nginx 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    systemctl disable nginx 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true

    # 删除服务文件
    rm -f "$NGINX_SERVICE"
    systemctl daemon-reload

    # 删除配置文件
    rm -rf "$CONFIG_DIR"
    rm -f "$NGINX_CONFIG"
    rm -f "$XRAY_CONFIG"

    # 删除SSL证书
    rm -rf /etc/ssl/private

    # 删除Nginx
    rm -f /usr/sbin/nginx
    rm -rf /usr/local/nginx
    rm -rf /etc/nginx

    # 卸载Xray
    if command -v xray >/dev/null 2>&1; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
    fi

    # 删除acme.sh
    if [[ -d "/root/.acme.sh" ]]; then
        /root/.acme.sh/acme.sh --uninstall
        rm -rf /root/.acme.sh
        rm -f /usr/local/bin/acme.sh
    fi

    log_success "Reality服务卸载完成"
}

# 安装BBR加速
install_bbr() {
    log_info "开始安装BBR加速..."

    # 检查当前BBR状态
    if lsmod | grep -q bbr; then
        log_success "BBR已经启用"
        return 0
    fi

    # 使用一键脚本安装BBR
    log_info "下载并运行BBR安装脚本..."
    if wget -O /tmp/tcp.sh http://sh.xdmb.xyz/tcp.sh; then
        bash /tmp/tcp.sh
        log_success "BBR安装脚本执行完成"
    else
        log_warning "BBR一键脚本下载失败，尝试手动配置..."
        manual_bbr_config
    fi
}

# 手动配置BBR
manual_bbr_config() {
    log_info "手动配置BBR..."

    # 备份原配置
    cp /etc/sysctl.conf /etc/sysctl.conf.backup

    # 检查是否已有BBR配置
    if ! grep -q "net.core.default_qdisc" /etc/sysctl.conf; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    fi

    if ! grep -q "net.ipv4.tcp_congestion_control" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    fi

    # 应用配置
    sysctl -p

    log_success "BBR手动配置完成"
}

# TCP窗口调优
optimize_tcp() {
    log_info "开始TCP窗口调优..."

    # 下载并运行调优脚本
    if wget -O /tmp/d11.sh sh.xdmb.xyz/d11.sh; then
        bash /tmp/d11.sh
        log_success "TCP窗口调优完成"
    else
        log_error "TCP调优脚本下载失败"
        return 1
    fi
}

# 检查BBR状态
check_bbr_status() {
    log_info "检查BBR状态..."

    echo -e "${BLUE}=== BBR状态检查 ===${NC}"

    # 检查BBR模块
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}✓ BBR模块已加载${NC}"
        lsmod | grep bbr
    else
        echo -e "${RED}✗ BBR模块未加载${NC}"
    fi

    echo

    # 检查拥塞控制算法
    local current_cc=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    echo "当前拥塞控制算法: $current_cc"

    if [[ "$current_cc" == "bbr" ]]; then
        echo -e "${GREEN}✓ BBR拥塞控制已启用${NC}"
    else
        echo -e "${RED}✗ BBR拥塞控制未启用${NC}"
    fi

    echo

    # 检查队列调度算法
    local current_qdisc=$(sysctl net.core.default_qdisc | awk '{print $3}')
    echo "当前队列调度算法: $current_qdisc"

    if [[ "$current_qdisc" == "fq" ]]; then
        echo -e "${GREEN}✓ FQ队列调度已启用${NC}"
    else
        echo -e "${RED}✗ FQ队列调度未启用${NC}"
    fi
}

# 检查安装状态
check_installation_status() {
    local nginx_installed=false
    local xray_installed=false
    local acme_installed=false

    if command -v nginx >/dev/null 2>&1; then
        nginx_installed=true
    fi

    if command -v xray >/dev/null 2>&1; then
        xray_installed=true
    fi

    if command -v acme.sh >/dev/null 2>&1; then
        acme_installed=true
    fi

    echo -e "${BLUE}=== 安装状态 ===${NC}"
    echo -n "Nginx: "
    if $nginx_installed; then
        echo -e "${GREEN}已安装${NC}"
    else
        echo -e "${RED}未安装${NC}"
    fi

    echo -n "Xray: "
    if $xray_installed; then
        echo -e "${GREEN}已安装${NC}"
    else
        echo -e "${RED}未安装${NC}"
    fi

    echo -n "acme.sh: "
    if $acme_installed; then
        echo -e "${GREEN}已安装${NC}"
    else
        echo -e "${RED}未安装${NC}"
    fi
    echo
}

# 主菜单
show_main_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Reality 一键搭建管理脚本    ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
    check_installation_status
    echo "1. 完整安装Reality服务"
    echo "2. 重启Xray服务"
    echo "3. 重启Nginx服务"
    echo "4. 查看服务状态"
    echo "5. 重置UUID"
    echo "6. 重置密钥对"
    echo "7. 重置ShortIds"
    echo "8. 重置所有配置"
    echo "9. 显示当前配置"
    echo "10. 生成VLESS链接"
    echo "11. 安装BBR加速"
    echo "12. TCP窗口调优"
    echo "13. 检查BBR状态"
    echo "14. 卸载Reality服务"
    echo "0. 退出"
    echo
}

# 主函数
main() {
    check_root
    create_config_dir
    
    while true; do
        show_main_menu
        read -p "请选择操作 (0-14): " choice
        
        case $choice in
            1)
                log_info "开始完整安装Reality服务..."
                collect_user_input
                verify_domain_resolution || continue
                install_dependencies
                install_nginx
                create_nginx_service
                install_acme
                request_certificate || continue
                install_xray
                generate_uuid
                generate_keys
                generate_short_ids
                create_nginx_config
                create_xray_config

                # 启动服务
                log_info "启动服务..."
                systemctl start nginx
                systemctl start xray
                systemctl enable xray

                # 检查服务状态
                if systemctl is-active --quiet nginx && systemctl is-active --quiet xray; then
                    log_success "Reality服务安装并启动完成！"
                    echo
                    generate_vless_link
                    echo

                    # 询问是否安装BBR
                    read -p "是否安装BBR加速？(y/N): " install_bbr_choice
                    if [[ "$install_bbr_choice" == "y" || "$install_bbr_choice" == "Y" ]]; then
                        install_bbr
                        echo
                        read -p "是否进行TCP窗口调优？(y/N): " optimize_choice
                        if [[ "$optimize_choice" == "y" || "$optimize_choice" == "Y" ]]; then
                            optimize_tcp
                        fi
                    fi
                else
                    log_error "服务启动失败，请检查配置"
                fi
                read -p "按回车键继续..."
                ;;
            2)
                systemctl restart xray
                log_success "Xray服务已重启"
                read -p "按回车键继续..."
                ;;
            3)
                systemctl restart nginx
                log_success "Nginx服务已重启"
                read -p "按回车键继续..."
                ;;
            4)
                echo -e "${BLUE}=== 服务状态 ===${NC}"
                systemctl status xray --no-pager -l
                echo
                systemctl status nginx --no-pager -l
                read -p "按回车键继续..."
                ;;
            5)
                generate_uuid
                if [[ -f "$CONFIG_DIR/domain.conf" ]]; then
                    create_xray_config
                    systemctl restart xray
                    log_success "UUID已重置并重启Xray服务"
                fi
                read -p "按回车键继续..."
                ;;
            6)
                generate_keys
                if [[ -f "$CONFIG_DIR/domain.conf" ]]; then
                    create_xray_config
                    systemctl restart xray
                    log_success "密钥对已重置并重启Xray服务"
                fi
                read -p "按回车键继续..."
                ;;
            7)
                generate_short_ids
                if [[ -f "$CONFIG_DIR/domain.conf" ]]; then
                    create_xray_config
                    systemctl restart xray
                    log_success "ShortIds已重置并重启Xray服务"
                fi
                read -p "按回车键继续..."
                ;;
            8)
                log_info "重置所有配置..."
                generate_uuid
                generate_keys
                generate_short_ids
                if [[ -f "$CONFIG_DIR/domain.conf" ]]; then
                    create_xray_config
                    systemctl restart xray
                    log_success "所有配置已重置并重启Xray服务"
                else
                    log_success "所有配置已重置"
                fi
                read -p "按回车键继续..."
                ;;
            9)
                echo -e "${BLUE}=== 当前配置 ===${NC}"
                if [[ -f "$CONFIG_DIR/domain.conf" ]]; then
                    echo "域名: $(cat $CONFIG_DIR/domain.conf)"
                fi
                if [[ -f "$CONFIG_DIR/uuid.conf" ]]; then
                    echo "UUID: $(cat $CONFIG_DIR/uuid.conf)"
                fi
                if [[ -f "$CONFIG_DIR/public-key.conf" ]]; then
                    echo "公钥: $(cat $CONFIG_DIR/public-key.conf)"
                fi
                if [[ -f "$CONFIG_DIR/shortids.conf" ]]; then
                    echo "ShortIds: $(cat $CONFIG_DIR/shortids.conf)"
                fi
                if [[ -f "$CONFIG_DIR/fake-site.conf" ]]; then
                    echo "伪装网站: $(cat $CONFIG_DIR/fake-site.conf)"
                fi
                read -p "按回车键继续..."
                ;;
            10)
                generate_vless_link
                read -p "按回车键继续..."
                ;;
            11)
                install_bbr
                read -p "按回车键继续..."
                ;;
            12)
                log_info "开始TCP窗口调优..."
                log_warning "请确保已先安装BBR"
                read -p "是否继续？(y/N): " confirm_optimize
                if [[ "$confirm_optimize" == "y" || "$confirm_optimize" == "Y" ]]; then
                    optimize_tcp
                fi
                read -p "按回车键继续..."
                ;;
            13)
                check_bbr_status
                read -p "按回车键继续..."
                ;;
            14)
                log_warning "卸载Reality服务将删除所有配置和证书"
                read -p "确认卸载？(y/N): " confirm_uninstall
                if [[ "$confirm_uninstall" == "y" || "$confirm_uninstall" == "Y" ]]; then
                    uninstall_reality
                fi
                read -p "按回车键继续..."
                ;;
            0)
                log_info "退出脚本"
                exit 0
                ;;
            *)
                log_error "无效选择，请重新输入"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 脚本入口
main "$@"
