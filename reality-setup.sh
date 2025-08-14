#!/bin/bash

# Reality一键搭建和管理脚本
# 支持VLESS-HTTP2-REALITY协议配置
# 作者: VPS Security Tools
# 版本: 2.1 (修复关键漏洞版)

# 移除 set -e，改用函数级别错误处理

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

# 错误处理函数
handle_error() {
    local exit_code=$1
    local error_msg="$2"
    if [[ $exit_code -ne 0 ]]; then
        log_error "$error_msg"
        return 1
    fi
}

# 检查命令是否存在
check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "命令 $1 未找到，请先安装"
        return 1
    fi
}

# 验证变量是否为空
validate_var() {
    local var_name="$1"
    local var_value="$2"
    if [[ -z "$var_value" ]]; then
        log_error "$var_name 不能为空"
        return 1
    fi
}

# 验证域名格式
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$ ]]; then
        log_error "域名格式不正确: $domain"
        return 1
    fi
}

# 网络连接检查
check_network() {
    log_info "检查网络连接..."
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_error "网络连接失败，请检查网络设置"
        return 1
    fi
    log_success "网络连接正常"
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

# 验证邮箱格式
validate_email() {
    local email="$1"
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        log_error "邮箱格式不正确: $email"
        return 1
    fi
}

# 收集用户输入
collect_user_input() {
    log_info "开始收集配置信息..."

    # 域名输入和验证
    while true; do
        read -p "请输入你的域名 (例如: example.com): " domain
        if validate_var "域名" "$domain" && validate_domain "$domain"; then
            echo "$domain" > "$CONFIG_DIR/domain.conf"
            break
        fi
        log_warning "请重新输入正确的域名"
    done

    # 邮箱输入和验证（用于SSL证书）
    while true; do
        read -p "请输入你的邮箱地址 (用于SSL证书通知): " email
        if validate_var "邮箱" "$email" && validate_email "$email"; then
            echo "$email" > "$CONFIG_DIR/email.conf"
            break
        fi
        log_warning "请重新输入正确的邮箱地址"
    done

    # CF Token输入和验证
    while true; do
        read -p "请输入Cloudflare API Token: " cf_token
        if validate_var "Cloudflare API Token" "$cf_token"; then
            # 简单验证Token格式（40个字符的字母数字）
            if [[ ${#cf_token} -ge 40 && "$cf_token" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                echo "$cf_token" > "$CONFIG_DIR/cf-token.conf"
                break
            else
                log_error "Cloudflare API Token格式不正确"
            fi
        fi
        log_warning "请重新输入正确的Cloudflare API Token"
    done

    # Reality目标网站配置
    log_info "配置Reality伪装目标..."
    echo -e "${YELLOW}Reality目标网站要求：${NC}"
    echo "• 支持TLS 1.3"
    echo "• 支持HTTP/2"
    echo "• 使用x25519密钥交换"
    echo "• 不使用CDN"
    echo "• 建议选择大型网站（如Microsoft、Apple等）"
    echo

    while true; do
        echo "推荐的Reality目标网站："
        echo "1. www.microsoft.com"
        echo "2. www.apple.com"
        echo "3. www.cloudflare.com"
        echo "4. www.bing.com"
        echo "5. 自定义输入"

        read -p "请选择Reality目标网站 (1-5): " reality_choice

        case $reality_choice in
            1) reality_dest="www.microsoft.com" ;;
            2) reality_dest="www.apple.com" ;;
            3) reality_dest="www.cloudflare.com" ;;
            4) reality_dest="www.bing.com" ;;
            5)
                read -p "请输入自定义Reality目标网站: " reality_dest
                if [[ -z "$reality_dest" ]]; then
                    log_error "Reality目标网站不能为空"
                    continue
                fi
                ;;
            *)
                log_error "无效选择"
                continue
                ;;
        esac

        echo "$reality_dest" > "$CONFIG_DIR/reality-dest.conf"
        log_success "Reality目标网站设置为: $reality_dest"
        break
    done

    # 伪装网站选择（用于Nginx反向代理）
    get_fake_site || return 1

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
        log_info "生成Reality密钥对..."

        # 关键修复：只生成一次密钥对，确保私钥和公钥匹配
        local key_pair=$(xray x25519)
        local private_key=$(echo "$key_pair" | awk '/Private key:/ {print $3}')
        local public_key=$(echo "$key_pair" | awk '/Public key:/ {print $3}')

        # 验证密钥是否成功生成
        if [[ -z "$private_key" || -z "$public_key" ]]; then
            log_error "无法生成或提取密钥对，请检查Xray是否正确安装"
            return 1
        fi

        # 验证密钥格式（Reality密钥应该是44个字符的base64）
        if [[ ${#private_key} -ne 44 || ${#public_key} -ne 44 ]]; then
            log_error "生成的密钥格式不正确"
            return 1
        fi

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

    # 检查网络连接
    check_network || return 1

    # 更新系统
    log_info "更新系统包列表..."
    apt update || { log_error "系统更新失败"; return 1; }

    log_info "升级系统..."
    apt upgrade -y || { log_error "系统升级失败"; return 1; }

    # 安装所有依赖包（包含基础工具，确保完整性）
    log_info "安装依赖包..."
    apt install -y \
        curl wget vim ufw \
        gcc g++ make \
        libpcre3 libpcre3-dev \
        zlib1g zlib1g-dev \
        openssl libssl-dev \
        socat cron \
        dnsutils bind9-utils \
        gawk sed grep \
        ca-certificates \
        gnupg lsb-release \
        software-properties-common \
        apt-transport-https || {
        log_error "依赖包安装失败"
        return 1
    }

    log_success "系统依赖安装完成"
}

# 安装Nginx
install_nginx() {
    log_info "开始安装Nginx..."

    # 检查是否已安装
    if command -v nginx >/dev/null 2>&1; then
        log_warning "Nginx已安装，跳过编译安装"
        return 0
    fi

    # 创建临时目录
    local temp_dir="/tmp/nginx-build"
    mkdir -p "$temp_dir" || { log_error "创建临时目录失败"; return 1; }
    cd "$temp_dir" || { log_error "进入临时目录失败"; return 1; }

    # 下载Nginx源码
    log_info "下载Nginx源码..."
    wget https://nginx.org/download/nginx-1.27.1.tar.gz || {
        log_error "Nginx源码下载失败"
        return 1
    }

    # 解压源码
    log_info "解压Nginx源码..."
    tar -xzf nginx-1.27.1.tar.gz || { log_error "解压失败"; return 1; }
    cd nginx-1.27.1 || { log_error "进入源码目录失败"; return 1; }

    # 配置编译选项
    log_info "配置Nginx编译选项..."
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
        --with-http_v2_module || {
        log_error "Nginx配置失败"
        return 1
    }

    # 编译
    log_info "编译Nginx..."
    make || { log_error "Nginx编译失败"; return 1; }

    # 安装
    log_info "安装Nginx..."
    make install || { log_error "Nginx安装失败"; return 1; }

    # 清理临时文件
    cd / && rm -rf "$temp_dir"

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

    # 检查是否已安装
    if [[ -f "/usr/local/bin/acme.sh" ]] && [[ -x "/usr/local/bin/acme.sh" ]]; then
        log_warning "acme.sh已安装，跳过安装"
        return 0
    fi

    # 下载并安装acme.sh
    log_info "下载acme.sh..."
    curl -s https://get.acme.sh | sh || {
        log_error "acme.sh下载安装失败"
        return 1
    }

    # 创建软链接
    if [[ -f "/root/.acme.sh/acme.sh" ]]; then
        ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh || {
            log_error "创建acme.sh软链接失败"
            return 1
        }
    else
        log_error "acme.sh安装文件未找到"
        return 1
    fi

    # 设置默认CA
    /usr/local/bin/acme.sh --set-default-ca --server letsencrypt || {
        log_error "设置acme.sh默认CA失败"
        return 1
    }

    log_success "acme.sh安装完成"
}

# 验证域名解析
verify_domain_resolution() {
    local domain=$(cat "$CONFIG_DIR/domain.conf")
    validate_var "域名" "$domain" || return 1

    log_info "验证域名解析..."

    # 获取服务器IP
    local server_ip=$(curl -s --connect-timeout 10 ifconfig.me)
    if [[ -z "$server_ip" ]]; then
        log_error "无法获取服务器IP地址"
        return 1
    fi
    log_info "服务器IP: $server_ip"

    # 检查dig命令
    check_command "dig" || return 1

    # 解析域名
    local resolved_ip=$(dig +short "$domain" @8.8.8.8 | head -n1)
    if [[ -z "$resolved_ip" ]]; then
        log_error "域名解析失败，请检查域名是否正确配置"
        log_warning "请确保域名已正确解析到服务器IP: $server_ip"
        read -p "域名解析未完成，建议稍后再试。是否强制继续？(y/N): " force_continue
        if [[ "$force_continue" != "y" && "$force_continue" != "Y" ]]; then
            log_info "安装已取消，请配置域名解析后重试"
            return 1
        fi
    elif [[ "$resolved_ip" == "$server_ip" ]]; then
        log_success "域名解析验证成功"
        return 0
    else
        log_warning "域名解析IP与服务器IP不匹配"
        log_warning "解析IP: $resolved_ip，服务器IP: $server_ip"
        log_warning "这可能导致SSL证书申请失败"
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

# 验证配置变量
validate_config_vars() {
    log_info "验证配置变量..."

    # 检查必要的配置文件
    local config_files=("domain.conf" "fake-site.conf")
    for file in "${config_files[@]}"; do
        if [[ ! -f "$CONFIG_DIR/$file" ]]; then
            log_error "配置文件 $file 不存在"
            return 1
        fi
    done

    # 验证域名
    local domain=$(cat "$CONFIG_DIR/domain.conf")
    validate_var "域名" "$domain" || return 1
    validate_domain "$domain" || return 1

    # 验证伪装网站
    local fake_site=$(cat "$CONFIG_DIR/fake-site.conf")
    validate_var "伪装网站" "$fake_site" || return 1

    log_success "配置变量验证通过"
}

# 创建Nginx配置文件
create_nginx_config() {
    log_info "创建Nginx配置文件..."

    # 验证配置变量
    validate_config_vars || return 1

    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local fake_site=$(cat "$CONFIG_DIR/fake-site.conf")

    # 备份现有配置
    if [[ -f "$NGINX_CONFIG" ]]; then
        cp "$NGINX_CONFIG" "$NGINX_CONFIG.backup.$(date +%Y%m%d_%H%M%S)" || {
            log_warning "备份Nginx配置失败"
        }
    fi

    # 创建逼真的伪装网站
    log_info "创建伪装网站..."
    mkdir -p /var/www/html/{css,js,images}

    # 创建主页
    cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechCorp Solutions - Digital Innovation Partner</title>
    <meta name="description" content="Leading technology solutions provider specializing in cloud computing, digital transformation, and enterprise software development.">
    <meta name="keywords" content="technology, cloud computing, digital transformation, enterprise software">
    <link rel="stylesheet" href="/css/style.css">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
</head>
<body>
    <header>
        <nav class="navbar">
            <div class="nav-container">
                <div class="nav-logo">
                    <h2>TechCorp</h2>
                </div>
                <ul class="nav-menu">
                    <li><a href="#home">Home</a></li>
                    <li><a href="#services">Services</a></li>
                    <li><a href="#about">About</a></li>
                    <li><a href="#contact">Contact</a></li>
                </ul>
            </div>
        </nav>
    </header>

    <main>
        <section id="home" class="hero">
            <div class="hero-content">
                <h1>Digital Innovation for Modern Business</h1>
                <p>We help enterprises transform their operations through cutting-edge technology solutions and strategic digital initiatives.</p>
                <button class="cta-button">Get Started</button>
            </div>
        </section>

        <section id="services" class="services">
            <div class="container">
                <h2>Our Services</h2>
                <div class="service-grid">
                    <div class="service-card">
                        <h3>Cloud Computing</h3>
                        <p>Scalable cloud infrastructure and migration services for modern enterprises.</p>
                    </div>
                    <div class="service-card">
                        <h3>Digital Transformation</h3>
                        <p>Strategic consulting and implementation for digital business transformation.</p>
                    </div>
                    <div class="service-card">
                        <h3>Enterprise Software</h3>
                        <p>Custom software development and enterprise application integration.</p>
                    </div>
                </div>
            </div>
        </section>

        <section id="about" class="about">
            <div class="container">
                <h2>About TechCorp</h2>
                <p>With over 15 years of experience in the technology industry, TechCorp Solutions has been at the forefront of digital innovation. We partner with businesses of all sizes to deliver transformative technology solutions that drive growth and efficiency.</p>
                <div class="stats">
                    <div class="stat">
                        <h3>500+</h3>
                        <p>Projects Completed</p>
                    </div>
                    <div class="stat">
                        <h3>50+</h3>
                        <p>Enterprise Clients</p>
                    </div>
                    <div class="stat">
                        <h3>15+</h3>
                        <p>Years Experience</p>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <footer>
        <div class="container">
            <p>&copy; 2024 TechCorp Solutions. All rights reserved.</p>
            <p>Contact: info@techcorp-solutions.com | +1 (555) 123-4567</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
HTML

    # 创建CSS样式文件
    cat > /var/www/html/css/style.css << 'CSS'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

/* Navigation */
.navbar {
    background: #fff;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    position: fixed;
    width: 100%;
    top: 0;
    z-index: 1000;
}

.nav-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    height: 70px;
}

.nav-logo h2 {
    color: #2c5aa0;
    font-size: 24px;
}

.nav-menu {
    display: flex;
    list-style: none;
    gap: 30px;
}

.nav-menu a {
    text-decoration: none;
    color: #333;
    font-weight: 500;
    transition: color 0.3s;
}

.nav-menu a:hover {
    color: #2c5aa0;
}

/* Hero Section */
.hero {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 150px 0 100px;
    text-align: center;
}

.hero-content h1 {
    font-size: 3rem;
    margin-bottom: 20px;
    font-weight: 700;
}

.hero-content p {
    font-size: 1.2rem;
    margin-bottom: 30px;
    max-width: 600px;
    margin-left: auto;
    margin-right: auto;
}

.cta-button {
    background: #ff6b6b;
    color: white;
    padding: 15px 30px;
    border: none;
    border-radius: 5px;
    font-size: 1.1rem;
    cursor: pointer;
    transition: background 0.3s;
}

.cta-button:hover {
    background: #ff5252;
}

/* Services Section */
.services {
    padding: 80px 0;
    background: #f8f9fa;
}

.services h2 {
    text-align: center;
    margin-bottom: 50px;
    font-size: 2.5rem;
    color: #333;
}

.service-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 30px;
}

.service-card {
    background: white;
    padding: 30px;
    border-radius: 10px;
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    text-align: center;
    transition: transform 0.3s;
}

.service-card:hover {
    transform: translateY(-5px);
}

.service-card h3 {
    color: #2c5aa0;
    margin-bottom: 15px;
    font-size: 1.5rem;
}

/* About Section */
.about {
    padding: 80px 0;
}

.about h2 {
    text-align: center;
    margin-bottom: 30px;
    font-size: 2.5rem;
    color: #333;
}

.about p {
    text-align: center;
    font-size: 1.1rem;
    margin-bottom: 50px;
    max-width: 800px;
    margin-left: auto;
    margin-right: auto;
}

.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 30px;
    text-align: center;
}

.stat h3 {
    font-size: 3rem;
    color: #2c5aa0;
    margin-bottom: 10px;
}

.stat p {
    font-size: 1.1rem;
    color: #666;
}

/* Footer */
footer {
    background: #333;
    color: white;
    text-align: center;
    padding: 30px 0;
}

footer p {
    margin-bottom: 10px;
}

/* Responsive */
@media (max-width: 768px) {
    .nav-menu {
        display: none;
    }

    .hero-content h1 {
        font-size: 2rem;
    }

    .hero-content p {
        font-size: 1rem;
    }
}
CSS

    # 创建JavaScript文件
    cat > /var/www/html/js/main.js << 'JS'
// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Add scroll effect to navbar
window.addEventListener('scroll', function() {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.background = 'rgba(255, 255, 255, 0.95)';
        navbar.style.backdropFilter = 'blur(10px)';
    } else {
        navbar.style.background = '#fff';
        navbar.style.backdropFilter = 'none';
    }
});

// Simple form validation and interaction
document.querySelector('.cta-button')?.addEventListener('click', function() {
    alert('Thank you for your interest! Please contact us at info@techcorp-solutions.com for more information.');
});

// Add loading animation
window.addEventListener('load', function() {
    document.body.style.opacity = '0';
    document.body.style.transition = 'opacity 0.5s';
    setTimeout(() => {
        document.body.style.opacity = '1';
    }, 100);
});
JS

    # 创建favicon
    echo "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==" | base64 -d > /var/www/html/favicon.ico

    # 创建robots.txt
    cat > /var/www/html/robots.txt << 'ROBOTS'
User-agent: *
Allow: /

Sitemap: https://$(cat "$CONFIG_DIR/domain.conf")/sitemap.xml
ROBOTS

    # 创建404页面
    cat > /var/www/html/404.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found | TechCorp Solutions</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <div style="text-align: center; padding: 100px 20px;">
        <h1 style="font-size: 4rem; color: #2c5aa0;">404</h1>
        <h2>Page Not Found</h2>
        <p>The page you're looking for doesn't exist.</p>
        <a href="/" style="color: #2c5aa0; text-decoration: none;">← Back to Home</a>
    </div>
</body>
</html>
HTML

    log_success "逼真伪装网站创建完成"

    cat > "$NGINX_CONFIG" << EOF
user root;
worker_processes auto;

error_log /usr/local/nginx/logs/error.log notice;
pid /usr/local/nginx/logs/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format main '[\$time_local] \$remote_addr "\$request" \$status \$body_bytes_sent "\$http_referer" "\$http_user_agent"';
    access_log /usr/local/nginx/logs/access.log main;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout  65;
    types_hash_max_size 2048;

    # HTTP重定向到HTTPS
    server {
        listen 80;
        listen [::]:80;
        server_name $domain;
        return 301 https://\$server_name\$request_uri;
    }

    # 主HTTPS服务器 - 伪装网站
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name $domain;

        # SSL配置
        ssl_certificate /etc/ssl/private/fullchain.cer;
        ssl_certificate_key /etc/ssl/private/private.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # 安全头
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;

        # 伪装网站根目录
        root /var/www/html;
        index index.html index.htm;

        # 主页面
        location / {
            try_files \$uri \$uri/ =404;
        }

        # 静态资源缓存
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # 隐藏nginx版本
        server_tokens off;

        # 错误页面
        error_page 404 /404.html;
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /var/www/html;
        }
    }
}

    log_success "Nginx配置文件创建完成"
}

    log_success "Nginx配置文件创建完成"
}

# 验证Xray配置变量
validate_xray_config_vars() {
    log_info "验证Xray配置变量..."

    # 检查必要的配置文件
    local config_files=("domain.conf" "uuid.conf" "private-key.conf" "shortids.conf" "reality-dest.conf")
    for file in "${config_files[@]}"; do
        if [[ ! -f "$CONFIG_DIR/$file" ]]; then
            log_error "配置文件 $file 不存在"
            return 1
        fi
    done

    # 验证各个配置项
    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local uuid=$(cat "$CONFIG_DIR/uuid.conf")
    local private_key=$(cat "$CONFIG_DIR/private-key.conf")
    local short_ids=$(cat "$CONFIG_DIR/shortids.conf")
    local reality_dest=$(cat "$CONFIG_DIR/reality-dest.conf")

    validate_var "域名" "$domain" || return 1
    validate_var "UUID" "$uuid" || return 1
    validate_var "私钥" "$private_key" || return 1
    validate_var "ShortIds" "$short_ids" || return 1
    validate_var "Reality目标" "$reality_dest" || return 1

    log_success "Xray配置变量验证通过"
}

# 创建Xray配置文件
create_xray_config() {
    log_info "创建Xray配置文件..."

    # 验证配置变量
    validate_xray_config_vars || return 1

    local domain=$(cat "$CONFIG_DIR/domain.conf")
    local uuid=$(cat "$CONFIG_DIR/uuid.conf")
    local private_key=$(cat "$CONFIG_DIR/private-key.conf")
    local short_ids=$(cat "$CONFIG_DIR/shortids.conf")
    local reality_dest=$(cat "$CONFIG_DIR/reality-dest.conf")

    # 备份现有配置
    if [[ -f "$XRAY_CONFIG" ]]; then
        cp "$XRAY_CONFIG" "$XRAY_CONFIG.backup.$(date +%Y%m%d_%H%M%S)" || {
            log_warning "备份Xray配置失败"
        }
    fi

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
                    "dest": "$reality_dest:443",
                    "xver": 1,
                    "serverNames": [
                        "$reality_dest"
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

    # 创建备份目录
    local backup_dir="/root/reality-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    log_info "配置备份目录: $backup_dir"

    # 备份配置文件
    if [[ -d "$CONFIG_DIR" ]]; then
        cp -r "$CONFIG_DIR" "$backup_dir/" 2>/dev/null || true
        log_info "配置文件已备份"
    fi

    # 停止服务
    log_info "停止服务..."
    systemctl stop nginx 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    systemctl disable nginx 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true

    # 删除服务文件
    log_info "删除服务文件..."
    rm -f "$NGINX_SERVICE"
    systemctl daemon-reload

    # 删除配置文件
    log_info "删除配置文件..."
    rm -rf "$CONFIG_DIR"
    rm -f "$NGINX_CONFIG"
    rm -f "$XRAY_CONFIG"
    rm -rf /etc/nginx

    # 删除SSL证书
    log_info "删除SSL证书..."
    if [[ -d "/etc/ssl/private" ]]; then
        cp -r /etc/ssl/private "$backup_dir/" 2>/dev/null || true
        rm -rf /etc/ssl/private
    fi

    # 删除Nginx
    log_info "卸载Nginx..."
    rm -f /usr/sbin/nginx
    rm -rf /usr/local/nginx

    # 卸载Xray
    log_info "卸载Xray..."
    if command -v xray >/dev/null 2>&1; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null || {
            log_warning "Xray自动卸载失败，手动清理..."
            rm -f /usr/local/bin/xray
            rm -rf /usr/local/etc/xray
            rm -f /etc/systemd/system/xray.service
            systemctl daemon-reload
        }
    fi

    # 删除acme.sh
    log_info "卸载acme.sh..."
    if [[ -d "/root/.acme.sh" ]]; then
        /root/.acme.sh/acme.sh --uninstall 2>/dev/null || true
        rm -rf /root/.acme.sh
        rm -f /usr/local/bin/acme.sh
    fi

    # 清理临时文件
    log_info "清理临时文件..."
    rm -f /tmp/tcp.sh /tmp/d11.sh /tmp/nginx-*.tar.gz
    rm -rf /tmp/nginx-build

    # 清理编译依赖（可选）
    read -p "是否卸载编译依赖包？(y/N): " remove_deps
    if [[ "$remove_deps" == "y" || "$remove_deps" == "Y" ]]; then
        log_info "卸载编译依赖..."
        apt autoremove -y gcc g++ libpcre3-dev zlib1g-dev libssl-dev make 2>/dev/null || true
    fi

    log_success "Reality服务卸载完成"
    log_info "配置备份保存在: $backup_dir"
}

# 检查脚本更新
check_script_update() {
    log_info "检查脚本更新..."

    local current_version="2.0"
    local script_url="https://raw.githubusercontent.com/your-repo/vps-security-tools/main/reality-setup.sh"

    # 检查网络连接
    check_network || return 1

    # 获取远程版本信息
    local remote_version=$(curl -s --connect-timeout 10 "$script_url" | grep "# 版本:" | head -n1 | awk '{print $3}')

    if [[ -z "$remote_version" ]]; then
        log_error "无法获取远程版本信息"
        return 1
    fi

    echo -e "${BLUE}=== 版本信息 ===${NC}"
    echo "当前版本: $current_version"
    echo "远程版本: $remote_version"

    if [[ "$remote_version" != "$current_version" ]]; then
        echo -e "${YELLOW}发现新版本！${NC}"
        read -p "是否下载最新版本？(y/N): " update_choice
        if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
            log_info "下载最新版本..."
            local backup_script="reality-setup-backup-$(date +%Y%m%d_%H%M%S).sh"
            cp "$0" "$backup_script" || {
                log_error "备份当前脚本失败"
                return 1
            }

            if curl -s --connect-timeout 30 -o "reality-setup-new.sh" "$script_url"; then
                chmod +x reality-setup-new.sh
                log_success "新版本下载完成: reality-setup-new.sh"
                log_info "当前版本已备份为: $backup_script"
                log_warning "请手动替换脚本文件并重新运行"
            else
                log_error "下载失败"
                return 1
            fi
        fi
    else
        log_success "当前已是最新版本"
    fi
}

# 安装BBR加速
install_bbr() {
    log_info "开始安装BBR加速..."

    # 检查当前BBR状态
    if lsmod | grep -q bbr; then
        log_success "BBR已经启用"
        return 0
    fi

    # 警告用户外部脚本风险
    log_warning "即将下载并执行外部BBR安装脚本"
    log_warning "脚本来源: http://sh.xdmb.xyz/tcp.sh"
    read -p "是否继续？(y/N): " confirm_bbr
    if [[ "$confirm_bbr" != "y" && "$confirm_bbr" != "Y" ]]; then
        log_info "用户取消BBR安装"
        return 1
    fi

    # 检查网络连接
    check_network || return 1

    # 使用一键脚本安装BBR
    log_info "下载BBR安装脚本..."
    if wget --timeout=30 -O /tmp/tcp.sh http://sh.xdmb.xyz/tcp.sh; then
        log_info "执行BBR安装脚本..."
        log_warning "脚本可能需要用户交互，请按提示操作"
        bash /tmp/tcp.sh || {
            log_warning "BBR脚本执行可能失败，尝试手动配置..."
            manual_bbr_config
        }
        # 清理临时文件
        rm -f /tmp/tcp.sh
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

# 优雅退出处理
cleanup_and_exit() {
    log_info "正在清理临时文件..."
    rm -f /tmp/tcp.sh /tmp/d11.sh 2>/dev/null
    log_info "感谢使用Reality一键搭建脚本！"
    exit 0
}

# 设置信号处理
trap cleanup_and_exit SIGINT SIGTERM

# 主菜单
show_main_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Reality 一键搭建管理脚本    ${NC}"
    echo -e "${BLUE}    版本: 2.0 (优化版)          ${NC}"
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
    echo "14. 检查脚本更新"
    echo "15. 卸载Reality服务"
    echo "0. 退出"
    echo
}

# 主函数
main() {
    check_root
    create_config_dir
    
    while true; do
        show_main_menu
        read -p "请选择操作 (0-15): " choice
        
        case $choice in
            1)
                log_info "开始完整安装Reality服务..."

                # 显示安装摘要
                echo -e "${BLUE}=== 安装摘要 ===${NC}"
                echo "即将安装以下组件："
                echo "• 系统依赖包 (gcc, nginx编译依赖等)"
                echo "• Nginx (从源码编译)"
                echo "• Xray (官方安装脚本)"
                echo "• acme.sh (SSL证书工具)"
                echo "• Reality配置文件"
                echo
                read -p "确认开始安装？(y/N): " confirm_install
                if [[ "$confirm_install" != "y" && "$confirm_install" != "Y" ]]; then
                    log_info "安装已取消"
                    continue
                fi

                # 分阶段安装
                log_info "[1/6] 收集配置信息..."
                collect_user_input || continue

                log_info "[2/6] 验证域名解析..."
                verify_domain_resolution || continue

                log_info "[3/6] 安装系统依赖..."
                install_dependencies || continue

                log_info "[4/6] 安装和配置服务..."
                install_nginx || continue
                create_nginx_service || continue
                install_acme || continue
                request_certificate || continue
                install_xray || continue

                log_info "[5/6] 生成配置文件..."
                generate_uuid || continue
                generate_keys || continue
                generate_short_ids || continue
                create_nginx_config || continue
                create_xray_config || continue

                log_info "[6/6] 启动服务..."
                systemctl start nginx || { log_error "Nginx启动失败"; continue; }
                systemctl start xray || { log_error "Xray启动失败"; continue; }
                systemctl enable xray || { log_warning "Xray自启动设置失败"; }

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
                    log_info "可以使用菜单选项4查看详细状态"
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
                if [[ -f "$CONFIG_DIR/email.conf" ]]; then
                    echo "邮箱: $(cat $CONFIG_DIR/email.conf)"
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
                if [[ -f "$CONFIG_DIR/reality-dest.conf" ]]; then
                    echo "Reality目标: $(cat $CONFIG_DIR/reality-dest.conf)"
                fi
                if [[ -f "$CONFIG_DIR/fake-site.conf" ]]; then
                    echo "Nginx伪装网站: $(cat $CONFIG_DIR/fake-site.conf)"
                fi
                if [[ -f "$CONFIG_DIR/vless-link.txt" ]]; then
                    echo
                    echo -e "${GREEN}VLESS链接:${NC}"
                    cat $CONFIG_DIR/vless-link.txt
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
                check_script_update
                read -p "按回车键继续..."
                ;;
            15)
                log_warning "卸载Reality服务将删除所有配置和证书"
                read -p "确认卸载？(y/N): " confirm_uninstall
                if [[ "$confirm_uninstall" == "y" || "$confirm_uninstall" == "Y" ]]; then
                    uninstall_reality
                fi
                read -p "按回车键继续..."
                ;;
            0)
                cleanup_and_exit
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
