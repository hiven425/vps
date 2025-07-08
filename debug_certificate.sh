#!/bin/bash
#
# 证书问题调试脚本
# 用于快速诊断 setup.sh 中证书相关的问题
#

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo "=== 证书问题调试脚本 ==="
echo ""

# 1. 检查配置文件
log_info "检查配置文件..."
if [ -f "/etc/setup/config.ini" ]; then
    log_success "配置文件存在"
    echo "配置内容："
    cat /etc/setup/config.ini
    echo ""
    
    # 读取域名
    MY_DOMAIN=$(grep "MY_DOMAIN=" /etc/setup/config.ini | cut -d'=' -f2)
    log_info "检测到域名: $MY_DOMAIN"
else
    log_error "配置文件不存在: /etc/setup/config.ini"
    echo "请先运行 setup.sh 进行初始配置"
    exit 1
fi

# 2. 检查 acme.sh 安装
log_info "检查 acme.sh 安装状态..."
if [ -f "/root/.acme.sh/acme.sh" ]; then
    log_success "acme.sh 已安装"
    /root/.acme.sh/acme.sh --version
else
    log_error "acme.sh 未安装"
    exit 1
fi

# 3. 检查证书文件
log_info "检查证书文件状态..."
CERT_DIR="/root/.acme.sh/${MY_DOMAIN}_ecc"
if [ -d "$CERT_DIR" ]; then
    log_success "证书目录存在: $CERT_DIR"
    echo "证书文件列表："
    ls -la "$CERT_DIR"
    echo ""
    
    # 检查关键文件
    if [ -f "$CERT_DIR/fullchain.cer" ]; then
        log_success "证书文件存在"
        log_info "证书有效期："
        openssl x509 -in "$CERT_DIR/fullchain.cer" -noout -dates
    else
        log_error "证书文件不存在: $CERT_DIR/fullchain.cer"
    fi
    
    if [ -f "$CERT_DIR/${MY_DOMAIN}.key" ]; then
        log_success "私钥文件存在"
    else
        log_error "私钥文件不存在: $CERT_DIR/${MY_DOMAIN}.key"
    fi
else
    log_error "证书目录不存在: $CERT_DIR"
fi

# 4. 检查目标证书目录
log_info "检查目标证书目录..."
if [ -d "/etc/ssl/private" ]; then
    log_success "目标目录存在: /etc/ssl/private"
    echo "目录内容："
    ls -la /etc/ssl/private/
    echo ""
else
    log_warn "目标目录不存在，创建中..."
    mkdir -p /etc/ssl/private
    log_success "目录已创建"
fi

# 5. 测试证书安装
log_info "测试证书安装..."
if [ -f "$CERT_DIR/fullchain.cer" ] && [ -f "$CERT_DIR/${MY_DOMAIN}.key" ]; then
    log_info "尝试手动安装证书..."
    
    # 不使用 reloadcmd，避免 nginx 问题
    /root/.acme.sh/acme.sh --install-cert -d "$MY_DOMAIN" --ecc \
        --key-file       /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer
    
    INSTALL_STATUS=$?
    if [ $INSTALL_STATUS -eq 0 ]; then
        log_success "证书安装成功"
        
        # 检查安装结果
        if [ -f "/etc/ssl/private/fullchain.cer" ] && [ -f "/etc/ssl/private/private.key" ]; then
            log_success "证书文件已正确复制到目标位置"
            
            # 设置权限
            chmod 600 /etc/ssl/private/private.key
            chmod 644 /etc/ssl/private/fullchain.cer
            log_success "权限设置完成"
            
            # 验证证书
            log_info "验证证书有效性..."
            if openssl x509 -in /etc/ssl/private/fullchain.cer -noout -text > /dev/null 2>&1; then
                log_success "证书格式正确"
            else
                log_error "证书格式有问题"
            fi
        else
            log_error "证书文件复制失败"
        fi
    else
        log_error "证书安装失败，状态码: $INSTALL_STATUS"
        log_info "显示 acme.sh 日志："
        tail -n 20 /root/.acme.sh/acme.sh.log
    fi
else
    log_error "源证书文件不完整，无法进行安装测试"
fi

# 6. 检查 Cloudflare API
log_info "检查 Cloudflare API 配置..."
if [ -n "$CF_Token" ]; then
    log_success "CF_Token 已设置"
else
    log_warn "CF_Token 未设置，这可能导致证书申请失败"
fi

echo ""
echo "=== 调试完成 ==="
echo ""
echo "如果证书安装成功，你可以继续运行 setup.sh"
echo "如果仍有问题，请将上述输出发送给技术支持"
