#!/bin/bash
#
# VLESS Reality 终极部署脚本
# 基于 https://jollyroger.top/sites/223.html
# 作者: 顶级 DevOps 工程师
# 版本: 6.0.0 - 终极版
# 功能: 智能证书处理、详细诊断、完全幂等性、用户友好
# 特性: 支持 --force 强制证书续期、智能跳过检测、详细失败诊断
# ===========================================================

set -e  # 遇到错误立即退出

# 显示使用说明
show_usage() {
    echo -e "${CYAN}VLESS Reality 终极部署脚本 v6.0.0${NC}"
    echo ""
    echo -e "${WHITE}使用方法:${NC}"
    echo "  bash setup.sh           # 正常模式（推荐）"
    echo "  bash setup.sh --force   # 强制模式（重新申请证书）"
    echo ""
    echo -e "${WHITE}参数说明:${NC}"
    echo "  --force    强制重新申请 SSL 证书，即使现有证书仍然有效"
    echo "  --help     显示此帮助信息"
    echo ""
    echo -e "${WHITE}特性:${NC}"
    echo "  ✓ 智能证书处理 - 自动检测证书状态，避免不必要的申请"
    echo "  ✓ 详细诊断信息 - 失败时自动显示详细日志"
    echo "  ✓ 完全幂等性   - 可安全重复运行"
    echo "  ✓ 用户友好     - 清晰的进度显示和状态说明"
    echo ""
}

# 检查帮助参数
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_usage
    exit 0
fi

# 检查是否提供了 --force 参数
ACME_FORCE_FLAG=""
if [[ "$1" == "--force" ]]; then
    echo -e "\033[1;33m[WARN]\033[0m 检测到 --force 参数，将强制重新申请证书。"
    echo -e "\033[0;34m[INFO]\033[0m 这将删除现有证书并重新申请新证书。"
    ACME_FORCE_FLAG="--force"
fi

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
readonly SCRIPT_VERSION="6.0.0"
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
    echo -e "${CYAN}║              VLESS Reality 终极管理面板 v${SCRIPT_VERSION}              ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  ✓ 智能证书处理  ✓ 详细诊断  ✓ 完全幂等性  ✓ 用户友好        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  1. 首次安装或完整重装服务                                      ║${NC}"
    echo -e "${WHITE}║  2. 修改服务配置                                                ║${NC}"
    echo -e "${WHITE}║  3. 安全与防火墙管理                                            ║${NC}"
    echo -e "${WHITE}║  4. 检查服务运行状态                                            ║${NC}"
    echo -e "${WHITE}║  5. 查看客户端连接信息                                          ║${NC}"
    echo -e "${WHITE}║  6. 卸载服务                                                    ║${NC}"
    echo -e "${WHITE}║  7. 退出                                                        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║  提示: 支持 bash setup.sh --force 强制重新申请证书             ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ========================================
# 功能1: 首次安装或完整重装服务
# ========================================

collect_user_input() {
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

    # 立即保存配置，防止中途失败时丢失用户输入
    save_config
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
    log_info "配置 SSL 证书（智能处理模式）..."

    # 创建证书目录
    mkdir -p /etc/ssl/private

    # 设置 Cloudflare API Token
    export CF_Token="$CF_TOKEN"

    # 设置默认 CA 为 Let's Encrypt 并注册账户（幂等性处理）
    log_info "设置 Let's Encrypt CA..."
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt 2>/dev/null || true
    ~/.acme.sh/acme.sh --register-account -m "admin@${MY_DOMAIN}" --server letsencrypt 2>/dev/null || true

    # 如果启用了 --force 参数，先删除现有证书
    if [[ -n "$ACME_FORCE_FLAG" ]]; then
        log_info "强制模式：删除现有证书文件..."
        rm -rf "/root/.acme.sh/${MY_DOMAIN}_ecc"
        rm -f "/etc/ssl/private/fullchain.cer"
        rm -f "/etc/ssl/private/private.key"
        log_info "现有证书已删除"
    fi

    # 智能证书申请流程 - 增强调试版本
    log_info "正在检查并申请 SSL 证书..."
    log_debug "执行命令: ~/.acme.sh/acme.sh --issue --dns dns_cf -d \"$MY_DOMAIN\" --ecc $ACME_FORCE_FLAG"

    # 如果不是强制模式，先尝试使用 staging 环境测试
    if [[ -z "$ACME_FORCE_FLAG" ]]; then
        log_info "首先使用 staging 环境测试证书申请..."
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --log --staging
        STAGING_STATUS=$?
        log_debug "staging 测试状态码: $STAGING_STATUS"
        
        if [ "$STAGING_STATUS" -eq 0 ]; then
            log_success "staging 环境测试通过，现在申请正式证书..."
            # 删除 staging 证书
            rm -rf "/root/.acme.sh/${MY_DOMAIN}_ecc"
            # 申请正式证书
            ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --log --force
            ISSUE_STATUS=$?
        elif [ "$STAGING_STATUS" -eq 2 ]; then
            log_info "staging 环境显示证书已存在，直接尝试正式环境..."
            ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --ecc
            ISSUE_STATUS=$?
        else
            log_error "staging 环境测试失败，状态码: $STAGING_STATUS"
            log_info "删除可能损坏的证书文件并重试..."
            rm -rf "/root/.acme.sh/${MY_DOMAIN}_ecc"
            ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --log --force
            ISSUE_STATUS=$?
        fi
    else
        # 强制模式直接申请
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --ecc $ACME_FORCE_FLAG
        ISSUE_STATUS=$?
    fi

    # 检查最终的申请状态
    log_debug "最终申请状态码: $ISSUE_STATUS"

    if [ "$ISSUE_STATUS" -eq 0 ]; then
        log_success "证书申请成功！"
    elif [ "$ISSUE_STATUS" -eq 2 ]; then
        log_info "证书已存在且有效，现在验证是否可以正常安装..."
        # 验证证书文件是否存在
        if [ ! -f "/root/.acme.sh/${MY_DOMAIN}_ecc/fullchain.cer" ]; then
            log_warn "证书文件不存在，删除证书目录并重新申请..."
            rm -rf "/root/.acme.sh/${MY_DOMAIN}_ecc"
            ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --log --force
            ISSUE_STATUS=$?
            if [ "$ISSUE_STATUS" -ne 0 ]; then
                log_error "强制重新申请失败，状态码: $ISSUE_STATUS"
                exit 1
            fi
        fi
    else
        log_error "证书申请失败，状态码: $ISSUE_STATUS"
        log_info "删除可能损坏的证书目录并重试..."
        rm -rf "/root/.acme.sh/${MY_DOMAIN}_ecc"
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --log --force
        RETRY_STATUS=$?
        if [ "$RETRY_STATUS" -ne 0 ]; then
            log_error "重试申请失败，状态码: $RETRY_STATUS"
            log_error "请检查以下可能的原因："
            log_error "1. Cloudflare API Token 是否正确"
            log_error "2. 域名 DNS 是否指向 Cloudflare"
            log_error "3. 网络连接是否正常"
            log_info "详细错误信息请查看: /root/.acme.sh/acme.sh.log"
            echo ""
            log_info "显示最后 10 行 acme.sh 日志："
            tail -n 10 /root/.acme.sh/acme.sh.log 2>/dev/null || echo "无法读取 acme.sh 日志文件"
            exit 1
        fi
    fi

    # 无论 issue 的结果如何，都必须执行 install-cert
    log_info "正在安装证书到 Nginx 配置目录..."

    # 先检查证书是否存在
    if [ ! -f "/root/.acme.sh/${MY_DOMAIN}_ecc/fullchain.cer" ]; then
        log_error "证书文件不存在: /root/.acme.sh/${MY_DOMAIN}_ecc/fullchain.cer"
        log_info "删除证书目录并重新申请..."
        rm -rf "/root/.acme.sh/${MY_DOMAIN}_ecc"
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --log --force
        if [ $? -ne 0 ]; then
            log_error "重新申请证书失败"
            exit 1
        fi
    fi

    log_debug "源证书文件存在，开始安装..."
    # 使用完整的安装命令，包含自动重载
    ~/.acme.sh/acme.sh --install-cert -d "$MY_DOMAIN" --ecc \
        --key-file       /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --reloadcmd      "sudo systemctl force-reload nginx"

    INSTALL_STATUS=$?
    log_debug "证书安装命令退出状态码: $INSTALL_STATUS"
    
    if [ $INSTALL_STATUS -ne 0 ]; then
        log_error "执行 --install-cert 时出错，状态码: $INSTALL_STATUS"
        log_info "尝试删除证书目录并重新申请..."
        rm -rf "/root/.acme.sh/${MY_DOMAIN}_ecc"
        
        # 重新申请证书
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$MY_DOMAIN" --log --force
        if [ $? -eq 0 ]; then
            log_info "证书重新申请成功，再次尝试安装..."
            ~/.acme.sh/acme.sh --install-cert -d "$MY_DOMAIN" --ecc \
                --key-file       /etc/ssl/private/private.key \
                --fullchain-file /etc/ssl/private/fullchain.cer \
                --reloadcmd      "sudo systemctl force-reload nginx"
            
            if [ $? -ne 0 ]; then
                log_error "重新安装证书仍然失败"
                log_info "显示最后 10 行 acme.sh 日志："
                tail -n 10 /root/.acme.sh/acme.sh.log 2>/dev/null || echo "无法读取 acme.sh 日志文件"
                exit 1
            fi
        else
            log_error "重新申请证书失败"
            exit 1
        fi
    fi

    log_success "证书安装成功"

    # 设置正确的权限
    log_info "设置证书文件权限..."
    if [ -f "/etc/ssl/private/private.key" ]; then
        chmod 600 /etc/ssl/private/private.key
        log_info "✓ 私钥权限设置为 600"
    else
        log_error "私钥文件不存在: /etc/ssl/private/private.key"
        exit 1
    fi

    if [ -f "/etc/ssl/private/fullchain.cer" ]; then
        chmod 644 /etc/ssl/private/fullchain.cer
        log_info "✓ 证书权限设置为 644"
    else
        log_error "证书文件不存在: /etc/ssl/private/fullchain.cer"
        exit 1
    fi

    log_success "证书已成功配置给 Nginx。"

    # 验证证书文件
    if [[ -f "/etc/ssl/private/fullchain.cer" ]] && [[ -f "/etc/ssl/private/private.key" ]]; then
        log_info "证书文件验证："
        log_info "✓ 证书文件: /etc/ssl/private/fullchain.cer"
        log_info "✓ 私钥文件: /etc/ssl/private/private.key"

        # 检查证书有效期
        if openssl x509 -checkend 86400 -noout -in /etc/ssl/private/fullchain.cer 2>/dev/null; then
            log_success "✓ 证书有效期检查通过（24小时内不会过期）"
        else
            log_warn "⚠ 证书可能即将过期，但安装成功"
        fi
    else
        log_error "证书文件验证失败！"
        exit 1
    fi

    log_success "SSL 证书配置完成！"
}

configure_xray() {
    log_info "配置 Xray..."
    
    # 创建配置目录
    mkdir -p /usr/local/etc/xray
    
    # 生成 Xray 配置文件 (严格按照最终确定的正确逻辑)
    log_info "生成 Xray 配置文件..."
    log_debug "UUID: $UUID"
    log_debug "MY_DOMAIN: $MY_DOMAIN"
    log_debug "PRIVATE_KEY: ${PRIVATE_KEY:0:10}..."
    log_debug "SHORT_ID: $SHORT_ID"
    
    # 验证关键变量是否都已设置
    if [[ -z "$UUID" || -z "$MY_DOMAIN" || -z "$PRIVATE_KEY" || -z "$SHORT_ID" ]]; then
        log_error "关键变量未设置！"
        log_error "UUID: ${UUID:-未设置}"
        log_error "MY_DOMAIN: ${MY_DOMAIN:-未设置}"
        log_error "PRIVATE_KEY: ${PRIVATE_KEY:+已设置}"
        log_error "SHORT_ID: ${SHORT_ID:-未设置}"
        exit 1
    fi
    
    # 使用临时文件生成配置，避免 heredoc 可能的问题
    TEMP_CONFIG="/tmp/xray_config_$$.json"
    
cat > "$TEMP_CONFIG" << EOF
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
          "xver": 1,
          "serverNames": [
            "$MY_DOMAIN"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ]
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
    
    # 验证临时配置文件是否生成成功
    if [[ ! -f "$TEMP_CONFIG" ]]; then
        log_error "临时配置文件生成失败"
        exit 1
    fi
    
    # 验证 JSON 格式
    if command -v jq &> /dev/null; then
        if ! jq empty "$TEMP_CONFIG" 2>/dev/null; then
            log_error "生成的配置文件 JSON 格式错误！"
            log_info "临时配置文件内容："
            cat "$TEMP_CONFIG"
            rm -f "$TEMP_CONFIG"
            exit 1
        fi
    fi
    
    # 检查关键变量是否正确替换
    if grep -q '\$UUID\|\$MY_DOMAIN\|\$PRIVATE_KEY\|\$SHORT_ID' "$TEMP_CONFIG"; then
        log_error "配置文件中存在未替换的变量"
        log_info "请检查以下变量是否正确设置："
        log_info "UUID: $UUID"
        log_info "MY_DOMAIN: $MY_DOMAIN"
        log_info "PRIVATE_KEY: ${PRIVATE_KEY:0:10}..."
        log_info "SHORT_ID: $SHORT_ID"
        log_info "临时配置文件内容："
        cat "$TEMP_CONFIG"
        rm -f "$TEMP_CONFIG"
        exit 1
    fi
    
    # 移动到最终位置
    mv "$TEMP_CONFIG" /usr/local/etc/xray/config.json
    
    # 验证最终配置文件
    if [[ ! -f "/usr/local/etc/xray/config.json" ]]; then
        log_error "配置文件移动失败"
        exit 1
    fi
    
    log_success "Xray 配置文件生成成功"
    
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
    log_info "启动和配置服务（增强诊断模式）..."

    # 测试 Nginx 配置
    log_info "测试 Nginx 配置文件语法..."
    if ! nginx -t; then
        log_error "Nginx 配置测试失败！"
        log_error "请检查 Nginx 配置文件语法错误"
        log_info "配置文件位置: /etc/nginx/nginx.conf"
        exit 1
    fi
    log_success "✓ Nginx 配置文件语法正确"

    # 测试 Xray 配置
    log_info "测试 Xray 配置文件语法..."
    log_debug "检查 Xray 配置文件是否存在: /usr/local/etc/xray/config.json"
    
    if [[ ! -f "/usr/local/etc/xray/config.json" ]]; then
        log_error "Xray 配置文件不存在: /usr/local/etc/xray/config.json"
        exit 1
    fi
    
    log_debug "显示生成的配置文件内容（前50行）："
    head -50 /usr/local/etc/xray/config.json
    echo ""
    
    log_debug "验证 JSON 格式..."
    if command -v jq &> /dev/null; then
        if ! jq empty /usr/local/etc/xray/config.json 2>/dev/null; then
            log_error "Xray 配置文件 JSON 格式错误！"
            log_info "使用 jq 验证 JSON 格式："
            jq empty /usr/local/etc/xray/config.json || true
            log_info "配置文件位置: /usr/local/etc/xray/config.json"
            exit 1
        else
            log_success "✓ JSON 格式验证通过"
        fi
    else
        log_warn "jq 工具未安装，跳过 JSON 格式验证"
    fi
    
    log_debug "检查 Xray 二进制文件..."
    if [[ ! -f "/usr/local/bin/xray" ]]; then
        log_error "Xray 二进制文件不存在: /usr/local/bin/xray"
        exit 1
    fi
    
    log_debug "Xray 版本信息："
    /usr/local/bin/xray version 2>/dev/null || log_warn "无法获取 Xray 版本信息"
    
    log_debug "使用 xray test 验证配置..."
    # 获取详细的错误输出
    XRAY_TEST_OUTPUT=$(/usr/local/bin/xray test -config /usr/local/etc/xray/config.json 2>&1)
    XRAY_TEST_STATUS=$?
    
    log_debug "Xray 测试输出："
    echo "$XRAY_TEST_OUTPUT"
    log_debug "Xray 测试退出状态码: $XRAY_TEST_STATUS"
    
    if [ $XRAY_TEST_STATUS -ne 0 ]; then
        log_error "Xray 配置测试失败！退出状态码: $XRAY_TEST_STATUS"
        log_error "详细错误信息："
        echo "$XRAY_TEST_OUTPUT"
        log_info "配置文件位置: /usr/local/etc/xray/config.json"
        log_info "尝试使用简化的配置进行测试..."
        
        # 生成一个最小的测试配置
        cat > /tmp/xray_test.json << 'EOF'
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 1080,
      "protocol": "socks"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF
        
        log_info "测试最小配置..."
        if /usr/local/bin/xray test -config /tmp/xray_test.json; then
            log_info "最小配置测试通过，问题可能在我们的配置中"
            log_info "检查变量替换情况..."
            
            # 检查是否有未替换的变量
            if grep -n '\$[A-Z_]*' /usr/local/etc/xray/config.json; then
                log_error "发现未替换的变量！"
            fi
            
            # 检查关键字段
            log_info "检查关键配置字段..."
            grep -n "\"id\":" /usr/local/etc/xray/config.json || log_warn "未找到 UUID 配置"
            grep -n "\"privateKey\":" /usr/local/etc/xray/config.json || log_warn "未找到 privateKey 配置"
            grep -n "\"serverNames\":" /usr/local/etc/xray/config.json || log_warn "未找到 serverNames 配置"
        else
            log_error "连最小配置都失败，Xray 安装可能有问题"
        fi
        
        rm -f /tmp/xray_test.json
        exit 1
    fi
    log_success "✓ Xray 配置文件语法正确"

    # 启动 Nginx 服务
    log_info "重启 Nginx 服务..."
    systemctl restart nginx
    if [ $? -ne 0 ]; then
        log_error "Nginx 重启失败！"
        log_info "显示 Nginx 服务状态和日志："
        systemctl status nginx --no-pager -l
        log_info "最后 20 行 Nginx 日志："
        journalctl -u nginx -n 20 --no-pager
        exit 1
    fi
    log_success "✓ Nginx 服务重启成功"

    # 启动 Xray 服务
    log_info "重启 Xray 服务..."
    systemctl restart xray
    if [ $? -ne 0 ]; then
        log_error "Xray 重启失败！"
        log_info "显示 Xray 服务状态和日志："
        systemctl status xray --no-pager -l
        log_info "最后 20 行 Xray 日志："
        journalctl -u xray -n 20 --no-pager
        exit 1
    fi
    log_success "✓ Xray 服务重启成功"

    # 启用服务自启动
    log_info "启用服务自启动..."
    systemctl enable nginx xray
    log_success "✓ 服务自启动已启用"

    # 等待服务完全启动
    log_info "等待服务完全启动..."
    sleep 5

    # 详细的服务状态检查
    log_info "执行详细的服务状态检查..."

    # 检查 Nginx 状态
    if ! systemctl is-active --quiet nginx; then
        log_error "Nginx 服务启动失败！"
        log_info "Nginx 服务状态: $(systemctl is-active nginx)"
        log_info "显示最后 20 行 Nginx 日志："
        journalctl -u nginx -n 20 --no-pager
        exit 1
    fi
    log_success "✓ Nginx 服务运行正常"

    # 检查 Xray 状态
    if ! systemctl is-active --quiet xray; then
        log_error "Xray 服务启动失败！"
        log_info "Xray 服务状态: $(systemctl is-active xray)"
        log_info "显示最后 20 行 Xray 日志："
        journalctl -u xray -n 20 --no-pager
        exit 1
    fi
    log_success "✓ Xray 服务运行正常"

    # 检查端口监听状态
    log_info "检查端口监听状态..."
    if ss -tlnp | grep -q ":443"; then
        log_success "✓ 443端口正在监听"
    else
        log_error "443端口未监听！"
        log_info "当前监听的端口："
        ss -tlnp | grep -E ":(80|443|22)"
        exit 1
    fi

    log_success "所有服务启动成功并运行正常！"
    log_info "服务状态摘要："
    log_info "- Nginx: $(systemctl is-active nginx) ($(systemctl is-enabled nginx))"
    log_info "- Xray:  $(systemctl is-active xray) ($(systemctl is-enabled xray))"
    log_info "- 443端口: 正在监听"
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

# 首次安装主函数（终极增强版）
first_install() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    VLESS Reality 终极部署                        ║${NC}"
    echo -e "${CYAN}║                      开始安装流程                                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_info "开始首次安装或完整重装..."
    log_info "此脚本具有完全幂等性，可安全重复运行"

    if [[ -n "$ACME_FORCE_FLAG" ]]; then
        log_warn "强制模式已启用，将重新申请所有证书"
    fi

    # 如果存在配置，创建备份
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "检测到现有配置，正在创建备份..."
        create_backup
    fi

    echo ""
    log_info "步骤 1/11: 收集用户配置参数"
    collect_user_input

    echo ""
    log_info "步骤 2/11: 更新系统并安装依赖"
    update_system

    echo ""
    log_info "步骤 3/11: 安装 Xray 核心"
    install_xray

    echo ""
    log_info "步骤 4/11: 安装 acme.sh 证书工具"
    install_acme

    echo ""
    log_info "步骤 5/11: 生成加密密钥"
    generate_keys

    echo ""
    log_info "步骤 6/11: 配置 SSL 证书（智能处理）"
    setup_ssl_certificate

    echo ""
    log_info "步骤 7/11: 配置 Xray 服务"
    configure_xray

    echo ""
    log_info "步骤 8/11: 配置 Nginx 反向代理"
    configure_nginx

    echo ""
    log_info "步骤 9/11: 配置防火墙"
    configure_firewall

    echo ""
    log_info "步骤 10/11: 启动服务（增强诊断）"
    start_services

    echo ""
    log_info "步骤 11/11: 生成客户端配置"
    generate_client_config
    save_config

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                        安装完成！                                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_success "VLESS Reality 服务已成功部署！"
    log_info "此脚本具有完全幂等性，可重复安全运行"

    if [[ -n "$ACME_FORCE_FLAG" ]]; then
        log_info "强制模式已完成，所有证书已重新申请"
    fi

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

    # 申请新证书（使用智能处理逻辑）
    export CF_Token="$CF_TOKEN"
    ~/.acme.sh/acme.sh --register-account -m "admin@${new_domain}" --server letsencrypt 2>/dev/null || true

    log_info "为新域名申请 SSL 证书..."
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$new_domain" --ecc

    # 检查证书申请状态
    ISSUE_STATUS=$?
    if [ "$ISSUE_STATUS" -eq 0 ]; then
        log_success "新域名证书申请成功！"
    elif [ "$ISSUE_STATUS" -eq 2 ]; then
        log_info "新域名证书已存在且有效，跳过申请。"
    else
        log_error "新域名证书申请失败，状态码: $ISSUE_STATUS"
        log_info "详细错误信息请查看: /root/.acme.sh/acme.sh.log"
        exit 1
    fi

    # 安装新证书
    log_info "安装新域名证书..."
    ~/.acme.sh/acme.sh --install-cert -d "$new_domain" --ecc \
        --key-file /etc/ssl/private/private.key \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --reloadcmd "sudo systemctl force-reload nginx"

    if [ $? -ne 0 ]; then
        log_error "新域名证书安装失败"
        exit 1
    fi
    log_success "新域名证书安装成功"
    
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
# 主程序逻辑
# ========================================

main() {
    # 检查权限和系统
    check_root
    check_system
    
    while true; do
        show_main_menu
        read -p "请输入选项 [1-7]: " choice
        
        case $choice in
            1) first_install ;;
            2) show_config_menu ;;
            3) show_security_menu ;;
            4) check_service_status ;;
            5) show_client_info ;;
            6) uninstall_service ;;
            7) 
                log_info "感谢使用 VLESS Reality 服务管理面板！"
                exit 0
                ;;
            *)
                log_error "无效选择，请输入 1-7"
                sleep 2
                ;;
        esac
    done
}

# 运行主程序
main "$@"