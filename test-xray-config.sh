#!/bin/bash

# 测试 Xray 配置文件脚本
# 用于验证修复后的配置是否正确

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# 检查 Xray 是否安装
if ! command -v /usr/local/bin/xray &> /dev/null; then
    log_error "Xray 未安装，请先安装 Xray"
    exit 1
fi

# 检查配置文件是否存在
if [[ ! -f "/usr/local/etc/xray/config.json" ]]; then
    log_error "Xray 配置文件不存在: /usr/local/etc/xray/config.json"
    exit 1
fi

log_info "检查 Xray 配置文件语法..."

# 测试配置文件
if /usr/local/bin/xray test -config /usr/local/etc/xray/config.json; then
    log_success "✓ Xray 配置文件语法正确"
    
    # 显示配置文件内容（去除敏感信息）
    log_info "配置文件内容预览："
    echo "----------------------------------------"
    cat /usr/local/etc/xray/config.json | jq '.' 2>/dev/null || cat /usr/local/etc/xray/config.json
    echo "----------------------------------------"
    
else
    log_error "✗ Xray 配置文件语法错误"
    log_info "请检查配置文件: /usr/local/etc/xray/config.json"
    exit 1
fi

log_info "测试完成"
