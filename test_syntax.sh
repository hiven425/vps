#!/bin/bash

# 简单的语法检查脚本
echo "检查 security-hardening.sh 脚本语法..."

# 使用 bash -n 检查语法
if bash -n security-hardening.sh 2>/dev/null; then
    echo "✓ 脚本语法检查通过"
    exit 0
else
    echo "✗ 脚本语法检查失败"
    echo "详细错误信息："
    bash -n security-hardening.sh
    exit 1
fi
