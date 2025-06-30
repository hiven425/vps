#!/bin/bash

# 测试配置修复
echo "=== 测试VLESS-TCP-HTTP-REALITY配置修复 ==="

# 模拟配置参数
port="443"
dest_domain="www.microsoft.com"
private_key="test_private_key"
public_key="test_public_key"
short_ids_config='"abc123", "def456"'
clients_config='{"id": "test-uuid", "email": "test@example.com"}'
listen_config='"listen": "0.0.0.0",'

# 生成测试配置
cat > test_xray_config.json << EOF
{
    "inbounds": [
        {
            $listen_config
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [$clients_config
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "$dest_domain:443",
                    "xver": 0,
                    "serverNames": [
                        "$dest_domain"
                    ],
                    "privateKey": "$private_key",
                    "shortIds": [
                        $short_ids_config
                    ]
                },
                "tcpSettings": {
                    "header": {
                        "type": "http",
                        "request": {
                            "version": "1.1",
                            "method": "GET",
                            "path": ["/"],
                            "headers": {
                                "Host": ["$dest_domain"],
                                "User-Agent": [
                                    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
                                    "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"
                                ],
                                "Accept-Encoding": ["gzip, deflate"],
                                "Connection": ["keep-alive"],
                                "Pragma": "no-cache"
                            }
                        }
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF

echo "✅ 测试配置已生成: test_xray_config.json"

# 验证JSON语法
if command -v jq &> /dev/null; then
    echo "🔍 验证JSON语法..."
    if jq . test_xray_config.json > /dev/null 2>&1; then
        echo "✅ JSON语法正确"
    else
        echo "❌ JSON语法错误"
        exit 1
    fi
else
    echo "⚠️  jq未安装，跳过JSON语法检查"
fi

# 显示关键配置
echo ""
echo "📋 关键配置信息："
echo "- 网络类型: tcp"
echo "- 伪装类型: http"
echo "- 安全协议: reality"
echo "- 目标域名: $dest_domain"
echo "- 监听端口: $port"

echo ""
echo "🎯 修复要点："
echo "1. 从 h2 改为 tcp 网络"
echo "2. 添加 tcpSettings 配置 HTTP 伪装"
echo "3. 保持 REALITY 安全配置不变"
echo "4. 客户端链接使用 type=tcp&headerType=http"

echo ""
echo "✅ 配置修复测试完成！"
