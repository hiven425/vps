# VPS 安全工具集

专业级的VPS安全加固和代理服务部署工具集，包含两个核心脚本：VPS安全加固工具和VLESS Reality代理部署脚本。

## 🎯 工具集概述

### 🛡️ VPS安全加固工具 (vps-security.sh)
- **一键安全加固**: 自动配置SSH、防火墙、入侵防护
- **交互式菜单**: 友好的图形化菜单界面
- **智能检测**: 自动检测现有安全配置，避免重复操作
- **模块化管理**: 独立管理SSH、Fail2ban、UFW各个组件
- **安全状态检查**: 全面的安全状态诊断和报告

### 🌐 Reality代理部署工具 (reality-setup.sh)
- **智能证书处理**: 精确处理acme.sh的不同状态，支持强制续期
- **详细失败诊断**: 自动显示服务日志，配置验证，端口检查
- **完全幂等性**: 可安全重复运行，智能跳过已完成步骤
- **企业级伪装**: 生成逼真的企业网站作为流量伪装
- **完整管理功能**: 支持配置重置、服务管理、链接生成

## 📁 项目结构

```
vps/
├── README.md                    # 项目说明文档
├── vps-security.sh             # VPS安全加固脚本
└── reality-setup.sh             # Reality代理部署脚本
```

### 脚本功能说明

| 脚本 | 主要功能 | 适用场景 | 交互性 | 推荐度 |
|------|----------|----------|--------|--------|
| vps-security.sh | SSH加固、防火墙、入侵防护 | VPS安全加固 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| reality-setup.sh | VLESS-Reality代理部署 | 代理服务搭建 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## 🚀 快速开始

### 🛡️ VPS安全加固

```bash
# 添加执行权限
chmod +x vps-security.sh

# 运行安全加固脚本
sudo ./vps-security.sh
```

**主要功能：**
- 🚀 一键安全加固（推荐新手）
- 🔧 SSH安全配置
- 🛡️ Fail2ban入侵防护
- 🔥 UFW防火墙配置
- 📊 安全状态检查
- ⚙️ 服务管理界面

### 🌐 Reality代理部署

```bash
# 添加执行权限
chmod +x reality-setup.sh

# 运行Reality部署脚本
sudo ./reality-setup.sh
```

**主要功能：**
- 🎯 完整安装Reality服务
- 🔄 服务管理（重启、状态检查）
- 🔧 配置重置（UUID、密钥、ShortIds）
- 📱 生成VLESS客户端链接
- 🚀 BBR加速和TCP优化
- 🗑️ 完整卸载功能

### 配置管理功能
- **更换主域名**: 申请新证书并更新所有相关配置
- **更换伪装域名**: 更新 Nginx 反向代理配置
- **重新生成 UUID**: 生成新的用户标识符
- **重新生成 Reality 密钥对**: 更新加密密钥
- **重新生成 ShortId**: 更新短标识符

## 🚀 快速开始

### 系统要求
- **操作系统**: Debian/Ubuntu (推荐 Ubuntu 20.04+)
- **权限**: Root 用户权限
- **网络**: 稳定的互联网连接
- **域名**: 已解析到服务器的域名（仅Reality脚本需要）
- **Cloudflare**: Cloudflare API Token（仅Reality脚本需要，用于DNS验证）

## 🎯 VPS安全加固脚本详解 (vps-security.sh)

### 交互式菜单功能
1. **一键安全加固** - 推荐新手使用
   - 自动配置SSH安全（端口、密钥、禁用密码登录）
   - 配置UFW防火墙规则
   - 安装和配置Fail2ban入侵防护
   - 智能检测现有配置，避免重复操作

2. **模块化管理**
   - SSH安全配置（端口修改、密钥管理）
   - Fail2ban管理（状态查看、IP解封）
   - UFW防火墙管理（规则添加、删除、重置）
   - 安全状态检查（全面的安全诊断）

## 🎯 Reality代理脚本详解 (reality-setup.sh)

### 主菜单功能
1. **完整安装Reality服务** - 一键安装所有组件
   - 自动安装系统依赖
   - 编译安装Nginx（支持必要模块）
   - 安装Xray和acme.sh
   - 申请SSL证书
   - 生成密钥和配置文件
   - 启动所有服务

2. **服务管理**
   - 重启Xray服务
   - 重启Nginx服务
   - 查看服务状态（详细诊断）

3. **配置管理**
   - 重置UUID（自动更新配置并重启服务）
   - 重置密钥对（自动更新配置并重启服务）
   - 重置ShortIds（自动更新配置并重启服务）
   - 重置所有配置（一键重置所有参数）

4. **信息查看**
   - 显示当前配置（域名、UUID、密钥等）
   - 生成VLESS链接（自动生成客户端连接链接）

5. **系统管理**
   - 卸载Reality服务（完整清理所有组件）

### 伪装网站选择
脚本内置20个优质伪装网站：
- **游戏类**: www.csgo.com
- **电商类**: shopify.com
- **工具类**: time.is, ip.sb
- **生活类**: icook.hk, icook.tw
- **地区类**: japan.com, malaysia.com, russia.com, singapore.com
- **技术类**: skk.moe, linux.do
- **金融类**: www.visa.com.sg, www.visa.com.hk 等
- **政府类**: www.gco.gov.qa, www.gov.se, www.gov.ua
- **自定义**: 支持用户输入任意域名

### 配置文件管理
所有配置存储在 `/etc/reality-config/` 目录：
```
/etc/reality-config/
├── domain.conf          # 主域名
├── cf-token.conf        # Cloudflare API Token
├── uuid.conf            # 用户UUID
├── private-key.conf     # Reality私钥
├── public-key.conf      # Reality公钥
├── shortids.conf        # ShortIds配置
├── fake-site.conf       # 伪装网站
└── vless-link.txt       # VLESS连接链接
```

## 🔍 智能证书处理详解

### 证书状态检测
脚本会智能检测 `acme.sh` 的退出状态码：

| 状态码 | 含义 | 脚本行为 | 用户看到的信息 |
|--------|------|----------|----------------|
| 0 | 新证书申请成功 | 继续安装证书 | `[SUCCESS] 新证书已成功签发！` |
| 2 | 证书已存在且有效 | 继续安装证书 | `[INFO] 证书已存在且在有效期内。跳过续期是正确的行为。` |
| 其他 | 申请失败 | 显示错误和诊断 | `[ERROR] 证书申请失败，状态码: X` |

### 用户友好的消息示例

#### 正常跳过（不是错误）
```
[INFO] 正在检查并申请 SSL 证书...
[INFO] 证书已存在且在有效期内。跳过续期是正确的行为。
[INFO] 这不是错误 - acme.sh 智能地避免了不必要的证书申请。
[SUCCESS] 证书已成功配置给 Nginx。
```

#### 真正的错误
```
[ERROR] 证书申请失败，状态码: 1
[ERROR] 请检查以下可能的原因：
[ERROR] 1. Cloudflare API Token 是否正确
[ERROR] 2. 域名 DNS 是否指向 Cloudflare
[ERROR] 3. 网络连接是否正常
[INFO] 详细错误信息请查看: /root/.acme.sh/acme.sh.log
```

## 💡 使用建议

### VPS安全加固最佳实践
1. **首次使用**: 建议使用"一键安全加固"功能，自动配置所有安全设置
2. **定期检查**: 使用"安全状态检查"功能定期检查系统安全状态
3. **备份配置**: 脚本会自动备份重要配置文件到 `/root/security-backups/`
4. **SSH连接**: 修改SSH端口后，请使用新端口连接服务器

### Reality代理部署建议
1. **域名准备**: 确保域名已正确解析到服务器IP
2. **Cloudflare配置**: 准备好Cloudflare API Token，用于自动DNS验证
3. **证书管理**: 脚本支持智能证书处理，会自动跳过有效证书的续期
4. **服务监控**: 使用菜单中的状态检查功能监控服务运行状态

## 🛠️ 故障排除

### 常见问题

#### Q: VPS安全加固后无法SSH连接怎么办？
A: 检查是否修改了SSH端口，使用新端口连接。脚本会在完成后显示新的SSH连接信息。

#### Q: Reality代理为什么显示"跳过续期"？
A: 这是正常行为！说明您的证书仍然有效，acme.sh智能地避免了不必要的申请。

#### Q: 如何重置Reality配置？
A: 使用reality-setup.sh菜单中的重置功能，可以重置UUID、密钥对或所有配置。

#### Q: 脚本可以重复运行吗？
A: 是的！两个脚本都具有完全幂等性，可以安全重复运行。

#### Q: 服务启动失败怎么办？
A: 脚本会自动显示详细的诊断信息，包括服务日志和配置验证结果。

### 日志和诊断
```bash
# VPS安全相关
# 查看SSH服务状态
systemctl status ssh
# 查看Fail2ban状态
fail2ban-client status
# 查看UFW防火墙状态
ufw status verbose

# Reality代理相关
# 查看 Xray 服务日志
journalctl -u xray -f
# 查看 Nginx 服务日志
journalctl -u nginx -f
# 检查服务状态
systemctl status xray nginx
# 验证配置文件
nginx -t
/usr/local/bin/xray test -config /usr/local/etc/xray/config.json
# 查看证书状态
openssl x509 -in /etc/ssl/private/fullchain.cer -text -noout
```

## 📋 技术细节

### 脚本架构
- **主程序**: `main()` 函数提供交互式菜单
- **功能模块**: 独立的功能函数，支持模块化调用
- **配置管理**: 统一的配置文件管理机制
- **错误处理**: 详细的错误检测和诊断功能

### 关键文件位置
```
# VPS安全加固相关
/etc/security-hardening/            # 安全配置目录
/etc/ssh/sshd_config.d/99-hardening.conf  # SSH安全配置
/etc/fail2ban/jail.local            # Fail2ban配置
/root/security-backups/             # 安全配置备份

# Reality代理相关
/etc/reality-config/                # Reality配置目录
/usr/local/etc/xray/config.json    # Xray 配置
/etc/nginx/nginx.conf               # Nginx 配置
/etc/ssl/private/                   # SSL 证书目录
/var/www/html/                      # 伪装网站目录
```

### 服务管理
```bash
# VPS安全服务
systemctl restart ssh          # 重启SSH服务
systemctl restart fail2ban     # 重启Fail2ban服务
ufw reload                      # 重载防火墙规则

# Reality代理服务
systemctl start xray nginx     # 启动服务
systemctl stop xray nginx      # 停止服务
systemctl restart xray nginx   # 重启服务
systemctl status xray nginx    # 查看状态
systemctl enable xray nginx    # 启用自启动
```

## 🔒 安全注意事项

1. **Root 权限**: 两个脚本都需要 root 权限运行，请确保在可信环境中使用
2. **SSH安全**: 修改SSH端口后请立即测试新端口连接，避免锁定自己
3. **防火墙配置**: 脚本会自动配置UFW防火墙，确保不会误封SSH端口
4. **API Token**: Cloudflare API Token具有敏感权限，请妥善保管（仅Reality脚本需要）
5. **配置备份**: 重要配置会自动备份，安全配置备份到`/root/security-backups/`
6. **证书安全**: SSL证书私钥权限设置为600，仅root可读

## 📚 参考资料

- **VLESS Protocol**: [Xray 官方文档](https://xtls.github.io/)
- **Reality Protocol**: [Reality 协议说明](https://github.com/XTLS/REALITY)
- **acme.sh**: [证书申请工具](https://github.com/acmesh-official/acme.sh)
- **Cloudflare API**: [API 文档](https://developers.cloudflare.com/api/)

---

**🎯 项目目标**: 提供最专业、最易用、最安全的VPS安全加固和代理服务部署解决方案

**📧 技术支持**: 如有问题，请通过 GitHub Issues 联系我们

**⭐ 支持项目**: 如果这个项目对您有帮助，请给我们一个 Star！

**⚠️ 免责声明**: 本脚本仅供学习和研究使用，请遵守当地法律法规
