# VPS安全工具包 v3.0.0

一个专业的VPS服务器安全加固和代理部署工具集，采用模块化设计，提供完整的安全解决方案。

## ✨ 项目特色

### 🏗️ 模块化架构
- **主脚本**: 集成安全加固和代理部署的一体化工具
- **安全专用**: 专注于系统安全加固的专业工具
- **代理专用**: 专注于VLESS-REALITY代理部署的专用工具
- **模块支持**: 支持增强日志、服务管理等扩展模块

### 🛡️ 安全加固功能
- **SSH安全配置**: 端口修改、密钥认证、云配置冲突处理
- **防火墙管理**: UFW/iptables配置、fail2ban入侵防护
- **系统加固**: 内核参数优化、服务管理、自动更新
- **安全审计**: 全面的安全检查和漏洞扫描

### 🚀 代理部署功能
- **VLESS-REALITY**: 最新抗检测代理协议
- **智能配置**: 自动端口选择、目标网站优化
- **多客户端支持**: JSON、分享链接、二维码、Clash配置
- **一键部署**: 快速部署和自定义配置模式

## 📁 项目结构

```
vps-security-toolkit/
├── vps-security-toolkit.sh       # 主脚本 (安全+代理一体化)
├── vps-security-hardening.sh     # 纯安全加固脚本
├── vps-proxy-deployment.sh       # 纯代理部署脚本
├── README.md                      # 项目文档 (本文件)
├── enhanced-logging.sh            # 增强日志模块 (可选)
├── secure-service-manager.sh      # 安全服务管理模块 (可选)
└── security-fixes.sh              # 安全修复补丁模块 (可选)
```

## 🚀 快速开始

### 权限要求
所有脚本都需要root权限运行：
```bash
sudo chmod +x *.sh
```

### 1. 主脚本 - 一体化工具
适合需要完整功能的用户，同时提供安全加固和代理部署功能。

```bash
# 交互模式 (推荐)
sudo ./vps-security-toolkit.sh

# 快速操作
sudo ./vps-security-toolkit.sh --ssh        # SSH安全配置
sudo ./vps-security-toolkit.sh --firewall   # 防火墙配置
sudo ./vps-security-toolkit.sh --optimize   # 系统优化
sudo ./vps-security-toolkit.sh --status     # 系统状态
```

### 2. 安全加固专用脚本
专注于系统安全加固，不包含代理功能。

```bash
# 交互模式
sudo ./vps-security-hardening.sh

# 快速操作
sudo ./vps-security-hardening.sh --ssh      # SSH安全配置
sudo ./vps-security-hardening.sh --firewall # 防火墙配置
sudo ./vps-security-hardening.sh --harden   # 系统加固
sudo ./vps-security-hardening.sh --audit    # 安全审计
sudo ./vps-security-hardening.sh --full     # 完整加固
```

### 3. 代理部署专用脚本
专注于VLESS-REALITY代理部署和管理。

```bash
# 交互模式
sudo ./vps-proxy-deployment.sh

# 快速操作
sudo ./vps-proxy-deployment.sh --quick      # 快速部署
sudo ./vps-proxy-deployment.sh --custom     # 自定义部署
sudo ./vps-proxy-deployment.sh --status     # 代理状态
sudo ./vps-proxy-deployment.sh --client     # 客户端信息
```

## 📊 功能对比

| 功能类别 | 主脚本 | 安全专用 | 代理专用 |
|---------|--------|----------|----------|
| SSH安全配置 | ✅ | ✅ | ❌ |
| 防火墙管理 | ✅ | ✅ | 基础 |
| 系统加固 | ✅ | ✅ | ❌ |
| 安全审计 | ✅ | ✅ | ❌ |
| 代理部署 | 基础 | ❌ | ✅ |
| 服务管理 | ✅ | ✅ | ✅ |
| 文件大小 | 中等 | 大 | 中等 |
| 启动速度 | 中等 | 快 | 快 |

## 🛡️ 安全功能详解

### SSH安全配置
- **端口管理**: 智能端口冲突检测和自动选择
- **云平台兼容**: 自动处理AWS/GCP/Azure/阿里云配置冲突
- **认证安全**: 禁用密码认证，强制密钥认证
- **现代加密**: 仅允许安全的加密算法和协议
- **连接保护**: 限制认证尝试、会话管理、连接保活

### 防火墙防护
- **UFW管理**: 自动UFW防火墙配置和规则管理
- **fail2ban**: 入侵检测和自动封禁功能
- **端口管理**: 智能端口开放和安全检查
- **规则优化**: 基于服务需求的智能规则生成

### 系统加固
- **内核参数**: 网络安全、内存保护、性能优化参数
- **服务管理**: 禁用不必要服务、安全配置
- **自动更新**: 系统安全更新自动化配置
- **权限控制**: 文件权限检查和修复

### 安全审计
- **SSH审计**: SSH配置安全性全面检查
- **系统审计**: 文件权限、服务状态、进程检查
- **漏洞扫描**: 常见安全问题和配置错误检测
- **合规检查**: 安全基线和最佳实践验证

## 🚀 代理功能详解

### VLESS-REALITY协议
- **协议版本**: 最新REALITY标准实现
- **传输优化**: HTTP/2多路复用，XTLS-RPRX-Vision流控
- **安全特性**: X25519密钥交换，TLS指纹完美伪装
- **抗检测**: 真实TLS握手，无法被识别为代理流量

### 智能配置
- **端口选择**: 443 → 8443 → 随机高端口智能选择
- **目标网站**: 延迟测试选择最优伪装目标
- **密钥管理**: 自动生成高强度密钥对
- **性能调优**: 根据服务器性能自动优化参数

### 客户端支持
- **配置格式**: JSON配置、分享链接、二维码、Clash配置
- **客户端兼容**: 
  - Android: v2rayNG
  - iOS: Shadowrocket
  - Windows: v2rayN
  - macOS: V2RayXS
  - Linux: Xray客户端
  - 路由器: Clash系列

### 部署模式
- **快速部署**: 60秒内完成，零配置干预
- **自定义部署**: 完全自定义所有参数
- **批量部署**: 支持多实例和配置模板

## 📋 系统要求

### 支持的操作系统
- **Ubuntu**: 18.04+ (推荐 20.04/22.04/24.04)
- **Debian**: 9+ (推荐 11/12)
- **CentOS**: 7+ (推荐 8/9)
- **RHEL**: 7+
- **Fedora**: 最新版本

### 硬件要求
- **权限**: Root访问权限
- **内存**: 最小512MB，推荐1GB+
- **存储**: 最小5GB可用空间
- **网络**: 稳定的互联网连接
- **架构**: x86_64, ARM64

### 网络要求
- **出站连接**: 443, 80端口可访问
- **DNS解析**: 能够解析github.com等域名
- **防火墙**: 允许脚本配置的端口

## 🔧 高级配置

### 配置文件位置
```bash
# 主配置目录
/etc/vps-security-toolkit/    # 主脚本配置
/etc/vps-security/            # 安全脚本配置  
/etc/vps-proxy/               # 代理脚本配置

# 日志文件
/var/log/vps-security.log         # 主脚本日志
/var/log/vps-security-hardening.log  # 安全脚本日志
/var/log/vps-proxy.log            # 代理脚本日志

# 备份目录
/etc/*/backup/                # 各模块备份目录
```

### SSH配置文件
```bash
/etc/ssh/sshd_config.d/99-vps-security.conf    # SSH安全配置
```

### 代理配置文件
```bash
/usr/local/etc/xray/config.json               # Xray主配置
/etc/vps-proxy/clients/                       # 客户端配置目录
├── vless_link.txt                             # 分享链接
├── client_config.json                         # JSON配置
├── clash_config.yaml                          # Clash配置
└── qrcode.png                                 # 二维码
```

### 环境变量配置
```bash
# 日志级别
export VPS_LOG_LEVEL=INFO    # DEBUG, INFO, WARN, ERROR

# 配置目录自定义
export VPS_CONFIG_DIR=/custom/path

# 跳过某些检查
export VPS_SKIP_UPDATE_CHECK=true
export VPS_SKIP_SYSTEM_CHECK=true
```

## 🔍 故障排除

### 常见问题

#### SSH连接问题
```bash
# 检查SSH服务状态
sudo systemctl status sshd

# 检查SSH配置语法
sudo sshd -t

# 查看SSH端口设置
sudo ./vps-security-hardening.sh --status

# 重置SSH配置 (紧急情况)
sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
sudo systemctl restart sshd
```

#### 代理连接问题
```bash
# 检查Xray服务状态
sudo systemctl status xray

# 查看Xray日志
sudo journalctl -u xray -f

# 检查代理配置
sudo ./vps-proxy-deployment.sh --status

# 验证配置文件
sudo xray test -config /usr/local/etc/xray/config.json
```

#### 防火墙问题
```bash
# 检查UFW状态
sudo ufw status verbose

# 检查fail2ban状态
sudo fail2ban-client status

# 临时禁用防火墙 (紧急情况)
sudo ufw disable
```

### 日志分析
```bash
# 查看安全日志
sudo tail -f /var/log/vps-security-hardening.log

# 查看代理日志
sudo tail -f /var/log/vps-proxy.log

# 查看系统认证日志
sudo tail -f /var/log/auth.log

# 查看防火墙日志
sudo tail -f /var/log/ufw.log
```

### 诊断工具
```bash
# SSH配置诊断
sudo ./vps-security-hardening.sh --audit

# 代理服务诊断
sudo ./vps-proxy-deployment.sh --status

# 网络连通性测试
ping -c 4 8.8.8.8
curl -I https://www.google.com
```

## 🤝 技术支持

### 获取帮助
```bash
# 查看帮助信息
sudo ./vps-security-toolkit.sh --help
sudo ./vps-security-hardening.sh --help
sudo ./vps-proxy-deployment.sh --help

# 查看版本信息
sudo ./vps-security-toolkit.sh --version
```

### 问题报告
在报告问题时，请提供以下信息：
1. **操作系统版本**: `cat /etc/os-release`
2. **脚本版本**: `./script.sh --version`
3. **错误信息**: 完整的错误输出
4. **日志文件**: 相关的日志内容
5. **系统状态**: `./script.sh --status`

### 常用诊断命令
```bash
# 系统信息收集
uname -a
cat /etc/os-release
df -h
free -h
systemctl --failed

# 网络状态检查
ss -tuln
iptables -L
ufw status
```

## 📚 扩展模块

项目支持可选的扩展模块，提供额外功能：

### enhanced-logging.sh - 增强日志系统
- 结构化JSON日志记录
- 多级日志管理 (DEBUG/INFO/WARN/ERROR/CRITICAL)
- 自动日志轮转和压缩
- 错误上下文管理和自动恢复
- 审计日志和操作追踪

### secure-service-manager.sh - 安全服务管理
- 安全的系统服务操作
- 服务白名单验证和批量操作
- 服务健康检查和依赖管理
- 交互式服务管理界面

### security-fixes.sh - 安全修复补丁
- 安全漏洞修复工具
- 文件权限安全修复
- 输入验证和清理增强
- 下载文件完整性验证

## 📄 许可证

本项目采用 **MIT License** 开源许可证。

### 许可证要点
- ✅ **商业使用**: 允许商业用途使用
- ✅ **修改分发**: 允许修改和分发
- ✅ **私人使用**: 允许个人和私人使用
- ✅ **专利使用**: 提供专利使用权
- ❌ **责任承担**: 不承担使用责任
- ❌ **担保提供**: 不提供任何担保

## ⚠️ 免责声明

### 使用条款
1. **合法使用**: 本工具仅供学习、研究和合法用途使用
2. **法律遵守**: 使用者需遵守当地法律法规和相关政策
3. **风险承担**: 使用本工具产生的任何后果由使用者自行承担
4. **技术支持**: 项目提供技术支持，但不承担使用责任

### 安全提醒
1. **生产环境**: 生产环境使用前请充分测试
2. **数据备份**: 重要数据请提前备份
3. **权限控制**: 谨慎使用root权限，避免安全风险
4. **定期更新**: 建议定期更新工具和系统补丁

## 🙏 致谢

### 开源项目
- **[XTLS/Xray-core](https://github.com/XTLS/Xray-core)**: 高性能代理核心
- **[fail2ban](https://github.com/fail2ban/fail2ban)**: 入侵防护系统
- **[UFW](https://wiki.ubuntu.com/UncomplicatedFirewall)**: 简化防火墙管理

### 技术参考
- **Linux Security Best Practices**: 系统安全加固标准
- **REALITY Protocol Documentation**: 协议实现技术细节
- **Modern DevOps Practices**: 现代运维最佳实践

---

**🎯 项目目标**: 提供最专业、最易用、最安全的VPS管理工具

**📧 技术支持**: 如有问题，请通过GitHub Issues联系我们

**⭐ 支持项目**: 如果这个项目对您有帮助，请给我们一个Star！