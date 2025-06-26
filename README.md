# VPS 一体化安全加固和代理搭建脚本

本项目提供一个统一的脚本 `security-hardening.sh`，集成了 VPS 安全加固和代理服务搭建的所有功能。

## 主要功能

### 🛡️ 安全加固功能
- 系统更新和用户管理
- SSH 安全配置
- 防火墙配置 (ufw)
- **fail2ban 安装和管理** - 防止暴力破解攻击
- 网络安全配置
- 系统监控和清理
- 安全扫描和备份

### 🚀 代理服务搭建
- **证书管理** - Cloudflare DNS 自动申请 SSL 证书
- **Hysteria2 服务** - 高性能代理协议
- **X-UI 面板** - 可视化管理界面
- **Sub-Store 服务** - 订阅转换服务
- **Nginx 分流配置** - 智能流量分发
- **vless+reality 代理** - 最新的伪装技术

### 🔧 一体化设计
所有功能集成在一个脚本中，避免多脚本管理的复杂性，提供统一的用户界面和配置管理。

## 使用方法

### 基本使用
```bash
# 下载脚本
wget https://raw.githubusercontent.com/your-repo/security-hardening.sh
chmod +x security-hardening.sh

# 运行脚本
./security-hardening.sh
```

### 功能菜单
脚本提供交互式菜单，包含以下选项：

**安全加固功能 (1-13)**
1. 显示系统信息
2. 系统更新
3. 创建非root用户
4. SSH安全配置
5. 防火墙配置
6. 安装fail2ban
7. 网络安全配置
8. 系统监控配置
9. 精简系统组件
10. 安全扫描与检查
11. 备份与恢复配置
12. fail2ban管理
13. 安全配置验证

**代理服务功能 (14-20)**
14. 证书管理 (Cloudflare)
15. Hysteria2服务
16. X-UI面板
17. Sub-Store服务
18. Nginx分流配置
19. 配置vless+reality代理
20. 代理服务管理

**一键执行 (21)**
21. 一键全部执行

## 快速开始

### 1. 基础安全加固
```bash
./security-hardening.sh
# 依次选择: 2 → 3 → 4 → 5 → 6
# 或直接选择: 21 (一键全部执行)
```

### 2. 代理服务搭建
```bash
# 前提：已完成基础安全加固
./security-hardening.sh

# 步骤1: 申请证书
# 选择 "14. 证书管理" → "1. 申请新证书"
# 需要准备: 域名、邮箱、Cloudflare API Token、Zone ID、Account ID

# 步骤2: 安装服务 (根据需要选择)
# 选择 "15. Hysteria2服务" 或 "16. X-UI面板" 或 "17. Sub-Store服务"

# 步骤3: 配置分流
# 选择 "18. Nginx分流配置"
```

### 3. 故障排除
如果遇到 fail2ban socket 连接问题：
```bash
./security-hardening.sh
# 选择 "12. fail2ban管理" → "7. 诊断和修复问题"
```

## 重要说明

### 前置要求
1. **系统要求**: Debian/Ubuntu 系统
2. **权限要求**: 必须使用 root 用户运行
3. **网络要求**: 服务器需要能够访问外网

### 证书申请要求
使用 Cloudflare 证书管理功能需要：
1. 在 Cloudflare 托管的域名
2. Cloudflare API Token (需要 Zone:Read, DNS:Edit 权限)
3. Cloudflare Zone ID 和 Account ID

### 安全建议
1. **修改默认端口**: SSH、X-UI 等服务端口
2. **使用强密码**: 所有账户和服务密码
3. **定期备份**: 重要配置和数据
4. **监控日志**: 定期检查安全日志

## 文档说明

- `fail2ban完整指南.md` - **主要文档**，包含完整的使用指南、配置说明和故障排除
- `VPS安全加固说明.md` - 安全加固功能详细说明
- `SSH配置最佳实践.md` - SSH 安全配置指南
- `vless+reality配置指南.md` - 代理服务配置指南

## 故障排除

### 常见问题
1. **fail2ban Socket 连接问题**: 使用脚本诊断功能 (选项 12 → 7)
2. **SSH端口检测错误**: 脚本已自动修复，支持多种检测方法
3. **配置验证失败**: 脚本会自动降级到可用配置
4. **证书申请失败**: 检查 Cloudflare 配置和网络连接

### 快速修复
```bash
# 重启相关服务
systemctl restart fail2ban
systemctl restart nginx

# 查看服务状态
systemctl status 服务名

# 查看日志
journalctl -u 服务名 -n 20
```

**详细说明请参考 `fail2ban完整指南.md`**

## 更新日志

### v2.0.0 (当前版本)
- 🔄 **重大更新**: 将所有功能整合到单一脚本
- ➕ **新增功能**: 证书管理、Hysteria2、X-UI、Sub-Store、Nginx 分流
- 🛠️ **优化**: fail2ban 诊断和修复功能
- 📚 **改进**: 统一的用户界面和文档

### v1.x.x (历史版本)
- 基础安全加固功能
- fail2ban 基础管理
- 分离式脚本设计
