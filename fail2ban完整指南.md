# VPS 安全加固和代理搭建完整指南

## 概述

本指南涵盖了 VPS 安全加固脚本 `security-hardening.sh` 的完整使用方法，包括 fail2ban 配置、代理服务搭建和故障排除。

### 脚本特点
- **一体化设计**: 集成安全加固和代理搭建功能
- **智能检测**: 自动检测系统配置和服务状态
- **故障自愈**: 内置诊断和自动修复功能
- **用户友好**: 交互式菜单和详细反馈

## 快速开始

### 基本使用
```bash
# 下载并运行脚本
chmod +x security-hardening.sh
./security-hardening.sh
```

### 功能菜单
- **安全加固功能 (1-13)**: 系统更新、用户管理、SSH配置、防火墙、fail2ban等
- **代理服务功能 (14-20)**: 证书管理、Hysteria2、X-UI、Sub-Store、Nginx分流等
- **一键执行 (21)**: 自动完成所有安全加固步骤

## 最新修复和改进

### SSH端口检测优化
脚本现在使用多种方法智能检测SSH端口：
- 从 `/etc/ssh/sshd_config` 文件解析
- 从当前SSH连接获取 (`ss -tlnp`)
- 从环境变量 `$SSH_CONNECTION` 获取
- 从 `netstat` 命令获取

### fail2ban配置修复
针对配置验证失败问题，实现了分级配置策略：
- **完整配置**: SSH + UFW监控 + 高级功能
- **基本配置**: SSH监控 + 基本参数
- **最简配置**: 仅SSH保护，确保可用性

## fail2ban 常见问题及解决方案

### Socket 连接错误

**错误信息**：
```
Failed to access socket path: /var/run/fail2ban/fail2ban.sock. Is fail2ban running?
```

**原因分析**：
1. fail2ban 服务未正常启动
2. socket 文件创建延迟
3. 服务启动后立即执行命令导致的竞态条件
4. 配置文件错误

**解决方案**：
1. 使用脚本诊断功能：`./security-hardening.sh` → 选择 "12. fail2ban管理" → 选择 "7. 诊断和修复问题"
2. 手动检查：`systemctl status fail2ban`
3. 重启服务：`systemctl restart fail2ban`
4. 等待30-60秒让服务完全启动

### 配置验证失败
**错误信息**: "fail2ban配置验证失败"

**解决方案**:
脚本会自动尝试分级修复：
1. 首先尝试完整配置
2. 如果失败，降级到基本配置
3. 最后使用最简配置确保可用性

### SSH端口检测错误
**错误信息**: "检测到无效的SSH端口配置"

**解决方案**:
脚本现在使用多种方法检测SSH端口，通常能自动解决此问题。

## 配置说明

### 主配置文件: `/etc/fail2ban/jail.local`

```ini
[DEFAULT]
# 全局默认设置
bantime = 3600      # 封禁时间：1小时
findtime = 600      # 查找时间窗口：10分钟
maxretry = 3        # 最大重试次数：3次
ignoreip = 127.0.0.1/8 ::1  # 忽略的IP地址

[sshd]
# SSH保护规则
enabled = true
port = ssh端口
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[ufw-block]
# UFW阻止日志监控 - 高级功能
enabled = true
filter = ufw-block
logpath = /var/log/syslog
maxretry = 5        # 5次触发后封禁
findtime = 600      # 10分钟内
bantime = -1        # 永久封禁
action = ufw        # 使用ufw进行封禁
```

### 过滤器配置: `/etc/fail2ban/filter.d/ufw-block.conf`

```ini
[Definition]
# 匹配UFW BLOCK日志中的源IP
failregex = ^.*\[UFW BLOCK\].*SRC=<HOST>.*$
ignoreregex =
```

### Action配置: `/etc/fail2ban/action.d/ufw.conf`

```ini
[Definition]
actionstart =       # 服务启动时执行（空）
actionstop =        # 服务停止时执行（空）
actioncheck =       # 检查动作（空）
actionban = ufw insert 1 deny from <ip> to any      # 封禁IP
actionunban = ufw delete deny from <ip> to any      # 解封IP
```

## 使用方法

### 基本命令

```bash
# 查看状态
fail2ban-client status

# 查看特定jail状态
fail2ban-client status sshd

# 解封IP
fail2ban-client set sshd unbanip 192.168.1.100

# 测试配置
fail2ban-client -t

# 重启服务
systemctl restart fail2ban
```

### 使用安全加固脚本管理

运行主脚本：
```bash
./security-hardening.sh
```

选择 "12. fail2ban管理"，可用选项：
1. **查看fail2ban状态** - 显示服务和jail状态
2. **查看被封禁的IP** - 列出所有被封禁的IP地址
3. **解封IP地址** - 手动解封指定IP
4. **查看日志** - 显示fail2ban和SSH日志
5. **重启fail2ban服务** - 安全重启服务
6. **测试配置** - 检查配置文件语法
7. **诊断和修复问题** - 全面诊断和自动修复

## 故障诊断

### 诊断步骤

1. **检查服务状态**
   ```bash
   systemctl status fail2ban
   systemctl is-active fail2ban
   ```

2. **检查socket文件**
   ```bash
   ls -la /var/run/fail2ban/fail2ban.sock
   ```

3. **检查配置文件**
   ```bash
   fail2ban-client -t
   ```

4. **查看日志**
   ```bash
   tail -f /var/log/fail2ban.log
   journalctl -u fail2ban -f
   ```

### 自动诊断

使用脚本的诊断功能会自动检查：
- 服务运行状态
- Socket文件存在性和权限
- 配置文件语法
- 日志文件错误信息
- 系统资源状态

## 工作原理

### SSH保护机制
- **监控文件**: `/var/log/auth.log`
- **触发条件**: 3次SSH登录失败
- **封禁时间**: 1小时
- **工作流程**:
  1. 监控SSH登录失败日志
  2. 统计10分钟内的失败次数
  3. 超过3次则封禁IP 1小时

### UFW阻止监控
- **监控文件**: `/var/log/syslog`
- **触发条件**: 5次被UFW阻止
- **封禁时间**: 永久
- **工作流程**:
  1. 监控UFW BLOCK日志
  2. 统计10分钟内的阻止次数
  3. 超过5次则永久封禁IP

## 性能优化

### 日志轮转配置
```bash
# /etc/logrotate.d/fail2ban
/var/log/fail2ban.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    postrotate
        /bin/systemctl reload fail2ban.service > /dev/null 2>&1 || true
    endscript
}
```

### 内存优化
- 定期清理过期的封禁记录
- 调整日志级别避免过多输出
- 使用合适的findtime和bantime值

## 安全建议

1. **定期检查**: 每周检查fail2ban状态和日志
2. **备份配置**: 定期备份jail.local配置文件
3. **监控告警**: 设置邮件或其他方式的封禁通知
4. **日志分析**: 定期分析攻击模式，调整防护策略
5. **更新规则**: 根据新的攻击方式更新过滤规则

## 常见错误及解决

### 配置文件语法错误
```bash
# 检查语法
fail2ban-client -t

# 常见错误：
# - 缺少必要的section
# - 参数值格式错误
# - 文件路径不存在
```

### 服务启动失败
```bash
# 查看详细错误
journalctl -u fail2ban -n 20

# 常见原因：
# - 配置文件错误
# - 权限问题
# - 磁盘空间不足
# - 依赖服务未启动
```

### Socket文件问题
```bash
# 检查文件权限
ls -la /var/run/fail2ban/

# 手动清理并重启
systemctl stop fail2ban
rm -f /var/run/fail2ban/fail2ban.sock
systemctl start fail2ban
```

## 高级配置

### 自定义过滤器
创建自定义过滤器文件 `/etc/fail2ban/filter.d/custom.conf`：
```ini
[Definition]
failregex = ^.*Custom attack pattern.*<HOST>.*$
ignoreregex =
```

### 邮件通知
在jail.local中添加：
```ini
[DEFAULT]
action = %(action_mw)s
destemail = admin@example.com
sender = fail2ban@example.com
```

### 白名单配置
```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24 10.0.0.0/8
```

## 代理服务搭建指南

### 证书管理 (选项14)
使用 Cloudflare DNS 自动申请 SSL 证书：

**前置要求**:
- 域名托管在 Cloudflare
- Cloudflare API Token (Zone:Read, DNS:Edit 权限)
- Zone ID 和 Account ID

**使用步骤**:
1. 选择 "14. 证书管理"
2. 选择 "1. 申请新证书"
3. 输入域名、邮箱和 Cloudflare 信息

### 代理服务安装

#### Hysteria2 (选项15)
高性能代理协议，适合高速网络环境：
- 自动安装和配置
- 支持自定义端口和认证
- 自动配置防火墙规则

#### X-UI 面板 (选项16)
可视化管理界面：
- 安装 3X-UI 管理面板
- 支持多种协议配置
- 提供 Web 管理界面

#### Sub-Store 服务 (选项17)
订阅转换服务：
- 自动安装 Node.js 环境
- 配置订阅转换功能
- 支持多种订阅格式

#### Nginx 分流配置 (选项18)
智能流量分发：
- 基于 SNI 的流量分流
- 支持多域名代理
- 自动 SSL 配置

### 搭建流程

**推荐顺序**:
1. 完成基础安全加固 (选项21或依次执行1-6)
2. 申请 SSL 证书 (选项14)
3. 安装所需代理服务 (选项15-17)
4. 配置 Nginx 分流 (选项18)

**配置要求**:
- 确保域名 DNS 解析正确
- 防火墙端口已开放
- 证书路径配置正确

## 故障排除和维护

### 日志查看
```bash
# 脚本日志
tail -f /var/log/security-hardening.log

# fail2ban 日志
tail -f /var/log/fail2ban.log

# 系统服务日志
journalctl -u 服务名 -f
```

### 服务管理
```bash
# 查看服务状态
systemctl status 服务名

# 重启服务
systemctl restart 服务名

# 查看端口占用
netstat -tlnp | grep 端口号
```

### 定期维护
1. **每周检查**: fail2ban 状态和封禁日志
2. **每月更新**: 系统软件包和安全补丁
3. **证书续期**: 自动续期，但建议定期检查
4. **配置备份**: 重要配置文件的定期备份

---

**注意**:
- fail2ban 是服务器安全的重要组成部分，但不应作为唯一的安全措施
- 代理服务仅供学习和合法用途，请遵守当地法律法规
- 建议结合防火墙、SSH密钥认证、定期更新等多重安全策略
