# fail2ban 完整配置和故障排除指南

## 概述

fail2ban 是一个入侵防护软件，通过监控日志文件来检测恶意行为，并自动封禁攻击者的IP地址。本指南涵盖了配置、使用和故障排除的完整内容。

## 常见问题及解决方案

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
1. 使用安全加固脚本的诊断功能：`./security-hardening.sh` → 选择 "12. fail2ban管理" → 选择 "7. 诊断和修复问题"
2. 手动检查服务状态：`systemctl status fail2ban`
3. 重启服务：`systemctl restart fail2ban`
4. 等待30-60秒让服务完全启动

**快速修复步骤**：
```bash
# 1. 检查服务状态
systemctl status fail2ban

# 2. 如果服务未运行，启动服务
systemctl start fail2ban

# 3. 等待socket文件创建
sleep 30

# 4. 测试连接
fail2ban-client status
```

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

---

**注意**: fail2ban是服务器安全的重要组成部分，但不应作为唯一的安全措施。建议结合防火墙、SSH密钥认证、定期更新等多重安全策略。
