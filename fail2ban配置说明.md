# fail2ban高级配置说明

## 概述

fail2ban是一个入侵防护软件，通过监控日志文件来检测恶意行为，并自动封禁攻击者的IP地址。本文档详细说明了脚本中配置的fail2ban规则。

## 配置文件结构

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

## 过滤器配置

### UFW阻止过滤器: `/etc/fail2ban/filter.d/ufw-block.conf`

```ini
[Definition]
# 匹配UFW BLOCK日志中的源IP
failregex = ^.*\[UFW BLOCK\].*SRC=<HOST>.*$
ignoreregex =
```

**说明**: 
- 监控系统日志中的UFW BLOCK记录
- 提取被防火墙阻止的源IP地址
- 对重复触发的IP进行永久封禁

## Action配置

### UFW封禁动作: `/etc/fail2ban/action.d/ufw.conf`

```ini
[Definition]
actionstart =       # 服务启动时执行（空）
actionstop =        # 服务停止时执行（空）
actioncheck =       # 检查动作（空）
actionban = ufw insert 1 deny from <ip> to any      # 封禁IP
actionunban = ufw delete deny from <ip> to any      # 解封IP
```

## 工作原理

### 1. SSH保护机制
- **监控文件**: `/var/log/auth.log`
- **触发条件**: 3次SSH登录失败
- **封禁时间**: 1小时
- **工作流程**:
  1. 监控SSH登录失败日志
  2. 统计10分钟内的失败次数
  3. 超过3次则封禁IP 1小时

### 2. UFW阻止监控
- **监控文件**: `/var/log/syslog`
- **触发条件**: 5次被UFW阻止
- **封禁时间**: 永久
- **工作流程**:
  1. 监控UFW BLOCK日志
  2. 统计10分钟内的阻止次数
  3. 超过5次则永久封禁IP

## 管理命令

### 基础状态查看
```bash
# 查看fail2ban总体状态
sudo fail2ban-client status

# 查看特定jail状态
sudo fail2ban-client status sshd
sudo fail2ban-client status ufw-block
```

### IP管理
```bash
# 解封特定IP
sudo fail2ban-client set sshd unbanip 192.168.1.100
sudo fail2ban-client set ufw-block unbanip 192.168.1.100

# 手动封禁IP
sudo fail2ban-client set sshd banip 192.168.1.100
```

### 服务管理
```bash
# 重启fail2ban
sudo systemctl restart fail2ban

# 重新加载配置
sudo fail2ban-client reload

# 测试配置文件
sudo fail2ban-client -t
```

## 日志分析

### 查看fail2ban日志
```bash
# 实时监控
sudo tail -f /var/log/fail2ban.log

# 查看最近的封禁记录
sudo grep "Ban" /var/log/fail2ban.log | tail -10

# 查看解封记录
sudo grep "Unban" /var/log/fail2ban.log | tail -10
```

### 查看SSH攻击日志
```bash
# 查看失败的SSH登录
sudo grep "Failed password" /var/log/auth.log | tail -20

# 查看成功的SSH登录
sudo grep "Accepted" /var/log/auth.log | tail -10
```

### 查看UFW阻止日志
```bash
# 查看UFW阻止的连接
sudo grep "UFW BLOCK" /var/log/syslog | tail -20

# 统计被阻止最多的IP
sudo grep "UFW BLOCK" /var/log/syslog | grep -o 'SRC=[0-9.]*' | sort | uniq -c | sort -nr | head -10
```

## 高级配置

### 自定义封禁时间
```ini
# 短期封禁 (30分钟)
bantime = 1800

# 长期封禁 (24小时)
bantime = 86400

# 永久封禁
bantime = -1
```

### 白名单配置
```ini
[DEFAULT]
# 添加信任的IP地址
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24 10.0.0.0/8
```

### 邮件通知 (可选)
```ini
[DEFAULT]
# 配置邮件通知
destemail = admin@yourdomain.com
sendername = Fail2Ban
mta = sendmail
action = %(action_mw)s
```

## 性能优化

### 日志轮转
确保日志文件不会过大：
```bash
# 检查日志大小
sudo du -h /var/log/auth.log /var/log/syslog

# 手动轮转日志
sudo logrotate -f /etc/logrotate.conf
```

### 内存使用
```bash
# 查看fail2ban内存使用
sudo ps aux | grep fail2ban

# 优化配置以减少内存使用
# 在jail.local中设置较小的日志缓存
backend = systemd  # 使用systemd后端而不是文件监控
```

## 故障排除

### 常见问题

1. **fail2ban无法启动**
   ```bash
   # 检查配置文件语法
   sudo fail2ban-client -t
   
   # 查看错误日志
   sudo journalctl -u fail2ban -f
   ```

2. **规则不生效**
   ```bash
   # 检查日志文件路径
   sudo ls -la /var/log/auth.log /var/log/syslog
   
   # 手动测试过滤器
   sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
   ```

3. **误封自己的IP**
   ```bash
   # 紧急解封
   sudo fail2ban-client set sshd unbanip YOUR_IP
   
   # 添加到白名单
   sudo nano /etc/fail2ban/jail.local
   # 在ignoreip中添加你的IP
   ```

## 安全建议

1. **定期检查**: 每周检查fail2ban状态和日志
2. **备份配置**: 定期备份jail.local配置文件
3. **监控告警**: 设置邮件或其他方式的封禁通知
4. **日志分析**: 定期分析攻击模式，调整防护策略
5. **更新规则**: 根据新的攻击方式更新过滤规则

## 脚本集成

使用安全加固脚本的fail2ban管理功能：
```bash
./security-hardening.sh
# 选择 "12. fail2ban管理"
```

功能包括：
- 实时状态查看
- 被封禁IP列表
- 手动解封IP
- 日志查看
- 服务重启
- 配置测试

---

**注意**: fail2ban是服务器安全的重要组成部分，但不应作为唯一的安全措施。建议结合防火墙、SSH密钥认证、定期更新等多重安全策略。
