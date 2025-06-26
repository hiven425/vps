# SSH配置最佳实践指南

## 概述

本文档详细说明了SSH安全配置的最佳实践，特别是如何正确使用`/etc/ssh/sshd_config.d/`目录来管理SSH配置，避免系统更新时的配置冲突。

## 配置文件结构

### 主配置文件
- `/etc/ssh/sshd_config` - SSH主配置文件
- `/etc/ssh/sshd_config.d/` - 自定义配置目录

### 配置优先级
SSH配置文件的读取顺序：
1. `/etc/ssh/sshd_config` - 主配置文件
2. `/etc/ssh/sshd_config.d/*.conf` - 按字母顺序读取

**重要**: 后读取的配置会覆盖先读取的配置

## 最佳实践原则

### 1. 使用sshd_config.d目录
**推荐做法**:
```bash
# 创建自定义配置文件
sudo nano /etc/ssh/sshd_config.d/99-security-hardening.conf
```

**优势**:
- 避免系统更新时配置被覆盖
- 便于配置管理和版本控制
- 可以按功能模块化配置
- 便于备份和恢复

### 2. 检查现有配置冲突
**检查步骤**:
```bash
# 查看sshd_config.d目录中的配置文件
sudo ls -la /etc/ssh/sshd_config.d/*.conf

# 查看具体配置内容
sudo cat /etc/ssh/sshd_config.d/*.conf

# 备份可能冲突的配置
sudo mv /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/50-cloud-init.conf.bak
```

### 3. 验证有效配置
**使用sshd -T命令**:
```bash
# 查看所有有效配置
sudo sshd -T

# 查看特定配置项
sudo sshd -T | grep -i "PermitRootLogin"
sudo sshd -T | grep -i "PasswordAuthentication"
sudo sshd -T | grep -i "Port"
```

## 常见云服务商配置

### CloudCone
```bash
# 常见配置文件
/etc/ssh/sshd_config.d/50-cloud-init.conf

# 典型内容
PasswordAuthentication yes
PermitRootLogin yes
```

### AWS EC2
```bash
# 常见配置文件
/etc/ssh/sshd_config.d/60-cloudimg-settings.conf

# 典型内容
PasswordAuthentication no
```

### DigitalOcean
```bash
# 通常修改主配置文件
# 需要检查是否有自定义配置
```

### Vultr
```bash
# 可能的配置文件
/etc/ssh/sshd_config.d/50-cloud-init.conf
```

## 安全配置模板

### 基础安全配置
```bash
# /etc/ssh/sshd_config.d/99-security-hardening.conf

# 基础安全设置
Port 2222
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes

# 连接限制
MaxAuthTries 3
LoginGraceTime 60
MaxStartups 10:30:100
MaxSessions 4

# 用户限制
AllowUsers admin user1 user2

# 禁用不安全功能
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
```

### 高级安全配置
```bash
# 高级加密算法
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# 认证设置
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes

# 会话设置
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes
Compression delayed
```

## 配置验证流程

### 1. 语法检查
```bash
# 检查配置语法
sudo sshd -t

# 如果有错误，会显示具体信息
sudo sshd -t -f /etc/ssh/sshd_config
```

### 2. 有效配置检查
```bash
# 查看最终有效配置
sudo sshd -T

# 检查关键配置项
sudo sshd -T | grep -E "(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)"
```

### 3. 测试连接
```bash
# 在新终端测试连接
ssh -p 新端口 用户名@服务器IP

# 使用详细模式排查问题
ssh -v -p 新端口 用户名@服务器IP
```

## 故障排除

### 常见问题

#### 1. 配置不生效
**原因**: 被其他配置文件覆盖
**解决**:
```bash
# 检查所有配置文件
sudo sshd -T | grep -i "配置项名称"

# 查找冲突的配置文件
grep -r "配置项" /etc/ssh/sshd_config.d/
```

#### 2. 无法连接
**原因**: 配置错误或防火墙阻断
**解决**:
```bash
# 检查SSH服务状态
sudo systemctl status sshd

# 检查监听端口
sudo ss -tlnp | grep sshd

# 检查防火墙
sudo ufw status
```

#### 3. 密码认证仍然有效
**原因**: 云服务商配置覆盖
**解决**:
```bash
# 查找覆盖配置
sudo sshd -T | grep -i "passwordauthentication"

# 检查所有相关配置
grep -r "PasswordAuthentication" /etc/ssh/
```

### 应急恢复

#### 1. 配置错误导致无法连接
```bash
# 通过控制台登录
# 恢复默认配置
sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
sudo rm /etc/ssh/sshd_config.d/99-security-hardening.conf
sudo systemctl restart sshd
```

#### 2. 备份和恢复
```bash
# 创建配置备份
sudo tar -czf ssh-config-backup-$(date +%Y%m%d).tar.gz /etc/ssh/

# 恢复配置
sudo tar -xzf ssh-config-backup-YYYYMMDD.tar.gz -C /
sudo systemctl restart sshd
```

## 自动化脚本集成

### 脚本改进点
1. **检查现有配置**: 自动检测并处理冲突配置
2. **使用sshd_config.d**: 避免直接修改主配置文件
3. **配置验证**: 使用`sshd -T`验证有效配置
4. **安全测试**: 提供连接测试指导

### 配置文件命名规范
```bash
# 推荐命名格式
/etc/ssh/sshd_config.d/99-security-hardening.conf

# 命名原则
- 使用数字前缀控制加载顺序
- 99- 确保最后加载，覆盖其他配置
- 描述性名称便于识别
```

## 监控和维护

### 定期检查
```bash
# 每月检查脚本
#!/bin/bash
echo "SSH配置检查报告 - $(date)"
echo "================================"

echo "当前SSH端口: $(sudo sshd -T | grep -i '^port' | awk '{print $2}')"
echo "Root登录设置: $(sudo sshd -T | grep -i '^permitrootlogin' | awk '{print $2}')"
echo "密码认证: $(sudo sshd -T | grep -i '^passwordauthentication' | awk '{print $2}')"

echo "配置文件列表:"
ls -la /etc/ssh/sshd_config.d/

echo "最近SSH登录:"
last -n 5
```

### 安全审计
```bash
# SSH安全审计
sudo sshd -T | grep -E "(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|AllowUsers)"
```

## 参考资源

- [OpenSSH官方文档](https://www.openssh.com/manual.html)
- [SSH配置最佳实践](https://wiki.mozilla.org/Security/Guidelines/OpenSSH)
- [Ubuntu SSH配置指南](https://ubuntu.com/server/docs/service-openssh)

---

**重要提醒**: 
- 修改SSH配置前务必确保有备用访问方式
- 使用`sshd -T`验证配置而不是依赖配置文件内容
- 定期检查和更新SSH配置以保持安全性
