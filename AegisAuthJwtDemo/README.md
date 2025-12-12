# AegisAuthJwtDemo

这是一个基于 AegisAuthJwt 的完整演示应用，展示了 JWT 认证与 WebAuthn 通行密钥的集成。

## 功能特性

- **用户注册**: 使用用户名和密码注册新用户
- **JWT 认证**: 标准的用户名/密码登录，返回 JWT 访问令牌
- **通行密钥注册**: 将 WebAuthn 通行密钥注册为双因素认证
- **通行密钥登录**: 使用通行密钥进行身份验证
- **私钥签名**: 使用存储在浏览器中的加密私钥对数据进行签名

## 技术栈

- **后端**: ASP.NET Core 9.0, Entity Framework Core (SQLite)
- **认证**: JWT Bearer Token + WebAuthn
- **前端**: 纯 HTML/JavaScript + Web Crypto API
- **数据库**: SQLite (用于演示)

## 运行方式

1. 确保已安装 .NET 9.0 SDK
2. 克隆仓库并进入项目目录
3. 运行应用:
   ```bash
   dotnet run --project AegisAuthJwtDemo
   ```
4. 在浏览器中访问: `http://localhost:5187`

## 使用流程

### 1. 用户注册
- 输入用户名和密码
- 点击 "Register User" 按钮

### 2. 用户登录
- 使用注册的用户名和密码登录
- 系统返回 JWT 令牌并显示认证状态

### 3. 注册通行密钥 (2FA)
- 登录后，点击 "Register Passkey" 按钮
- 浏览器会提示创建通行密钥
- 通行密钥将作为双因素认证使用

### 4. 通行密钥登录
- 点击 "Get Login Options" 获取登录选项
- 点击 "Login with Passkey" 使用通行密钥登录
- 无需密码，直接通过生物识别或硬件密钥认证

### 5. 数据签名
- 使用存储的私钥对数据进行数字签名
- 签名过程需要重新进行 WebAuthn 认证以访问加密的私钥

## 安全特性

- **JWT 令牌黑名单**: 防止已注销的令牌被重复使用
- **私钥加密存储**: 使用 WebAuthn PRF 扩展生成的密钥对私钥进行 AES-GCM 加密
- **数据完整性保护**: HMAC 确保存储数据的完整性
- **双因素认证**: 支持通行密钥作为第二因素

## API 端点

### 认证相关
- `POST /api/auth/register` - 用户注册
- `POST /api/auth/login` - 用户名密码登录
- `POST /api/auth/logout` - 用户登出
- `POST /api/auth/refresh` - 刷新令牌

### 通行密钥相关
- `POST /api/auth/passkey/login-options` - 获取通行密钥登录选项
- `POST /api/auth/passkey/login` - 通行密钥登录
- `GET /api/auth/passkey/register-options` - 获取通行密钥注册选项
- `POST /api/auth/passkey/register` - 注册通行密钥

### 业务相关
- `POST /api/business/verify-options` - 获取签名验证选项
- `POST /api/business/verify` - 验证数据签名

## 数据库

应用使用 SQLite 数据库 (`jwt-demo.db`) 存储:
- 用户信息
- 通行密钥凭据
- 安全审计日志
- JWT 令牌黑名单

数据库会在应用启动时自动创建和初始化。