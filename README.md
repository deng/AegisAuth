# AegisAuth

一个功能全面的 .NET 认证解决方案，提供 JWT 和 Session 两种认证方式，支持令牌黑名单、安全审计日志、WebAuthn 双因素认证和数字签名功能。

## 项目结构

- **AegisAuthBase** - 核心共享库（实体、仓储接口、服务）
- **AegisAuthJwt** - JWT 认证库
- **AegisAuthSession** - Session 认证库
- **AegisAuthJwtTest** - JWT 测试项目
- **AegisAuthSessionTest** - Session 测试项目
- **AegisAuthJwtDemo** - JWT + WebAuthn 完整演示项目
- **AegisAuth.WebAuthnDemo** - WebAuthn 演示项目

## 特性

### 共同特性
- 🛡️ **密码安全**：基于 PBKDF2 的密码哈希（100,000 次迭代）
- 📊 **安全审计日志**：全面记录认证事件
- 🔒 **账户锁定**：5 次失败尝试后锁定 30 分钟
- 🌐 **ASP.NET Core 集成**：无缝集成到 ASP.NET Core 应用
- 🎯 **即用控制器**：内置控制器可直接使用
- 🔐 **WebAuthn 双因素认证**：支持 FIDO2 标准的安全认证
- 🗝️ **通行密钥支持**：无密码认证体验
- ✍️ **数字签名**：基于 WebAuthn 的数据签名功能

### AegisAuthJwt 特性
- 🔐 **JWT 认证**：标准 JWT 令牌认证
- 🚫 **令牌黑名单**：自动令牌失效机制
- 🔄 **令牌刷新**：自动续期支持
- 🧹 **自动清理**：后台清理过期令牌
- 🗝️ **通行密钥集成**：JWT + WebAuthn 双因素认证
- ✍️ **凭据存储**：安全存储 WebAuthn 凭据用于签名验证

### AegisAuthSession 特性
- 🔑 **Session 认证**：基于 Session ID 的认证
- 💾 **多种存储**：支持内存、Redis、数据库存储
- ⏰ **滑动过期**：自动延长活跃 Session
- 🔄 **Session 续期**：接近过期时自动续期
- 🛡️ **Session 固定攻击保护**：防止 Session 劫持
- 🧹 **后台清理**：定期清理过期 Session
- 📱 **多设备管理**：限制每用户最大 Session 数

## 演示项目

### AegisAuthJwtDemo（JWT + WebAuthn 完整演示）

一个完整的演示项目，展示了如何在 ASP.NET Core 应用中集成 JWT 认证和 WebAuthn 双因素认证。

**特性：**
- 🔐 JWT 令牌认证
- 🗝️ 通行密钥注册和认证
- ✍️ 数字签名功能
- 🔒 客户端私钥加密存储
- 🌐 完整的 Web 前端界面

**运行演示：**
```bash
cd AegisAuthJwtDemo
dotnet run
```

然后在浏览器中访问 `https://localhost:5001` 查看演示。

### AegisAuth.WebAuthnDemo（WebAuthn 演示）

专注于 WebAuthn 功能的演示项目。

## 快速开始

### AegisAuthJwt（JWT 认证）

详细文档请查看：[AegisAuthJwt README](AegisAuthJwt/README.md)

**安装：**
```bash
dotnet add package AegisAuthJwt
```

**基础配置：**
```csharp
// 注册仓储
builder.Services.AddScoped<IUserRepository, YourUserRepository>();
builder.Services.AddScoped<ISecurityAuditLogRepository, YourAuditLogRepository>();
builder.Services.AddScoped<ITokenBlacklistRepository, YourTokenBlacklistRepository>();

// 配置 JWT 认证
builder.Services.Configure<AuthSetting>(builder.Configuration.GetSection("AuthSetting"));
builder.Services.AddScoped<AuthManager>();

// 配置 JWT 中间件
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(/* 配置选项 */);
```

### AegisAuthSession（Session 认证）

详细文档请查看：[AegisAuthSession QUICKSTART](AegisAuthSession/QUICKSTART.md)

**安装：**
```bash
dotnet add package AegisAuthSession
```

**快速配置（三种方式）：**

1. **内存存储（开发/测试）**
```csharp
builder.Services.AddScoped<IUserRepository, YourUserRepository>();
builder.Services.AddScoped<ISecurityAuditLogRepository, YourAuditLogRepository>();

builder.Services.AddAegisAuthSessionWithMemory(settings =>
{
    settings.SessionExpirationMinutes = 30;
    settings.MaxSessionsPerUser = 5;
});

app.UseAegisAuthSession();
```

2. **Redis 存储（生产推荐）**
```csharp
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = "localhost:6379";
    options.InstanceName = "AegisAuth:";
});
builder.Services.AddAegisAuthSessionWithRedis();

app.UseAegisAuthSession();
```

3. **数据库存储**
```csharp
builder.Services.AddDbContext<YourDbContext>(/* 配置 */);
builder.Services.AddScoped<DbContext, YourDbContext>();
builder.Services.AddAegisAuthSessionWithDatabase();

app.UseAegisAuthSession();
```

## 认证方式对比

| 特性 | AegisAuthJwt | AegisAuthSession |
|------|--------------|------------------|
| **认证机制** | JWT Token | Session ID |
| **状态管理** | 无状态 | 有状态 |
| **存储方式** | 客户端（Token） | 服务端（Session Store） |
| **扩展性** | 易于水平扩展 | 需要共享存储（Redis/数据库） |
| **性能** | 无需查询存储 | 每次请求需查询存储 |
| **撤销支持** | 需要黑名单机制 | 直接删除 Session |
| **适用场景** | API、微服务、移动应用 | Web 应用、需要即时撤销的场景 |
| **安全性** | Token 泄露风险较高 | Session ID 泄露风险较低 |

## API 端点

两个库都提供了类似的 REST API 端点：

### 通用端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/api/auth/login` | 用户登录 | ❌ |
| POST | `/api/auth/logout` | 用户登出 | ✅ |

### AegisAuthJwt 特有端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/api/auth/refresh` | 刷新 Token | ❌ |

### AegisAuthSession 特有端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/api/auth/refresh` | 刷新 Session | ✅ |
| POST | `/api/auth/logout-all` | 登出所有设备 | ✅ |
| GET | `/api/auth/info` | 获取 Session 信息 | ✅ |
| GET | `/api/auth/validate` | 验证 Session | ✅ |

### 请求/响应示例

**登录请求：**
```json
{
  "userName": "testuser",
  "password": "password123"
}
```

**登录响应：**
```json
{
  "success": true,
  "data": {
    "userId": "1",
    "userName": "testuser",
    "token": "eyJhbG...", // JWT: token, Session: sessionId
    "refreshToken": "refresh_token", // 仅 JWT
    "role": "Admin"
  },
  "error": null
}
```

## WebAuthn 和通行密钥

### 技术概述

AegisAuth 集成了 WebAuthn (Web Authentication) 标准，支持 FIDO2 认证器，提供无密码的双因素认证体验。

**核心特性：**
- 🔐 **FIDO2 标准兼容**：支持所有 FIDO2 认证器
- 🗝️ **通行密钥**：无密码认证体验
- ✍️ **数字签名**：使用 WebAuthn 凭据进行数据签名
- 🔒 **客户端加密**：私钥使用 PRF 扩展加密存储在 localStorage
- ⚡ **性能优化**：客户端提供凭据 ID，避免服务器端解析开销

### 认证流程

1. **注册通行密钥**：
   - 客户端生成 ECDSA 密钥对
   - 公钥发送到服务器存储
   - 私钥使用 PRF 扩展加密后存储在客户端

2. **双因素认证**：
   - 用户提供用户名/密码
   - 客户端使用私钥签名认证挑战
   - 服务器验证签名完成认证

3. **数字签名**：
   - 客户端使用私钥对数据进行签名
   - 服务器使用存储的公钥验证签名

### 安全特性

- **零知识证明**：私钥永不离开客户端
- **防重放攻击**：每次认证使用唯一挑战
- **凭据隔离**：每个网站使用独立的凭据
- **审计日志**：记录所有认证和签名事件

## 数据模型

### 核心实体（AegisAuthBase）

#### User（用户）
```csharp
public class User
{
    public string Id { get; set; }
    public string UserName { get; set; }
    public string PasswordHash { get; set; }
    public string PasswordSalt { get; set; }
    public string? Role { get; set; }
    public bool IsActive { get; set; }
    public DateTimeOffset? LastLogin { get; set; }
    public int FailedLoginAttempts { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public DateTimeOffset? PasswordChangedAt { get; set; }
}
```

#### SecurityAuditLog（安全审计日志）
```csharp
public class SecurityAuditLog
{
    public string Id { get; set; }
    public string UserName { get; set; }
    public SecurityEventType EventType { get; set; }
    public string EventDescription { get; set; }
    public SecurityEventResult Result { get; set; }
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
```

### JWT 特有实体

#### TokenBlacklist（令牌黑名单）
```csharp
public class TokenBlacklist
{
    public string Id { get; set; }
    public string TokenHash { get; set; }
    public int TokenLength { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string? UserId { get; set; }
    public string? UserName { get; set; }
    public string? RevocationReason { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}
```

### Session 特有实体

#### Session（会话）
```csharp
public class Session
{
    public string Id { get; set; }
    public string UserId { get; set; }
    public string UserName { get; set; }
    public string? Role { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset LastAccessedAt { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}
```

### WebAuthn 特有实体

#### WebAuthnCredential（WebAuthn 凭据）
```csharp
public class WebAuthnCredential
{
    public string Id { get; set; }
    public string UserId { get; set; }
    public string CredentialId { get; set; }
    public byte[] PublicKey { get; set; }
    public string UserHandle { get; set; }
    public uint SignatureCounter { get; set; }
    public string CredType { get; set; }
    public string RegDate { get; set; }
    public Guid AaGuid { get; set; }
    public string? FriendlyName { get; set; }
}
```

### 仓储接口

您需要实现以下仓储接口：

**所有项目都需要：**
- `IUserRepository`
- `ISecurityAuditLogRepository`

**AegisAuthJwt 额外需要：**
- `ITokenBlacklistRepository`
- `IWebAuthnCredentialRepository`（用于通行密钥和数字签名功能）

**AegisAuthSession 不需要额外仓储**（使用 `ISessionStore`）

## 安全特性

### 密码安全
- ✅ PBKDF2 哈希算法
- ✅ 100,000 次迭代
- ✅ 随机盐值
- ✅ SHA256 密码哈希

### 账户保护
- ✅ 失败登录计数（5 次后锁定）
- ✅ 账户锁定（30 分钟）
- ✅ 密码修改追踪
- ✅ 账户激活状态

### 会话安全（AegisAuthSession）
- ✅ Session 固定攻击保护
- ✅ 滑动过期时间
- ✅ 多设备管理
- ✅ 强制登出所有设备

### 审计与监控
- ✅ 全面的安全审计日志
- ✅ IP 地址追踪
- ✅ User-Agent 记录
- ✅ 事件类型分类

### WebAuthn 安全
- ✅ FIDO2 标准兼容
- ✅ 公钥认证（私钥不离开客户端）
- ✅ 防重放攻击（唯一挑战）
- ✅ 凭据隔离（按域名）
- ✅ 数字签名验证
- ✅ 客户端私钥加密存储

## 配置示例

### JWT 配置（appsettings.json）
```json
{
  "AuthSetting": {
    "JwtTokenKey": "your-256-bit-secret-key-here-minimum-32-characters",
    "JwtTokenIssuer": "https://yourdomain.com",
    "JwtTokenAudience": "https://yourdomain.com",
    "AccessTokenExpirationMinutes": 60,
    "RefreshTokenExpirationDays": 7
  },
  "TokenCleanupWorker": {
    "Enabled": true,
    "CleanupIntervalHours": 24
  }
}
```

### Session 配置（appsettings.json）
```json
{
  "SessionSetting": {
    "SessionExpirationMinutes": 30,
    "SessionRememberMeExpirationDays": 7,
    "MaxSessionsPerUser": 5,
    "SessionIdLength": 64,
    "SessionCookieName": "AegisAuthSession",
    "EnableSessionFixationProtection": true,
    "EnableSlidingExpiration": true,
    "SessionRenewalMinutes": 10,
    "CleanupIntervalMinutes": 60
  },
  "Redis": {
    "Configuration": "localhost:6379",
    "InstanceName": "AegisAuth:"
  }
}
```

### WebAuthn 配置（appsettings.json）
```json
{
  "WebAuthn": {
    "ServerName": "Your App Name",
    "ServerDomain": "localhost",
    "Origins": ["https://localhost:5001"],
    "Timeout": 60000
  },
  "AuthSetting": {
    "EnableWebAuthn": true,
    "EnablePasskeyRegistration": true,
    "EnableDigitalSignatures": true
  }
}
```

## 文档

### AegisAuthJwt
- [完整文档](AegisAuthJwt/README.md)

### AegisAuthSession
- [快速开始](AegisAuthSession/QUICKSTART.md)
- [存储实现指南](AegisAuthSession/STORAGE_GUIDE.md)

### WebAuthn 和通行密钥
- [WebAuthn 集成指南](AegisAuthJwtDemo/README.md)
- [数字签名使用指南](AegisAuthJwtDemo/README.md#数字签名)

## 测试项目

两个测试项目提供了完整的使用示例：
- **AegisAuthJwtTest** - JWT 认证完整示例
- **AegisAuthSessionTest** - Session 认证完整示例

运行测试项目：
```bash
cd AegisAuthJwtTest
dotnet run

# 或
cd AegisAuthSessionTest
dotnet run
```

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 贡献

欢迎贡献！请提交 Pull Request 或创建 Issue。