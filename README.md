# AegisAuth

一个功能全面的 JWT 认证服务库，为 ASP.NET Core 应用程序提供令牌黑名单和安全审计日志功能。

## 特性

- 🔐 **JWT 认证**：支持可配置过期时间的安全令牌认证
- 🚫 **令牌黑名单**：具有持久化存储的自动令牌失效机制
- 📊 **安全审计日志**：全面记录认证事件
- 🔄 **令牌刷新**：支持刷新令牌的自动续期
- 🧹 **自动清理**：后台工作进程自动清理过期令牌
- 🛡️ **密码安全**：基于 PBKDF2 的密码哈希加盐
- 🌐 **ASP.NET Core 集成**：与 ASP.NET Core 应用程序无缝集成
- 🎯 **即用控制器**：内置 AuthController 可直接使用

## 安装

```bash
dotnet add package AegisAuth
```

## 快速开始

### 1. 配置服务

```csharp
using AegisAuth;
using AegisAuth.Entities;
using AegisAuth.Repositories;
using AegisAuth.Services;
using AegisAuth.Settings;
using AegisAuth.Workers;

// 在 Program.cs 或 Startup.cs 中
builder.Services.AddScoped<IUserRepository, YourUserRepository>();
builder.Services.AddScoped<ISecurityAuditLogRepository, YourSecurityAuditLogRepository>();
builder.Services.AddScoped<ITokenBlacklistRepository, YourTokenBlacklistRepository>();

builder.Services.AddScoped<AuthManager>();
builder.Services.AddScoped<IHttpContextAccessorService, HttpContextAccessorService>();

// 配置设置
builder.Services.Configure<AuthSetting>(builder.Configuration.GetSection("AuthSetting"));

// 添加令牌清理后台工作进程
builder.Services.Configure<TokenCleanupWorkerOptions>(
    builder.Configuration.GetSection("TokenCleanupWorker"));
builder.Services.AddHostedService<TokenCleanupWorker>();
```

### 2. 配置认证中间件

```csharp
// 添加 JWT 认证
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var authSetting = builder.Configuration.GetSection("AuthSetting").Get<AuthSetting>();

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = authSetting.JwtTokenIssuer,
        ValidateAudience = true,
        ValidAudience = authSetting.JwtTokenAudience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authSetting.JwtTokenKey)),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };

    // 添加令牌黑名单验证
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var tokenHash = AuthManager.ComputeTokenHash(token);

            if (AuthManager.IsTokenBlacklisted(tokenHash))
            {
                context.Fail("Token has been revoked");
            }
        }
    };
});
```

### 3. 初始化令牌黑名单

在应用程序启动时，需要从数据库加载令牌黑名单到内存中：

```csharp
var app = builder.Build();

// 初始化令牌黑名单（重要：必须在处理任何请求之前调用）
using (var scope = app.Services.CreateScope())
{
    var authManager = scope.ServiceProvider.GetRequiredService<AuthManager>();
    await authManager.InitializeMemoryBlacklistAsync();
}

// 配置中间件管道
app.UseAuthentication();
app.UseAuthorization();
```

**注意：** 如果不调用 `InitializeMemoryBlacklistAsync()`，在验证令牌时会抛出 `InvalidOperationException` 异常。

### 4. 使用内置的认证控制器

该包包含一个即用的 `AuthController`。只需在您的应用程序中注册它：

```csharp
// 在 Program.cs 中
using AegisAuth.Controllers;

// 添加该包后，AuthController 会自动可用
// 您可以通过继承它来自定义，或直接使用它
```

### 5. 配置应用程序设置

如果您希望创建自定义配置：

```json
{
  "AuthSetting": {
    "JwtTokenKey": "your-256-bit-secret-key-here",
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

## API 参考

### AuthController

内置的 REST API 控制器，提供开箱即用的认证端点。

#### POST /api/auth/login
用户登录端点。

**请求体：**
```json
{
  "userName": "用户名",
  "password": "密码"
}
```

**响应：**
```json
{
  "success": true,
  "data": {
    "userId": "用户ID",
    "userName": "用户名",
    "token": "访问令牌",
    "refreshToken": "刷新令牌",
    "role": "用户角色"
  },
  "error": null
}
```

#### POST /api/auth/refresh
刷新访问令牌端点。

**请求体：**
```json
{
  "refreshToken": "刷新令牌"
}
```

**响应：**
```json
{
  "success": true,
  "data": {
    "userId": "用户ID",
    "userName": "用户名",
    "token": "新的访问令牌",
    "refreshToken": "新的刷新令牌",
    "role": "用户角色"
  },
  "error": null
}
```

#### POST /api/auth/logout
用户登出端点（需要认证）。

**请求头：**
```
Authorization: Bearer {访问令牌}
```

**响应：**
```json
{
  "success": true,
  "data": true,
  "error": null
}
```

### AuthManager

核心认证管理器，提供认证逻辑的实现。

#### SignIn(LoginRequest)
验证用户身份并返回 JWT 令牌。

**参数：**
- `request`：包含用户名和密码的 LoginRequest

**返回：** 包含访问令牌和刷新令牌的 `ApiResponse<SignedInUser>`

#### RefreshToken(RefreshTokenRequest)
使用有效的刷新令牌刷新访问令牌。

**参数：**
- `request`：包含刷新令牌的 RefreshTokenRequest

**返回：** 包含新令牌的 `ApiResponse<SignedInUser>`

#### Logout()
通过将当前访问令牌添加到黑名单来使其失效。

**返回：** 指示成功的 `ApiResponse<bool>`

#### ComputeTokenHash(string)
计算令牌的 SHA256 哈希值的静态方法。

#### IsTokenBlacklisted(string)
检查令牌哈希是否在黑名单中的静态方法。

**参数：**
- `tokenHash`：令牌的 SHA256 哈希值

**返回：** `bool` - 如果令牌在黑名单中返回 true

**异常：** 如果黑名单未初始化，抛出 `InvalidOperationException`

#### InitializeMemoryBlacklistAsync()
从数据库加载所有未过期的令牌到内存黑名单中。

**使用场景：**
- 应用程序启动时必须调用一次
- 在长时间运行的应用中，可以定期调用以同步数据库状态

**示例：**
```csharp
// 在应用启动时
using (var scope = app.Services.CreateScope())
{
    var authManager = scope.ServiceProvider.GetRequiredService<AuthManager>();
    await authManager.InitializeMemoryBlacklistAsync();
}
```

**注意事项：**
- 此方法会清空现有的内存黑名单并重新加载
- 操作是线程安全的
- 会记录安全审计日志

## 数据库架构

该库需要以下实体：

### User（用户）
- `Id`: string（主键）
- `Username`: string（用户名）
- `PasswordHash`: string（密码哈希）
- `PasswordSalt`: string（密码盐）
- `Role`: string?（用户角色，可由使用者自定义，如 "Admin", "User" 等）
- `IsActive`: bool（是否激活）
- `LastLogin`: DateTimeOffset?（最后登录时间）
- `FailedLoginAttempts`: int（失败登录尝试次数）
- `LockoutEnd`: DateTimeOffset?（锁定结束时间）
- `PasswordChangedAt`: DateTimeOffset?（密码修改时间）

### TokenBlacklist（令牌黑名单）
- `Id`: string（主键）
- `TokenHash`: string（SHA256 哈希）
- `TokenLength`: int（令牌长度）
- `ExpiresAt`: DateTime（过期时间）
- `UserId`: string?（用户 ID）
- `UserName`: string?（用户名）
- `RevocationReason`: string?（撤销原因）
- `IpAddress`: string?（IP 地址）
- `UserAgent`: string?（用户代理）

### SecurityAuditLog（安全审计日志）
- `Id`: string（主键）
- `UserName`: string（用户名）
- `EventType`: SecurityEventType（事件类型）
- `EventDescription`: string（事件描述）
- `Result`: SecurityEventResult（结果）
- `Details`: string?（详细信息）
- `IpAddress`: string?（IP 地址）
- `UserAgent`: string?（用户代理）
- `CreatedAt`: DateTimeOffset（创建时间）

## 安全功能

- **密码哈希**：使用 PBKDF2 进行 100,000 次迭代并使用随机盐
- **令牌黑名单**：防止已撤销令牌的重复使用
- **账户锁定**：登录失败后自动锁定账户
- **安全审计**：全面记录所有认证事件
- **IP 追踪**：记录客户端 IP 地址以进行安全监控

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 许可证

本项目基于 MIT 许可证 - 详见 LICENSE 文件。

## 支持

如需支持和提问，请在 GitHub 上提交 issue。