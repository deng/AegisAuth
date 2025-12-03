using AegisAuthBase.Repositories;
using AegisAuthBase.Entities;
using AegisAuthBase.Requests;
using AegisAuthBase.Responses;
using AegisAuthBase.Services;
using AegisAuthBase.Settings;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AegisAuthJwt.Managers;

/// <summary>
/// JWT 认证管理器
/// </summary>
public class AuthManager
{
    private readonly AuthSetting m_AuthSetting;
    private readonly IUserRepository m_UserRepository;
    private readonly ISecurityAuditLogRepository m_SecurityAuditLogRepository;
    private readonly ITokenBlacklistRepository m_TokenBlacklistRepository;
    private readonly PasswordSecurityService m_PasswordSecurityService;
    private readonly IHttpContextAccessorService m_HttpContextAccessor;

    // Token黑名单 - 存储已失效的访问令牌
    private static readonly HashSet<string> s_TokenBlacklist = new HashSet<string>();
    
    // 标识内存黑名单是否已初始化
    private static bool s_IsBlacklistInitialized = false;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="authSetting">认证设置</param>
    /// <param name="userRepository">用户仓储</param>
    /// <param name="securityAuditLogRepository">安全审计日志仓储</param>
    /// <param name="tokenBlacklistRepository">令牌黑名单仓储</param>
    /// <param name="httpContextAccessor">HTTP 上下文访问器服务</param>
    public AuthManager(AuthSetting authSetting, IUserRepository userRepository, ISecurityAuditLogRepository securityAuditLogRepository, ITokenBlacklistRepository tokenBlacklistRepository, IHttpContextAccessorService httpContextAccessor)
    {
        m_AuthSetting = authSetting;
        m_UserRepository = userRepository;
        m_SecurityAuditLogRepository = securityAuditLogRepository ?? throw new ArgumentNullException(nameof(securityAuditLogRepository));
        m_TokenBlacklistRepository = tokenBlacklistRepository ?? throw new ArgumentNullException(nameof(tokenBlacklistRepository));
        m_HttpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        m_PasswordSecurityService = new PasswordSecurityService();
    }

    /// <summary>
    /// 用户登录
    /// </summary>
    /// <param name="request">登录请求</param>
    /// <returns>登录结果</returns>
    public async Task<ApiResponse<SignedInUser>> SignIn(LoginRequest request)
    {
        // 1. 验证请求参数
        var validationResult = ValidateRequest(request);
        if (!validationResult.isValid)
        {
            return new ApiResponse<SignedInUser>
            {
                Success = false,
                Error = validationResult.message
            };
        }

        // 2. 获取用户信息
        var user = await m_UserRepository.GetUserByUserNameAsync(request.UserName);
        if (user == null)
        {
            // 记录失败的登录尝试（即使用户不存在也要记录，防止用户名枚举）
            await LogFailedLoginAttempt(request.UserName, "用户不存在");
            return new ApiResponse<SignedInUser>
            {
                Success = false,
                Error = "用户名或密码错误"
            };
        }

        // 3. 检查账户状态
        var accountCheck = await CheckAccountStatus(user);
        if (!accountCheck.isValid)
        {
            return new ApiResponse<SignedInUser>
            {
                Success = false,
                Error = accountCheck.message
            };
        }

        // 4. 验证密码
        var passwordValid = ValidatePassword(request.Password, user);
        if (!passwordValid)
        {
            // 记录失败的登录尝试
            await HandleFailedLoginAttempt(user);
            return new ApiResponse<SignedInUser>
            {
                Success = false,
                Error = "用户名或密码错误"
            };
        }

        // 5. 登录成功，重置失败计数并更新最后登录时间
        await HandleSuccessfulLogin(user);

        // 6. 生成 JWT token 和刷新令牌
        var token = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken(user);

        var signedInUser = new SignedInUser
        {
            UserId = user.Id,
            UserName = user.UserName,
            Token = token,
            RefreshToken = refreshToken,
            Role = user.Role,
            ExpiresAt = DateTimeOffset.Now.AddMinutes(m_AuthSetting.AccessTokenExpirationMinutes)
        };

        return new ApiResponse<SignedInUser>
        {
            Success = true,
            Data = signedInUser
        };
    }

    /// <summary>
    /// 用户注册
    /// </summary>
    /// <param name="request">注册请求</param>
    /// <returns>注册结果</returns>
    public async Task<ApiResponse> Register(RegisterRequest request)
    {
        // 1. 验证请求参数
        var validationResult = ValidateRegisterRequest(request);
        if (!validationResult.isValid)
        {
            return new ApiResponse
            {
                Success = false,
                Error = validationResult.message
            };
        }

        // 2. 检查用户名是否已存在
        var existingUser = await m_UserRepository.GetUserByUserNameAsync(request.UserName);
        if (existingUser != null)
        {
            return new ApiResponse
            {
                Success = false,
                Error = "用户名已存在"
            };
        }

        // 3. 创建新用户
        var (passwordHash, passwordSalt) = m_PasswordSecurityService.CreatePasswordHash(request.Password);
        var newUser = new User
        {
            UserName = request.UserName,
            PasswordHash = passwordHash,
            PasswordSalt = passwordSalt,
            Role = UserRole.User,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            FailedLoginAttempts = 0,
            IsLocked = false
        };

        // 4. 保存用户
        await m_UserRepository.CreateAsync(newUser);
        await m_UserRepository.CommitAsync();

        // 5. 记录注册日志
        await m_SecurityAuditLogRepository.AddAsync(new SecurityAuditLog
        {
            UserName = newUser.UserName,
            EventType = SecurityEventType.SensitiveOperation,
            EventDescription = "User registered",
            Details = $"User {newUser.UserName} registered",
            IpAddress = m_HttpContextAccessor.GetClientIpAddress(),
            UserAgent = m_HttpContextAccessor.GetUserAgent(),
            Result = SecurityEventResult.Success,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await m_SecurityAuditLogRepository.CommitAsync();

        return new ApiResponse
        {
            Success = true
        };
    }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="request">刷新令牌请求</param>
    /// <returns>刷新结果</returns>
    public async Task<ApiResponse<SignedInUser>> RefreshToken(RefreshTokenRequest request)
    {
        try
        {
            // 验证刷新令牌
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtTokenKey = m_AuthSetting.JwtTokenKey;
            var jwtTokenIssuer = m_AuthSetting.JwtTokenIssuer;
            var jwtTokenAudience = m_AuthSetting.JwtTokenAudience;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtTokenKey)),
                ValidateIssuer = true,
                ValidIssuer = jwtTokenIssuer,
                ValidateAudience = true,
                ValidAudience = jwtTokenAudience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            // 解析令牌
            var principal = tokenHandler.ValidateToken(request.RefreshToken, validationParameters, out var validatedToken);
            var jwtToken = (JwtSecurityToken)validatedToken;

            // 检查是否为刷新令牌
            var tokenType = jwtToken.Claims.FirstOrDefault(c => c.Type == "token_type")?.Value;
            if (tokenType != "refresh")
            {
                return new ApiResponse<SignedInUser>
                {
                    Success = false,
                    Error = "无效的刷新令牌"
                };
            }

            // 获取用户ID
            var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new ApiResponse<SignedInUser>
                {
                    Success = false,
                    Error = "无效的刷新令牌"
                };
            }

            // 获取用户信息
            var user = await m_UserRepository.GetByIdAsync(userId, false);
            if (user == null)
            {
                return new ApiResponse<SignedInUser>
                {
                    Success = false,
                    Error = "用户不存在"
                };
            }

            // 检查账户状态
            var accountCheck = await CheckAccountStatus(user);
            if (!accountCheck.isValid)
            {
                return new ApiResponse<SignedInUser>
                {
                    Success = false,
                    Error = accountCheck.message
                };
            }

            // 生成新的访问令牌和刷新令牌
            var newAccessToken = GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken(user);

            var signedInUser = new SignedInUser
            {
                UserId = user.Id,
                UserName = user.UserName,
                Token = newAccessToken,
                RefreshToken = newRefreshToken,
                Role = user.Role,
                ExpiresAt = DateTimeOffset.Now.AddMinutes(m_AuthSetting.AccessTokenExpirationMinutes)
            };

            // 记录安全日志
            await LogSuccessfulLogin(user.UserName);

            return new ApiResponse<SignedInUser>
            {
                Success = true,
                Data = signedInUser
            };
        }
        catch (SecurityTokenException)
        {
            return new ApiResponse<SignedInUser>
            {
                Success = false,
                Error = "无效的刷新令牌"
            };
        }
        catch (Exception ex)
        {
            // 记录安全日志
            await m_SecurityAuditLogRepository.AddAsync(new SecurityAuditLog
            {
                UserName = "unknown",
                EventType = SecurityEventType.UserLogin,
                EventDescription = "令牌刷新失败",
                Result = SecurityEventResult.Failure,
                Details = $"异常: {ex.Message}",
                IpAddress = m_HttpContextAccessor.GetClientIpAddress(),
                UserAgent = m_HttpContextAccessor.GetUserAgent()
            });
            await m_SecurityAuditLogRepository.CommitAsync();

            return new ApiResponse<SignedInUser>
            {
                Success = false,
                Error = "令牌刷新失败"
            };
        }
    }

    /// <summary>
    /// 用户登出
    /// </summary>
    /// <returns>登出结果</returns>
    public async Task<ApiResponse> Logout()
    {
        try
        {
            // 获取当前请求的Authorization header中的令牌
            var authorizationHeader = m_HttpContextAccessor.GetAuthorizationHeader();
            
            if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
            {
                return new ApiResponse
                {
                    Success = false,
                    Error = "未找到有效的访问令牌"
                };
            }

            var token = authorizationHeader.Substring("Bearer ".Length);

            // 计算令牌哈希
            var tokenHash = ComputeTokenHash(token);

            // 解析JWT令牌获取过期时间
            var tokenExpiry = DateTime.UtcNow.AddHours(1); // 默认1小时后过期
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
                if (jwtToken?.ValidTo != null)
                {
                    tokenExpiry = jwtToken.ValidTo;
                }
            }
            catch
            {
                // 如果无法解析令牌，使用默认过期时间（1小时后）
                tokenExpiry = DateTime.UtcNow.AddHours(1);
            }

            // 将令牌添加到内存黑名单（仅在黑名单已初始化后）
            if (s_IsBlacklistInitialized)
            {
                lock (s_TokenBlacklist)
                {
                    s_TokenBlacklist.Add(tokenHash);
                }
            }

            // 获取当前用户信息
            var userId = m_HttpContextAccessor.GetCurrentUserId();
            var user = await m_UserRepository.GetByIdAsync(userId, false);
            var userName = user?.UserName ?? "unknown";

            // 将令牌添加到数据库黑名单
            var tokenBlacklist = new TokenBlacklist
            {
                TokenHash = tokenHash,
                TokenLength = token.Length,
                ExpiresAt = tokenExpiry,
                UserId = userId,
                UserName = userName,
                RevocationReason = "用户主动登出",
                IpAddress = m_HttpContextAccessor.GetClientIpAddress(),
                UserAgent = m_HttpContextAccessor.GetUserAgent()
            };

            await m_TokenBlacklistRepository.AddAsync(tokenBlacklist);
            await m_TokenBlacklistRepository.CommitAsync();

            // 记录安全日志
            await m_SecurityAuditLogRepository.AddAsync(new SecurityAuditLog
            {
                UserName = userName,
                EventType = SecurityEventType.UserLogout,
                EventDescription = "用户主动登出",
                Result = SecurityEventResult.Success,
                Details = "令牌已加入黑名单",
                IpAddress = m_HttpContextAccessor.GetClientIpAddress(),
                UserAgent = m_HttpContextAccessor.GetUserAgent()
            });
            await m_SecurityAuditLogRepository.CommitAsync();

            return new ApiResponse
            {
                Success = true,
            };
        }
        catch (Exception ex)
        {
            // 记录安全日志
            await m_SecurityAuditLogRepository.AddAsync(new SecurityAuditLog
            {
                UserName = "unknown",
                EventType = SecurityEventType.UserLogout,
                EventDescription = "用户登出失败",
                Result = SecurityEventResult.Failure,
                Details = $"异常: {ex.Message}",
                IpAddress = m_HttpContextAccessor.GetClientIpAddress(),
                UserAgent = m_HttpContextAccessor.GetUserAgent()
            });
            await m_SecurityAuditLogRepository.CommitAsync();

            return new ApiResponse
            {
                Success = false,
                Error = "登出失败"
            };
        }
    }

    /// <summary>
    /// 计算令牌的SHA256哈希值
    /// </summary>
    public static string ComputeTokenHash(string token)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// 检查令牌哈希是否在内存黑名单中
    /// </summary>
    public static bool IsTokenBlacklisted(string tokenHash)
    {
        // 如果黑名单未初始化，抛出异常
        if (!s_IsBlacklistInitialized)
        {
            throw new InvalidOperationException("内存黑名单尚未初始化，请先调用InitializeMemoryBlacklistAsync方法");
        }

        lock (s_TokenBlacklist)
        {
            return s_TokenBlacklist.Contains(tokenHash);
        }
    }

    /// <summary>
    /// 初始化内存黑名单，从数据库加载所有未过期的令牌
    /// </summary>
    public async Task InitializeMemoryBlacklistAsync()
    {
        try
        {
            // 获取所有未过期的令牌哈希
            var validTokenHashes = await GetValidTokenHashesFromDatabaseAsync();

            // 原子性地更新内存黑名单
            lock (s_TokenBlacklist)
            {
                s_TokenBlacklist.Clear();
                foreach (var tokenHash in validTokenHashes)
                {
                    s_TokenBlacklist.Add(tokenHash);
                }
            }

            // 标记黑名单已初始化
            s_IsBlacklistInitialized = true;

            // 记录初始化完成
            await m_SecurityAuditLogRepository.AddAsync(new SecurityAuditLog
            {
                UserName = "system",
                EventType = SecurityEventType.UserLogout, // 复用登出事件类型
                EventDescription = "内存黑名单初始化完成",
                Result = SecurityEventResult.Success,
                Details = $"已加载 {validTokenHashes.Count} 个令牌到内存黑名单",
                IpAddress = "127.0.0.1",
                UserAgent = "System"
            });
            await m_SecurityAuditLogRepository.CommitAsync();
        }
        catch (Exception ex)
        {
            // 记录初始化失败
            await m_SecurityAuditLogRepository.AddAsync(new SecurityAuditLog
            {
                UserName = "system",
                EventType = SecurityEventType.UserLogout,
                EventDescription = "内存黑名单初始化失败",
                Result = SecurityEventResult.Failure,
                Details = $"异常: {ex.Message}",
                IpAddress = "127.0.0.1",
                UserAgent = "System"
            });
            await m_SecurityAuditLogRepository.CommitAsync();
            throw;
        }
    }

    /// <summary>
    /// 从数据库获取所有未过期的令牌哈希
    /// </summary>
    private async Task<List<string>> GetValidTokenHashesFromDatabaseAsync()
    {
        return await m_TokenBlacklistRepository.GetValidTokenHashesAsync();
    }

    private string GenerateJwtToken(User user)
    {
        var jwtTokenKey = m_AuthSetting.JwtTokenKey;
        var jwtTokenIssuer = m_AuthSetting.JwtTokenIssuer;
        var jwtTokenAudience = m_AuthSetting.JwtTokenAudience;

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtTokenKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // 添加角色声明
        claims.Add(new Claim(ClaimTypes.Role, user.Role.ToString()));

        var token = new JwtSecurityToken(
            issuer: jwtTokenIssuer,
            audience: jwtTokenAudience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(m_AuthSetting.AccessTokenExpirationMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken(User user)
    {
        var jwtTokenKey = m_AuthSetting.JwtTokenKey;
        var jwtTokenIssuer = m_AuthSetting.JwtTokenIssuer;
        var jwtTokenAudience = m_AuthSetting.JwtTokenAudience;

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtTokenKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("token_type", "refresh")
        };

        var token = new JwtSecurityToken(
            issuer: jwtTokenIssuer,
            audience: jwtTokenAudience,
            claims: claims,
            expires: DateTime.Now.AddDays(m_AuthSetting.RefreshTokenExpirationDays),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    #region 私有验证方法

    /// <summary>
    /// 验证请求参数
    /// </summary>
    private (bool isValid, string message) ValidateRequest(LoginRequest request)
    {
        if (request == null)
            return (false, "请求不能为空");

        if (string.IsNullOrWhiteSpace(request.UserName))
            return (false, "用户名不能为空");

        if (string.IsNullOrWhiteSpace(request.Password))
            return (false, "密码不能为空");

        if (request.UserName.Length > 50)
            return (false, "用户名长度不能超过50个字符");

        if (request.Password.Length > 128)
            return (false, "密码长度不能超过128个字符");

        return (true, string.Empty);
    }

    private (bool isValid, string message) ValidateRegisterRequest(RegisterRequest request)
    {
        if (request == null)
            return (false, "请求不能为空");

        if (string.IsNullOrWhiteSpace(request.UserName))
            return (false, "用户名不能为空");

        if (string.IsNullOrWhiteSpace(request.Password))
            return (false, "密码不能为空");

        if (request.UserName.Length > 50)
            return (false, "用户名长度不能超过50个字符");

        if (request.Password.Length > 128)
            return (false, "密码长度不能超过128个字符");

        if (request.Password != request.ConfirmPassword)
            return (false, "密码和确认密码不匹配");

        return (true, string.Empty);
    }

    /// <summary>
    /// 检查账户状态
    /// </summary>
    private Task<(bool isValid, string message)> CheckAccountStatus(User user)
    {
        // 检查账户是否激活
        if (!user.IsActive)
            return Task.FromResult((false, "账户未激活，请联系管理员"));

        // 检查账户是否被锁定
        if (user.IsLocked)
            return Task.FromResult((false, "账户已被锁定，请联系管理员"));

        // 检查是否在锁定期间
        if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
        {
            var remainingTime = user.LockoutEnd.Value - DateTimeOffset.UtcNow;
            return Task.FromResult((false, $"账户暂时锁定，请在 {remainingTime.TotalMinutes:F0} 分钟后重试"));
        }

        // 检查密码是否过期（90天）
        if (user.PasswordChangedAt.HasValue)
        {
            var passwordAge = DateTimeOffset.UtcNow - user.PasswordChangedAt.Value;
            if (passwordAge.TotalDays > 90)
                return Task.FromResult((false, "密码已过期，请修改密码"));
        }

        return Task.FromResult((true, string.Empty));
    }

    /// <summary>
    /// 验证密码
    /// </summary>
    private bool ValidatePassword(string password, User user)
    {
        return m_PasswordSecurityService.VerifyPassword(password, user.PasswordHash, user.PasswordSalt);
    }

    /// <summary>
    /// 处理登录失败
    /// </summary>
    private async Task HandleFailedLoginAttempt(User user)
    {
        // 增加失败次数
        user.FailedLoginAttempts++;

        // 如果失败次数达到阈值，锁定账户
        const int maxFailedAttempts = 5;
        if (user.FailedLoginAttempts >= maxFailedAttempts)
        {
            user.IsLocked = true;
            user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(30); // 锁定30分钟
        }

        await m_UserRepository.UpdateAsync(user);
        await m_UserRepository.CommitAsync();

        // 记录安全日志
        await LogFailedLoginAttempt(user.UserName, $"密码验证失败，失败次数: {user.FailedLoginAttempts}");
    }

    /// <summary>
    /// 处理登录成功
    /// </summary>
    private async Task HandleSuccessfulLogin(User user)
    {
        // 重置失败次数
        user.FailedLoginAttempts = 0;
        user.IsLocked = false;
        user.LockoutEnd = null;
        user.LastLogin = DateTimeOffset.UtcNow;

        await m_UserRepository.UpdateAsync(user);
        await m_UserRepository.CommitAsync();

        // 记录安全日志
        await LogSuccessfulLogin(user.UserName);
    }

    /// <summary>
    /// 记录失败登录尝试
    /// </summary>
    private async Task LogFailedLoginAttempt(string userName, string reason)
    {
        var log = new SecurityAuditLog
        {
            UserName = userName,
            EventType = SecurityEventType.UserLogin,
            EventDescription = $"登录失败: {reason}",
            Result = SecurityEventResult.Failure,
            Details = $"失败原因: {reason}",
            IpAddress = m_HttpContextAccessor.GetClientIpAddress(),
            UserAgent = m_HttpContextAccessor.GetUserAgent()
        };

        await m_SecurityAuditLogRepository.AddAsync(log);
        await m_SecurityAuditLogRepository.CommitAsync();
    }

    /// <summary>
    /// 记录成功登录
    /// </summary>
    private async Task LogSuccessfulLogin(string userName)
    {
        var log = new SecurityAuditLog
        {
            UserName = userName,
            EventType = SecurityEventType.UserLogin,
            EventDescription = "用户登录成功",
            Result = SecurityEventResult.Success,
            IpAddress = m_HttpContextAccessor.GetClientIpAddress(),
            UserAgent = m_HttpContextAccessor.GetUserAgent()
        };

        await m_SecurityAuditLogRepository.AddAsync(log);
        await m_SecurityAuditLogRepository.CommitAsync();
    }

    #endregion
}