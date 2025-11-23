using AegisAuthSession.Entities;
using AegisAuthSession.Repositories;
using AegisAuth.Core.Requests;
using AegisAuth.Core.Responses;
using AegisAuth.Core.Services;
using AegisAuth.Core.Entities;
using AegisAuth.Core.Repositories;
using AegisAuthSession.Settings;
using AegisAuthSession.Services;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace AegisAuthSession.Managers;

/// <summary>
/// Session 认证管理器
/// </summary>
public class SessionAuthManager
{
    private readonly SessionSetting _sessionSetting;
    private readonly ISessionStore _sessionStore;
    private readonly ILogger<SessionAuthManager> _logger;
    private readonly IUserRepository _userRepository;
    private readonly ISecurityAuditLogRepository _securityAuditLogRepository;
    private readonly PasswordSecurityService _passwordSecurityService;
    private readonly IHttpContextAccessorService _httpContextAccessor;

    public SessionAuthManager(
        SessionSetting sessionSetting,
        ISessionStore sessionStore,
        ILogger<SessionAuthManager> logger,
        IUserRepository userRepository,
        ISecurityAuditLogRepository securityAuditLogRepository,
        IHttpContextAccessorService httpContextAccessor)
    {
        _sessionSetting = sessionSetting;
        _sessionStore = sessionStore;
        _logger = logger;
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _securityAuditLogRepository = securityAuditLogRepository ?? throw new ArgumentNullException(nameof(securityAuditLogRepository));
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _passwordSecurityService = new PasswordSecurityService();
    }

    /// <summary>
    /// 用户登录 - 创建 Session
    /// </summary>
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
        var user = await _userRepository.GetUserByUserNameAsync(request.UserName);
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

        // 6. 创建 Session
        var session = await CreateUserSessionAsync(
            userId: user.Id,
            userName: user.Username,
            role: user.Role,
            ipAddress: _httpContextAccessor.GetClientIpAddress(),
            userAgent: _httpContextAccessor.GetUserAgent(),
            rememberMe: request.RememberMe
        );

        var signedInUser = new SignedInUser
        {
            UserId = session.UserId,
            UserName = session.UserName,
            Token = session.Id, // Session ID 作为 Token
            RefreshToken = session.Id, // Session ID 也作为 RefreshToken
            Role = session.Role,
            ExpiresAt = session.ExpiresAt,
            RememberMe = request.RememberMe
        };

        return new ApiResponse<SignedInUser>
        {
            Success = true,
            Data = signedInUser
        };
    }

    /// <summary>
    /// 创建新的 Session ID
    /// </summary>
    public static string GenerateSessionId(int length = 64)
    {
        var bytes = new byte[length / 2];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToHexString(bytes);
    }

    /// <summary>
    /// 验证 Session 是否有效
    /// </summary>
    public async Task<(bool isValid, Session? session, string? error)> ValidateSessionAsync(string sessionId)
    {
        try
        {
            var session = await _sessionStore.GetSessionAsync(sessionId);

            if (session == null)
            {
                _logger.LogWarning("Session not found: {SessionId}", sessionId);
                return (false, null, "Session not found");
            }

            if (!session.IsActive)
            {
                _logger.LogWarning("Session is inactive: {SessionId}", sessionId);
                return (false, null, "Session is inactive");
            }

            if (session.IsExpired)
            {
                _logger.LogWarning("Session expired: {SessionId}", sessionId);
                await _sessionStore.DeleteSessionAsync(sessionId);
                return (false, null, "Session expired");
            }

            // 更新最后访问时间
            session.LastAccessedAt = DateTimeOffset.UtcNow;

            // 如果启用滑动过期，则续期 Session
            if (_sessionSetting.EnableSlidingExpiration)
            {
                await RenewSessionIfNeededAsync(session);
            }

            await _sessionStore.UpdateSessionAsync(session);

            return (true, session, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating session: {SessionId}", sessionId);
            return (false, null, "Session validation failed");
        }
    }

    /// <summary>
    /// 创建用户 Session
    /// </summary>
    public async Task<Session> CreateUserSessionAsync(
        string userId,
        string userName,
        string? role,
        string? ipAddress,
        string? userAgent,
        bool rememberMe = false)
    {
        // 检查最大同时在线 Session 限制
        if (_sessionSetting.MaxSessionsPerUser > 0)
        {
            var activeCount = await _sessionStore.GetUserActiveSessionCountAsync(userId);
            if (activeCount >= _sessionSetting.MaxSessionsPerUser)
            {
                // 删除最旧的 Session
                await _sessionStore.DeleteUserSessionsAsync(userId);
                _logger.LogInformation("Cleared old sessions for user: {UserId}", userId);
            }
        }

        var sessionId = GenerateSessionId(_sessionSetting.SessionIdLength);
        var now = DateTimeOffset.UtcNow;

        // 计算过期时间
        var timeoutMinutes = rememberMe ?
            _sessionSetting.SessionExpirationMinutes * 24 * 7 : // 记住登录延长到7天
            _sessionSetting.SessionExpirationMinutes;

        var session = new Session
        {
            Id = sessionId,
            UserId = userId,
            UserName = userName,
            Role = role,
            CreatedAt = now,
            LastAccessedAt = now,
            ExpiresAt = now.AddMinutes(timeoutMinutes),
            IpAddress = ipAddress,
            UserAgent = userAgent,
            IsActive = true
        };

        await _sessionStore.CreateSessionAsync(session);

        _logger.LogInformation("Created session for user: {UserName} ({UserId}), SessionId: {SessionId}",
            userName, userId, sessionId);

        return session;
    }

    /// <summary>
    /// 销毁 Session
    /// </summary>
    public async Task<bool> DestroySessionAsync(string sessionId)
    {
        try
        {
            await _sessionStore.DeleteSessionAsync(sessionId);
            _logger.LogInformation("Destroyed session: {SessionId}", sessionId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error destroying session: {SessionId}", sessionId);
            return false;
        }
    }

    /// <summary>
    /// 销毁用户的所有 Session
    /// </summary>
    public async Task<int> DestroyUserSessionsAsync(string userId)
    {
        try
        {
            await _sessionStore.DeleteUserSessionsAsync(userId);
            _logger.LogInformation("Destroyed all sessions for user: {UserId}", userId);
            return await _sessionStore.GetUserActiveSessionCountAsync(userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error destroying user sessions: {UserId}", userId);
            return 0;
        }
    }

    /// <summary>
    /// 续期 Session
    /// </summary>
    public async Task<bool> RenewSessionAsync(string sessionId, TimeSpan? extension = null)
    {
        try
        {
            var extensionMinutes = extension?.TotalMinutes ?? _sessionSetting.SessionRenewalMinutes;
            return await _sessionStore.RenewSessionAsync(sessionId, TimeSpan.FromMinutes(extensionMinutes));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error renewing session: {SessionId}", sessionId);
            return false;
        }
    }

    /// <summary>
    /// 获取 Session 信息
    /// </summary>
    public async Task<SessionInfo?> GetSessionInfoAsync(string sessionId)
    {
        var session = await _sessionStore.GetSessionAsync(sessionId);
        if (session == null)
        {
            return null;
        }

        return new SessionInfo
        {
            SessionId = session.Id,
            UserId = session.UserId,
            UserName = session.UserName,
            Role = session.Role,
            CreatedAt = session.CreatedAt,
            LastAccessedAt = session.LastAccessedAt,
            ExpiresAt = session.ExpiresAt,
            IpAddress = session.IpAddress,
            UserAgent = session.UserAgent,
            RememberMe = session.RememberMe
        };
    }

    /// <summary>
    /// 清理过期 Session
    /// </summary>
    public async Task<int> CleanupExpiredSessionsAsync()
    {
        try
        {
            var deletedCount = await _sessionStore.DeleteExpiredSessionsAsync();
            _logger.LogInformation("Cleaned up {Count} expired sessions", deletedCount);
            return deletedCount;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning up expired sessions");
            return 0;
        }
    }

    /// <summary>
    /// 如果需要则续期 Session
    /// </summary>
    private async Task RenewSessionIfNeededAsync(Session session)
    {
        if (session.IsExpiringSoon)
        {
            var newExpiresAt = DateTimeOffset.UtcNow.AddMinutes(_sessionSetting.SessionExpirationMinutes);
            session.ExpiresAt = newExpiresAt;
            await _sessionStore.UpdateSessionAsync(session);

            _logger.LogInformation("Auto-renewed session: {SessionId}", session.Id);
        }
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
        return _passwordSecurityService.VerifyPassword(password, user.PasswordHash, user.PasswordSalt);
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

        await _userRepository.UpdateAsync(user);
        await _userRepository.CommitAsync();

        // 记录安全日志
        await LogFailedLoginAttempt(user.Username, $"密码验证失败，失败次数: {user.FailedLoginAttempts}");
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

        await _userRepository.UpdateAsync(user);
        await _userRepository.CommitAsync();

        // 记录安全日志
        await LogSuccessfulLogin(user.Username);
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
            IpAddress = _httpContextAccessor.GetClientIpAddress(),
            UserAgent = _httpContextAccessor.GetUserAgent()
        };

        await _securityAuditLogRepository.AddAsync(log);
        await _securityAuditLogRepository.CommitAsync();
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
            IpAddress = _httpContextAccessor.GetClientIpAddress(),
            UserAgent = _httpContextAccessor.GetUserAgent()
        };

        await _securityAuditLogRepository.AddAsync(log);
        await _securityAuditLogRepository.CommitAsync();
    }

    #endregion
}