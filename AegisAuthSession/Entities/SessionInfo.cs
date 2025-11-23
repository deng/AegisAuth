namespace AegisAuthSession.Entities;

/// <summary>
/// Session 信息
/// </summary>
public class SessionInfo
{
    /// <summary>
    /// Session ID
    /// </summary>
    public required string SessionId { get; set; }

    /// <summary>
    /// 用户ID
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// 用户名
    /// </summary>
    public required string UserName { get; set; }

    /// <summary>
    /// 用户角色
    /// </summary>
    public string? Role { get; set; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// 最后活动时间
    /// </summary>
    public DateTimeOffset LastActivity { get; set; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// IP地址
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// 用户代理
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// 是否记住登录
    /// </summary>
    public bool RememberMe { get; set; }

    /// <summary>
    /// 判断 Session 是否已过期
    /// </summary>
    public bool IsExpired => DateTimeOffset.UtcNow > ExpiresAt;

    /// <summary>
    /// 检查 Session 是否即将过期（5分钟内）
    /// </summary>
    public bool IsExpiringSoon => (ExpiresAt - DateTimeOffset.UtcNow).TotalMinutes < 5;

    /// <summary>
    /// 获取剩余时间（分钟）
    /// </summary>
    public double RemainingMinutes => (ExpiresAt - DateTimeOffset.UtcNow).TotalMinutes;

    // 兼容性属性
    public DateTimeOffset LastAccessedAt
    {
        get => LastActivity;
        set => LastActivity = value;
    }
}