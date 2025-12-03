using AegisAuthBase.Entities;

namespace AegisAuthBase.Responses;

/// <summary>
/// 已登录用户响应
/// </summary>
public class SignedInUser
{
    /// <summary>
    /// 用户ID
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// 用户名
    /// </summary>
    public required string UserName { get; set; }

    /// <summary>
    /// 访问令牌
    /// </summary>
    public required string Token { get; set; }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    public required string RefreshToken { get; set; }

    /// <summary>
    /// 用户角色
    /// </summary>
    public UserRole Role { get; set; }

    /// <summary>
    /// 令牌过期时间
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>
    /// 是否记住登录状态
    /// </summary>
    public bool RememberMe { get; set; }
}