using AegisAuthBase.Entities;
using Fido2NetLib;

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
    /// 过期时间
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// 是否已启用双因素认证
    /// </summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>
    /// 是否需要双因素认证
    /// </summary>
    public bool RequiresTwoFactor { get; set; }

    /// <summary>
    /// 双因素认证临时ID (用于验证)
    /// </summary>
    public string? TwoFactorId { get; set; }

    /// <summary>
    /// 双因素认证类型
    /// </summary>
    public TwoFactorTypeFlags TwoFactorType { get; set; }

    /// <summary>
    /// 通行密钥登录选项 (WebAuthn AssertionOptions)
    /// </summary>
    public AssertionOptions? PasskeyOptions { get; set; }

    /// <summary>
    /// 是否记住登录状态
    /// </summary>
    public bool RememberMe { get; set; }
}