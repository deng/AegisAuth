namespace AegisAuthBase.Settings;

/// <summary>
/// 认证设置
/// </summary>
public class AuthSetting
{
    /// <summary>
    /// JWT 令牌密钥
    /// </summary>
    public required string JwtTokenKey { get; set; }

    /// <summary>
    /// JWT 令牌发行者
    /// </summary>
    public required string JwtTokenIssuer { get; set; }

    /// <summary>
    /// JWT 令牌受众
    /// </summary>
    public required string JwtTokenAudience { get; set; }

    /// <summary>
    /// 访问令牌过期时间（分钟）
    /// </summary>
    public int AccessTokenExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// 刷新令牌过期时间（天）
    /// </summary>
    public int RefreshTokenExpirationDays { get; set; } = 7;

    /// <summary>
    /// Session 过期时间（分钟）
    /// </summary>
    public int SessionExpirationMinutes { get; set; } = 30;

    /// <summary>
    /// 记住我 Session 过期时间（天）
    /// </summary>
    public int SessionRememberMeExpirationDays { get; set; } = 7;

    /// <summary>
    /// 每个用户最大 Session 数量
    /// </summary>
    public int MaxSessionsPerUser { get; set; } = 5;
}