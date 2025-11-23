namespace AegisAuth.Core.Settings;

public class AuthSetting
{
    public required string JwtTokenKey { get; set; }

    public required string JwtTokenIssuer { get; set; }

    public required string JwtTokenAudience { get; set; }

    public int AccessTokenExpirationMinutes { get; set; } = 60; // 访问令牌过期时间（分钟）

    public int RefreshTokenExpirationDays { get; set; } = 7; // 刷新令牌过期时间（天）

    // Session 设置
    public int SessionExpirationMinutes { get; set; } = 30; // Session 过期时间（分钟）

    public int SessionRememberMeExpirationDays { get; set; } = 7; // 记住我 Session 过期时间（天）

    public int MaxSessionsPerUser { get; set; } = 5; // 每个用户最大 Session 数量
}