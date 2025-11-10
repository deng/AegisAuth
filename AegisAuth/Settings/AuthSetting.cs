namespace AegisAuth.Settings;

public class AuthSetting
{
    public required string JwtTokenKey { get; set; }

    public required string JwtTokenIssuer { get; set; }

    public required string JwtTokenAudience { get; set; }

    public int AccessTokenExpirationMinutes { get; set; } = 60; // 访问令牌过期时间（分钟）

    public int RefreshTokenExpirationDays { get; set; } = 7; // 刷新令牌过期时间（天）
}