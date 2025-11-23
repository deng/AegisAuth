namespace AegisAuthSession.Settings;

public class SessionSetting
{
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

    /// <summary>
    /// Session 清理间隔（分钟）
    /// </summary>
    public int CleanupIntervalMinutes { get; set; } = 60;

    /// <summary>
    /// Session Cookie 名称
    /// </summary>
    public string SessionCookieName { get; set; } = "AegisAuthSession";

    /// <summary>
    /// 是否启用滑动过期
    /// </summary>
    public bool EnableSlidingExpiration { get; set; } = true;

    /// <summary>
    /// Session ID 长度（字节）
    /// </summary>
    public int SessionIdLength { get; set; } = 64;

    /// <summary>
    /// Session 续期时间（分钟）
    /// </summary>
    public int SessionRenewalMinutes { get; set; } = 10;

    /// <summary>
    /// 是否启用 Session 固定攻击保护
    /// </summary>
    public bool EnableSessionFixationProtection { get; set; } = true;
}