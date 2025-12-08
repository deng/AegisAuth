namespace AegisAuthBase.Entities;

/// <summary>
/// JWT令牌黑名单实体类
/// 用于存储已失效的JWT访问令牌，防止令牌被重复使用
/// </summary>
public class TokenBlacklist
{
    /// <summary>
    /// 记录ID
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// JWT令牌（哈希值，为安全起见不存储原始令牌）
    /// </summary>
    public required string TokenHash { get; set; }

    /// <summary>
    /// 令牌原始长度（用于验证）
    /// </summary>
    public int TokenLength { get; set; }

    /// <summary>
    /// 令牌创建时间（加入黑名单的时间）
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// 令牌过期时间
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// 关联的用户ID
    /// </summary>
    public string? UserId { get; set; }

    /// <summary>
    /// 用户名（冗余字段，便于查询）
    /// </summary>
    public string? UserName { get; set; }

    /// <summary>
    /// 吊销原因
    /// </summary>
    public string? RevocationReason { get; set; }

    /// <summary>
    /// IP地址
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// 用户代理
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// 判断令牌是否已过期
    /// </summary>
    public bool IsExpired() => DateTimeOffset.UtcNow > ExpiresAt;
}