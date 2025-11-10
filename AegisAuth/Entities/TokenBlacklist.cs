using System.ComponentModel.DataAnnotations;

namespace AegisAuth.Entities;

/// <summary>
/// JWT令牌黑名单实体类
/// 用于存储已失效的JWT访问令牌，防止令牌被重复使用
/// </summary>
public class TokenBlacklist
{
    /// <summary>
    /// 记录ID
    /// </summary>
    [StringLength(50)]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// JWT令牌（哈希值，为安全起见不存储原始令牌）
    /// </summary>
    [StringLength(128)] // SHA256哈希长度
    public required string TokenHash { get; set; }

    /// <summary>
    /// 令牌原始长度（用于验证）
    /// </summary>
    public int TokenLength { get; set; }

    /// <summary>
    /// 令牌创建时间（加入黑名单的时间）
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 令牌过期时间
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// 关联的用户ID
    /// </summary>
    [StringLength(50)]
    public string? UserId { get; set; }

    /// <summary>
    /// 用户名（冗余字段，便于查询）
    /// </summary>
    [StringLength(50)]
    public string? UserName { get; set; }

    /// <summary>
    /// 吊销原因
    /// </summary>
    [StringLength(200)]
    public string? RevocationReason { get; set; }

    /// <summary>
    /// IP地址
    /// </summary>
    [StringLength(45)] // IPv6最大长度
    public string? IpAddress { get; set; }

    /// <summary>
    /// 用户代理
    /// </summary>
    [StringLength(500)]
    public string? UserAgent { get; set; }

    /// <summary>
    /// 判断令牌是否已过期
    /// </summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
}