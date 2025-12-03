using AegisAuthBase.Entities;
using System.ComponentModel.DataAnnotations;

namespace AegisAuthSession.Entities;

/// <summary>
/// Session 实体类
/// </summary>
public class Session
{
    /// <summary>
    /// Session ID（主键）
    /// </summary>
    [StringLength(128)]
    public required string Id { get; set; }

    /// <summary>
    /// 用户ID
    /// </summary>
    [StringLength(50)]
    public required string UserId { get; set; }

    /// <summary>
    /// 用户名
    /// </summary>
    [StringLength(50)]
    public required string UserName { get; set; }

    /// <summary>
    /// 用户角色
    /// </summary>
    public UserRole Role { get; set; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// 最后访问时间
    /// </summary>
    public DateTimeOffset LastAccessedAt { get; set; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// IP地址
    /// </summary>
    [StringLength(45)] // IPv6 地址最大长度
    public string? IpAddress { get; set; }

    /// <summary>
    /// 用户代理
    /// </summary>
    [StringLength(500)]
    public string? UserAgent { get; set; }

    /// <summary>
    /// 是否记住登录
    /// </summary>
    public bool RememberMe { get; set; }

    /// <summary>
    /// 是否激活
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// 扩展数据（JSON格式存储）
    /// </summary>
    public string? Data { get; set; }

    /// <summary>
    /// 检查 Session 是否过期
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
}