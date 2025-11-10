using System.ComponentModel.DataAnnotations;

namespace AegisAuth.Entities;

/// <summary>
/// 用户实体类
/// </summary>
public class User
{
    /// <summary>
    /// 用户ID
    /// </summary>
    [StringLength(50)]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// 用户名
    /// </summary>
    [StringLength(50)]
    public required string Username { get; set; }

    /// <summary>
    /// 用户角色（由使用者自定义，如 "Admin", "User" 等）
    /// </summary>
    [StringLength(50)]
    public string? Role { get; set; }

    /// <summary>
    /// 是否激活
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// 最后登录时间
    /// </summary>
    public DateTimeOffset? LastLogin { get; set; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// 密码哈希
    /// </summary>
    [StringLength(256)]
    public required string PasswordHash { get; set; }

    /// <summary>
    /// 密码盐值
    /// </summary>
    [StringLength(256)]
    public required string PasswordSalt { get; set; }

    /// <summary>
    /// 登录失败次数
    /// </summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>
    /// 账户锁定结束时间
    /// </summary>
    public DateTimeOffset? LockoutEnd { get; set; }

    /// <summary>
    /// 密码最后修改时间
    /// </summary>
    public DateTimeOffset? PasswordChangedAt { get; set; }

    /// <summary>
    /// 是否被锁定
    /// </summary>
    public bool IsLocked { get; set; }
}