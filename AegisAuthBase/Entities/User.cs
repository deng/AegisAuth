namespace AegisAuthBase.Entities;

/// <summary>
/// 用户实体类
/// </summary>
public class User
{
    /// <summary>
    /// 用户ID
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// 用户名
    /// </summary>
    public required string UserName { get; set; }

    /// <summary>
    /// 用户角色
    /// </summary>
    public UserRole Role { get; set; }

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
    public required string PasswordHash { get; set; }

    /// <summary>
    /// 密码盐值
    /// </summary>
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