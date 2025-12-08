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
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

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
    /// 密码修改时间
    /// </summary>
    public DateTimeOffset? PasswordChangedAt { get; set; }

    /// <summary>
    /// 是否启用双因素认证
    /// </summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>
    /// 双因素认证类型 (支持多选)
    /// </summary>
    public TwoFactorTypeFlags TwoFactorType { get; set; }

    /// <summary>
    /// 双因素认证密钥/方式
    /// </summary>
    public string? TwoFactorSecret { get; set; }

    /// <summary>
    /// 是否被锁定
    /// </summary>
    public bool IsLocked { get; set; }
}

/// <summary>
/// 用户凭据实体类
/// </summary>
public class UserCredential
{
    /// <summary>
    /// 用户ID
    /// </summary>
    public string UserId { get; set; }

    /// <summary>
    /// 凭据ID
    /// </summary>
    public string CredentialId { get; set; }

    /// <summary>
    /// 公钥
    /// </summary>
    public string PublicKey { get; set; }
}