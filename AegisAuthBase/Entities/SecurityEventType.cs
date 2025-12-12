namespace AegisAuthBase.Entities;

/// <summary>
/// 安全事件类型枚举
/// </summary>
public enum SecurityEventType : byte
{
    /// <summary>
    /// 用户登录
    /// </summary>
    UserLogin = 1,

    /// <summary>
    /// 用户登出
    /// </summary>
    UserLogout = 2,

    /// <summary>
    /// 密码修改
    /// </summary>
    PasswordChange = 3,

    /// <summary>
    /// 账户锁定
    /// </summary>
    AccountLockout = 4,

    /// <summary>
    /// 账户解锁
    /// </summary>
    AccountUnlock = 5,

    /// <summary>
    /// 权限变更
    /// </summary>
    PermissionChange = 6,

    /// <summary>
    /// 敏感操作
    /// </summary>
    SensitiveOperation = 7,

    /// <summary>
    /// API访问
    /// </summary>
    ApiAccess = 8,

    /// <summary>
    /// 异常访问
    /// </summary>
    AbnormalAccess = 9,

    /// <summary>
    /// 双因素认证验证
    /// </summary>
    TwoFactorVerify = 10
}
