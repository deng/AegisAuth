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
    SuspiciousActivity = 9
}

/// <summary>
/// 安全事件结果枚举
/// </summary>
public enum SecurityEventResult : byte
{
    /// <summary>
    /// 成功
    /// </summary>
    Success = 1,

    /// <summary>
    /// 失败
    /// </summary>
    Failure = 2,

    /// <summary>
    /// 警告
    /// </summary>
    Warning = 3,

    /// <summary>
    /// 信息
    /// </summary>
    Information = 4
}

/// <summary>
/// 用户角色枚举
/// </summary>
public enum UserRole : byte
{
    /// <summary>
    /// 普通用户
    /// </summary>
    User = 1,

    /// <summary>
    /// 管理员
    /// </summary>
    Admin = 2
}