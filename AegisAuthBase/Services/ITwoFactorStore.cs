namespace AegisAuthBase.Services;

/// <summary>
/// 双因素认证存储接口
/// </summary>
public interface ITwoFactorStore
{
    /// <summary>
    /// 保存验证码
    /// </summary>
    /// <param name="twoFactorId">临时ID</param>
    /// <param name="code">验证码</param>
    /// <param name="userId">用户ID</param>
    /// <param name="expiration">过期时间</param>
    /// <returns></returns>
    Task SaveCodeAsync(string twoFactorId, string code, string userId, TimeSpan expiration);

    /// <summary>
    /// 获取验证码
    /// </summary>
    /// <param name="twoFactorId">临时ID</param>
    /// <returns>验证码和用户ID</returns>
    Task<(string? Code, string? UserId)> GetCodeAsync(string twoFactorId);

    /// <summary>
    /// 移除验证码
    /// </summary>
    /// <param name="twoFactorId">临时ID</param>
    /// <returns></returns>
    Task RemoveCodeAsync(string twoFactorId);
}
