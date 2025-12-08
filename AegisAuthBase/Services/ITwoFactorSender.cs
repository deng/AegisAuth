using AegisAuthBase.Entities;

namespace AegisAuthBase.Services;

/// <summary>
/// 双因素认证发送器接口
/// </summary>
public interface ITwoFactorSender
{
    /// <summary>
    /// 发送验证码
    /// </summary>
    /// <param name="user">用户</param>
    /// <param name="code">验证码</param>
    /// <param name="type">验证类型 (Email/Sms)</param>
    /// <returns></returns>
    Task SendCodeAsync(User user, string code, TwoFactorTypeFlags type);
}
