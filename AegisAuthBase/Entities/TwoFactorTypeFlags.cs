namespace AegisAuthBase.Entities;

/// <summary>
/// 双因素认证类型 (Flags)
/// </summary>
[Flags]
public enum TwoFactorTypeFlags : byte
{
    /// <summary>
    /// 未启用
    /// </summary>
    None = 0,

    /// <summary>
    /// 电子邮件
    /// </summary>
    Email = 1,

    /// <summary>
    /// 短信
    /// </summary>
    Sms = 2,

    /// <summary>
    /// 认证器应用 (Google Authenticator等)
    /// </summary>
    AuthenticatorApp = 4,

    /// <summary>
    /// 通行密钥
    /// </summary>
    Passkey = 8
}
