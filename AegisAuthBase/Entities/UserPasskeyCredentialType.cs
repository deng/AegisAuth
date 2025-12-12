namespace AegisAuthBase.Entities;

/// <summary>
/// 用户通行密钥凭证类型
/// </summary>
public enum UserPasskeyCredentialType : byte
{
    /// <summary>
    /// 未知
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// 公钥 (public-key)
    /// </summary>
    PublicKey = 1
}
