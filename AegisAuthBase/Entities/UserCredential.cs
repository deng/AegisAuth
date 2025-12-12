namespace AegisAuthBase.Entities;

/// <summary>
/// 用户凭据实体类
/// </summary>
public class UserCredential
{
    /// <summary>
    /// 用户ID
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// 凭据ID
    /// </summary>
    public required string CredentialId { get; set; }

    /// <summary>
    /// 公钥
    /// </summary>
    public required string PublicKey { get; set; }
}