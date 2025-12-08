using System;

namespace AegisAuthBase.Entities;

/// <summary>
/// 用户通行密钥 (WebAuthn/FIDO2 Credentials)
/// </summary>
public class UserPasskey
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    public required string UserId { get; set; }
    
    /// <summary>
    /// 凭证ID (Raw Id) - Base64 Encoded
    /// </summary>
    public string CredentialId { get; set; } = string.Empty;

    /// <summary>
    /// 公钥 - Base64 Encoded
    /// </summary>
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>
    /// 签名计数器 (防止重放攻击)
    /// </summary>
    public uint SignatureCounter { get; set; }

    /// <summary>
    /// 凭证类型 (例如 "public-key")
    /// </summary>
    public UserPasskeyCredentialType CredentialType { get; set; } = UserPasskeyCredentialType.PublicKey;

    /// <summary>
    /// 认证器AAGUID (用于识别设备型号)
    /// </summary>
    public string Aaguid { get; set; } = string.Empty;

    /// <summary>
    /// PRF是否启用
    /// </summary>
    public bool PrfEnabled { get; set; }

    /// <summary>
    /// PRF First值 - Base64 Encoded
    /// </summary>
    public string? PrfFirst { get; set; }

    /// <summary>
    /// PRF Second值 - Base64 Encoded
    /// </summary>
    public string? PrfSecond { get; set; }

    /// <summary>
    /// 备注名称 (例如 "iPhone 13", "Chrome on MacBook")
    /// </summary>
    public string? DisplayName { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    
    public DateTimeOffset LastUsedAt { get; set; }
}
