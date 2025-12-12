using Fido2NetLib;

namespace AegisAuthBase.Requests;

/// <summary>
/// WebAuthn 注册请求
/// </summary>
public class WebAuthnRegisterRequest
{
    /// <summary>
    /// 认证器证明响应
    /// </summary>
    public required AuthenticatorAttestationRawResponse Attestation { get; set; }

    /// <summary>
    /// 原始选项
    /// </summary>
    public required CredentialCreateOptions OriginalOptions { get; set; }

    /// <summary>
    /// 公钥
    /// </summary>
    public required string PublicKey { get; set; }
}