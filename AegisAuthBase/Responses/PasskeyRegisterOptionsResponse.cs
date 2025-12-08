using Fido2NetLib;

namespace AegisAuthBase.Responses;

/// <summary>
/// 通行密钥注册选项响应
/// </summary>
public class PasskeyRegisterOptionsResponse
{
    /// <summary>
    /// 流程ID (提交注册时需带回)
    /// </summary>
    public required string FlowId { get; set; }

    /// <summary>
    /// 注册选项 (WebAuthn CredentialCreateOptions)
    /// </summary>
    public required CredentialCreateOptions Options { get; set; }
}
