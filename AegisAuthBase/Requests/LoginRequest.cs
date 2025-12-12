using Fido2NetLib;

namespace AegisAuthBase.Requests;

/// <summary>
/// WebAuthn 登录请求
/// </summary>
public class WebAuthnLoginRequest
{
    /// <summary>
    /// 认证器断言响应
    /// </summary>
    public required AuthenticatorAssertionRawResponse Assertion { get; set; }

    /// <summary>
    /// 原始选项
    /// </summary>
    public required AssertionOptions OriginalOptions { get; set; }

    /// <summary>
    /// 公钥（可选，用于存储更新）
    /// </summary>
    public string? PublicKey { get; set; }
}