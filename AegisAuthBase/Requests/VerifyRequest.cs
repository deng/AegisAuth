using Fido2NetLib;

namespace AegisAuthBase.Requests;

/// <summary>
/// 验证请求
/// </summary>
public class VerifyRequest
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
    /// 要验证的数据
    /// </summary>
    public required string Data { get; set; }

    /// <summary>
    /// 签名
    /// </summary>
    public required string Signature { get; set; }
}