using System.ComponentModel.DataAnnotations;

namespace AegisAuthBase.Requests;

/// <summary>
/// 双因素认证验证请求
/// </summary>
public class TwoFactorVerifyRequest
{
    /// <summary>
    /// 双因素认证临时ID (从登录响应中获取)
    /// </summary>
    [Required]
    public required string TwoFactorId { get; set; }

    /// <summary>
    /// 多个验证码 (Key: 验证类型, Value: 验证码)
    /// </summary>
    [Required]
    public required Dictionary<string, string> Codes { get; set; }

    /// <summary>
    /// 通行密钥断言 (WebAuthn Assertion)
    /// </summary>
    public object? PasskeyAssertion { get; set; }
}
