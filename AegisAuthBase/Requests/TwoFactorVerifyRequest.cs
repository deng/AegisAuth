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
    /// 多个验证码 (Key: 验证类型, Value: 验证码字符串或序列化的验证对象)
    /// </summary>
    [Required]
    public required Dictionary<string, string> Codes { get; set; }

    /// <summary>
    /// 公钥 (用于签名验证，如果客户端私钥对丢失)
    /// </summary>
    public string? PublicKey { get; set; }
}
