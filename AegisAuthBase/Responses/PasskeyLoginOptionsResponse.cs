using Fido2NetLib;

namespace AegisAuthBase.Responses;

/// <summary>
/// 通行密钥登录选项响应
/// </summary>
public class PasskeyLoginOptionsResponse
{
    /// <summary>
    /// 流程ID
    /// </summary>
    public required string FlowId { get; set; }

    /// <summary>
    /// 登录选项 (AssertionOptions)
    /// </summary>
    public required AssertionOptions Options { get; set; }
}
