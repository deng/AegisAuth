using System.ComponentModel.DataAnnotations;

namespace AegisAuthBase.Requests;

/// <summary>
/// 通行密钥注册请求
/// </summary>
public class PasskeyRegisterRequest
{
    /// <summary>
    /// 流程ID (用于关联注册选项)
    /// </summary>
    [Required]
    public required string FlowId { get; set; }

    /// <summary>
    /// 认证器响应 (WebAuthn Attestation)
    /// </summary>
    [Required]
    public required object Attestation { get; set; }
}
