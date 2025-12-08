using System.ComponentModel.DataAnnotations;

namespace AegisAuthBase.Requests;

/// <summary>
/// 通行密钥登录请求
/// </summary>
public class PasskeyLoginRequest
{
    /// <summary>
    /// 流程ID (从获取选项接口返回)
    /// </summary>
    [Required]
    public required string FlowId { get; set; }

    /// <summary>
    /// 验证器断言响应
    /// </summary>
    [Required]
    public required object Assertion { get; set; }
}
