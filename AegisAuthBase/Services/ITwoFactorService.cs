using AegisAuthBase.Requests;
using AegisAuthBase.Responses;

namespace AegisAuthBase.Services;

/// <summary>
/// 双因素认证服务接口
/// </summary>
public interface ITwoFactorService
{
    /// <summary>
    /// 验证双因素认证
    /// </summary>
    /// <param name="request">验证请求</param>
    /// <returns>登录结果</returns>
    Task<ApiResponse<SignedInUser>> VerifyTwoFactorAsync(TwoFactorVerifyRequest request);

    /// <summary>
    /// 启用双因素认证
    /// </summary>
    /// <returns>启用结果</returns>
    Task<ApiResponse> EnableTwoFactorAsync();
}