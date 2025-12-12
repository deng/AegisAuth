using AegisAuthBase.Requests;
using AegisAuthBase.Responses;

namespace AegisAuthBase.Services;

/// <summary>
/// 通行密钥认证服务接口
/// </summary>
public interface IPasskeyAuthService
{
    /// <summary>
    /// 获取通行密钥登录选项
    /// </summary>
    Task<ApiResponse<PasskeyLoginOptionsResponse>> GetPasskeyLoginOptionsAsync(string userId);

    /// <summary>
    /// 通行密钥登录
    /// </summary>
    Task<ApiResponse<SignedInUser>> LoginPasskeyAsync(PasskeyLoginRequest request);

    /// <summary>
    /// 获取通行密钥注册选项
    /// </summary>
    Task<ApiResponse<PasskeyRegisterOptionsResponse>> GetPasskeyRegisterOptionsAsync(string userId);

    /// <summary>
    /// 注册通行密钥
    /// </summary>
    Task<ApiResponse> RegisterPasskeyAsync(string userId, PasskeyRegisterRequest request);
}