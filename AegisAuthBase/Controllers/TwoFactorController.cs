using AegisAuthBase.Entities;
using AegisAuthBase.Services;
using AegisAuthBase.Requests;
using AegisAuthBase.Responses;
using Microsoft.AspNetCore.Mvc;

namespace AegisAuthBase.Controllers;

/// <summary>
/// 双因素认证控制器
/// </summary>
[ApiController]
[Route("api/two-factor")]
public class TwoFactorController : ControllerBase
{
    private readonly ITwoFactorService _twoFactorService;
    private readonly ICredentialStore _credentialStore;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="twoFactorService">双因素认证服务</param>
    /// <param name="credentialStore">凭据存储</param>
    public TwoFactorController(ITwoFactorService twoFactorService, ICredentialStore credentialStore)
    {
        _twoFactorService = twoFactorService;
        _credentialStore = credentialStore;
    }

    /// <summary>
    /// 验证双因素认证
    /// </summary>
    /// <param name="request">验证请求</param>
    /// <returns>登录结果</returns>
    [HttpPost("verify")]
    [ProducesResponseType(typeof(ApiResponse<SignedInUser>), 200)]
    public async Task<IActionResult> Verify([FromBody] TwoFactorVerifyRequest request)
    {
        var result = await _twoFactorService.VerifyTwoFactorAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// 启用双因素认证
    /// </summary>
    /// <returns>启用结果</returns>
    [HttpPost("enable")]
    [Microsoft.AspNetCore.Authorization.Authorize]
    [ProducesResponseType(typeof(ApiResponse), 200)]
    public async Task<IActionResult> EnableTwoFactor()
    {
        var result = await _twoFactorService.EnableTwoFactorAsync();
        return Ok(result);
    }
}