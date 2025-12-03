using AegisAuthJwt.Managers;
using AegisAuthBase.Requests;
using AegisAuthBase.Responses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AegisAuthJwt.Controllers;

/// <summary>
/// 认证控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthManager _authManager;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="authManager">认证管理器</param>
    public AuthController(AuthManager authManager)
    {
        _authManager = authManager;
    }

    /// <summary>
    /// 用户登录
    /// </summary>
    /// <param name="request">登录请求</param>
    /// <returns>登录结果</returns>
    [HttpPost("login")]
    [ProducesResponseType(typeof(ApiResponse<SignedInUser>), 200)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var result = await _authManager.SignIn(request);
        return Ok(result);
    }

    /// <summary>
    /// 用户注册
    /// </summary>
    /// <param name="request">注册请求</param>
    /// <returns>注册结果</returns>
    [HttpPost("register")]
    [ProducesResponseType(typeof(ApiResponse), 200)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var result = await _authManager.Register(request);
        return Ok(result);
    }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="request">刷新令牌请求</param>
    /// <returns>刷新结果</returns>
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(ApiResponse<SignedInUser>), 200)]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
    {
        var result = await _authManager.RefreshToken(request);
        return Ok(result);
    }

    /// <summary>
    /// 用户登出
    /// </summary>
    /// <returns>登出结果</returns>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse), 200)]
    public async Task<IActionResult> Logout()
    {
        var result = await _authManager.Logout();
        return Ok(result);
    }
}