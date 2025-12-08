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
    /// 验证双因素认证
    /// </summary>
    /// <param name="request">验证请求</param>
    /// <returns>登录结果</returns>
    [HttpPost("verify-2fa")]
    [ProducesResponseType(typeof(ApiResponse<SignedInUser>), 200)]
    public async Task<IActionResult> VerifyTwoFactor([FromBody] TwoFactorVerifyRequest request)
    {
        var result = await _authManager.VerifyTwoFactor(request);
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

    /// <summary>
    /// 获取通行密钥登录选项
    /// </summary>
    /// <param name="userName">用户名</param>
    /// <returns>登录选项</returns>
    [HttpPost("passkey/login-options")]
    [ProducesResponseType(typeof(ApiResponse<PasskeyLoginOptionsResponse>), 200)]
    public async Task<IActionResult> GetPasskeyLoginOptions([FromBody] string userName)
    {
        var result = await _authManager.GetPasskeyLoginOptionsAsync(userName);
        return Ok(result);
    }

    /// <summary>
    /// 通行密钥登录
    /// </summary>
    /// <param name="request">登录请求</param>
    /// <returns>登录结果</returns>
    [HttpPost("passkey/login")]
    [ProducesResponseType(typeof(ApiResponse<SignedInUser>), 200)]
    public async Task<IActionResult> LoginPasskey([FromBody] PasskeyLoginRequest request)
    {
        var result = await _authManager.LoginPasskeyAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// 获取通行密钥注册选项
    /// </summary>
    /// <returns>注册选项</returns>
    [HttpGet("passkey/register-options")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse<PasskeyRegisterOptionsResponse>), 200)]
    public async Task<IActionResult> GetPasskeyRegisterOptions()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        
        var result = await _authManager.GetPasskeyRegisterOptionsAsync(userId);
        return Ok(result);
    }

    /// <summary>
    /// 注册通行密钥
    /// </summary>
    /// <param name="request">注册请求</param>
    /// <returns>注册结果</returns>
    [HttpPost("passkey/register")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse), 200)]
    public async Task<IActionResult> RegisterPasskey([FromBody] PasskeyRegisterRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var result = await _authManager.RegisterPasskeyAsync(userId, request);
        return Ok(result);
    }
}