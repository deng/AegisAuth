using AegisAuthBase.Entities;
using AegisAuthBase.Requests;
using AegisAuthBase.Responses;
using AegisAuthBase.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AegisAuthBase.Controllers;

/// <summary>
/// 通行密钥控制器
/// </summary>
[ApiController]
[Route("api/passkey")]
public class PasskeyController : ControllerBase
{
    private readonly IPasskeyAuthService _passkeyAuthService;
    private readonly ICredentialStore _credentialStore;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="passkeyAuthService">通行密钥认证服务</param>
    /// <param name="credentialStore">凭据存储</param>
    public PasskeyController(IPasskeyAuthService passkeyAuthService, ICredentialStore credentialStore)
    {
        _passkeyAuthService = passkeyAuthService;
        _credentialStore = credentialStore;
    }

    /// <summary>
    /// 获取通行密钥登录选项
    /// </summary>
    /// <returns>登录选项</returns>
    [HttpPost("login-options")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse<PasskeyLoginOptionsResponse>), 200)]
    public async Task<IActionResult> GetPasskeyLoginOptions()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var result = await _passkeyAuthService.GetPasskeyLoginOptionsAsync(userId);
        return Ok(result);
    }

    /// <summary>
    /// 通行密钥登录
    /// </summary>
    /// <param name="request">登录请求</param>
    /// <returns>登录结果</returns>
    [HttpPost("login")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse<SignedInUser>), 200)]
    public async Task<IActionResult> LoginPasskey([FromBody] PasskeyLoginRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var result = await _passkeyAuthService.LoginPasskeyAsync(request);
        if (result.Success && !string.IsNullOrEmpty(request.PublicKey))
        {
            // Extract credential ID from assertion RawId
            var assertionJson = System.Text.Json.JsonSerializer.Serialize(request.Assertion);
            var assertion = System.Text.Json.JsonSerializer.Deserialize<Fido2NetLib.AuthenticatorAssertionRawResponse>(assertionJson);
            if (assertion != null)
            {
                var credentialId = Convert.ToBase64String(assertion.RawId);

                // Check if credential already exists
                var existingCredential = _credentialStore.FindCredential(credentialId, userId);
                if (existingCredential == null)
                {
                    // Store the credential for signature verification
                    _credentialStore.AddCredential(new UserCredential
                    {
                        UserId = userId,
                        CredentialId = credentialId,
                        PublicKey = request.PublicKey
                    });
                }
                else
                {
                    // Update the public key if different
                    if (existingCredential.PublicKey != request.PublicKey)
                    {
                        existingCredential.PublicKey = request.PublicKey;
                        _credentialStore.UpdateCredential(existingCredential);
                    }
                }
            }
        }
        return Ok(result);
    }

    /// <summary>
    /// 获取通行密钥注册选项
    /// </summary>
    /// <returns>注册选项</returns>
    [HttpGet("register-options")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse<PasskeyRegisterOptionsResponse>), 200)]
    public async Task<IActionResult> GetPasskeyRegisterOptions()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var result = await _passkeyAuthService.GetPasskeyRegisterOptionsAsync(userId);
        return Ok(result);
    }

    /// <summary>
    /// 注册通行密钥
    /// </summary>
    /// <param name="request">注册请求</param>
    /// <returns>注册结果</returns>
    [HttpPost("register")]
    [Authorize]
    [ProducesResponseType(typeof(ApiResponse), 200)]
    public async Task<IActionResult> RegisterPasskey([FromBody] PasskeyRegisterRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var result = await _passkeyAuthService.RegisterPasskeyAsync(userId, request);
        if (result.Success)
        {
            // Extract credential ID from attestation RawId
            var attestationJson = System.Text.Json.JsonSerializer.Serialize(request.Attestation);
            var attestation = System.Text.Json.JsonSerializer.Deserialize<Fido2NetLib.AuthenticatorAttestationRawResponse>(attestationJson);
            if (attestation != null)
            {
                var credentialId = Convert.ToBase64String(attestation.RawId);

                // Store the credential for signature verification
                _credentialStore.AddCredential(new UserCredential
                {
                    UserId = userId,
                    CredentialId = credentialId,
                    PublicKey = request.PublicKey
                });
            }
        }
        return Ok(result);
    }
}