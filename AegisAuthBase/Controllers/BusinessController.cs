using AegisAuthBase.Repositories;
using AegisAuthBase.Requests;
using AegisAuthBase.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AegisAuthBase.Controllers;

/// <summary>
/// 业务控制器 - 处理签名验证等业务逻辑
/// </summary>
[ApiController]
[Route("api/business")]
public partial class BusinessController : ControllerBase
{
    private readonly IPasskeyService _passkeyService;
    private readonly IUserRepository _userRepo;
    private readonly ICredentialStore _credentialStore;
    private readonly IUserPasskeyRepository _passkeyRepo;

    public BusinessController(IPasskeyService passkeyService, IUserRepository userRepo, ICredentialStore credentialStore, IUserPasskeyRepository passkeyRepo)
    {
        _passkeyService = passkeyService;
        _userRepo = userRepo;
        _credentialStore = credentialStore;
        _passkeyRepo = passkeyRepo;
    }

    /// <summary>
    /// 获取验证选项
    /// </summary>
    [HttpPost("verify-options")]
    [Authorize]
    public async Task<IActionResult> GetVerifyOptions()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var user = await _userRepo.GetByIdAsync(userId, false);
        if (user == null) return BadRequest("User not found");

        var options = await _passkeyService.GetLoginOptionsAsync(user);
        if (options == null) return BadRequest("No passkeys found for this user");
        
        return Ok(options);
    }

    /// <summary>
    /// 验证签名
    /// </summary>
    [HttpPost("verify")]
    [Authorize]
    public async Task<IActionResult> Verify([FromBody] VerifyRequest request)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var user = await _userRepo.GetByIdAsync(userId, false);
        if (user == null) return BadRequest("User not found");

        var assertion = request.Assertion;

        var isValid = await _passkeyService.LoginAsync(user, assertion, request.OriginalOptions);
        if (isValid)
        {
            var credentialId = Convert.ToBase64String(assertion.RawId);
            var credential = _credentialStore.FindCredential(credentialId, userId);
            if (credential == null) return BadRequest("Credential not found");

            // Verify the signature using the stored public key
            var publicKeyBytes = Convert.FromBase64String(credential.PublicKey);
            using var ecdsa = System.Security.Cryptography.ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            var dataBytes = System.Text.Encoding.UTF8.GetBytes(request.Data);
            var signatureBytes = Convert.FromBase64String(request.Signature);
            isValid = ecdsa.VerifyData(dataBytes, signatureBytes, System.Security.Cryptography.HashAlgorithmName.SHA256);
        }

        return isValid ? Ok("Login successful") : BadRequest("Login failed");
    }
}