using AegisAuth.WebAuthnDemo.Services;
using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using AegisAuthBase.Requests;
using AegisAuthBase.Services;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;

namespace AegisAuth.WebAuthnDemo.Controllers;

/// <summary>
/// WebAuthn 控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class WebauthnController : ControllerBase
{
    private readonly IPasskeyService _passkeyService;
    private readonly IUserRepository _userRepo;
    private readonly ICredentialStore _credentialStore;
    private readonly DemoUserService _demoUserService;

    public WebauthnController(IPasskeyService passkeyService, IUserRepository userRepo, ICredentialStore credentialStore, DemoUserService demoUserService)
    {
        _passkeyService = passkeyService;
        _userRepo = userRepo;
        _credentialStore = credentialStore;
        _demoUserService = demoUserService;
    }

    /// <summary>
    /// 获取注册选项
    /// </summary>
    [HttpPost("register-options")]
    public async Task<IActionResult> GetRegisterOptions()
    {
        var user = await _demoUserService.GetOrCreateDemoUserAsync();
        var options = await _passkeyService.GetRegisterOptionsAsync(user);
        return Ok(options);
    }

    /// <summary>
    /// 注册通行密钥
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] WebAuthnRegisterRequest request)
    {
        var user = await _demoUserService.GetOrCreateDemoUserAsync();

        await _passkeyService.RegisterAsync(user, request.Attestation, request.OriginalOptions);

        // Extract credential ID from attestation RawId (matching frontend arrayBufferToBase64)
        var credentialId = Convert.ToBase64String(request.Attestation.RawId);

        // Store the credential
        _credentialStore.AddCredential(new UserCredential
        {
            UserId = user.Id,
            CredentialId = credentialId,
            PublicKey = request.PublicKey
        });

        return Ok("Registration successful");
    }

    /// <summary>
    /// 获取登录选项
    /// </summary>
    [HttpPost("login-options")]
    public async Task<IActionResult> GetLoginOptions()
    {
        var user = await _demoUserService.GetOrCreateDemoUserAsync();
        var options = await _passkeyService.GetLoginOptionsAsync(user);
        if (options == null) return BadRequest("No passkeys found for this user");
        
        return Ok(options);
    }

    /// <summary>
    /// 通行密钥登录
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] WebAuthnLoginRequest request)
    {
        var user = await _demoUserService.GetOrCreateDemoUserAsync();

        var assertion = request.Assertion;

        var isValid = await _passkeyService.LoginAsync(user, assertion, request.OriginalOptions);
        if (!isValid) return BadRequest("Login failed");

        // If PublicKey is provided, store/update the credential (similar to register logic)
        if (!string.IsNullOrEmpty(request.PublicKey))
        {
            // Extract credential ID from assertion RawId (matching frontend arrayBufferToBase64)
            var credentialId = Convert.ToBase64String(assertion.RawId);

            // Check if credential already exists
            var existingCredential = _credentialStore.FindCredential(credentialId, user.Id);
            if (existingCredential == null)
            {
                // Store the credential
                _credentialStore.AddCredential(new UserCredential
                {
                    UserId = user.Id,
                    CredentialId = credentialId,
                    PublicKey = request.PublicKey
                });
            }
            else
            {
                // Update the public key
                existingCredential.PublicKey = request.PublicKey;
                _credentialStore.UpdateCredential(existingCredential);
            }
        }

        return Ok("Login successful");
    }
}