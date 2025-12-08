using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using AegisAuthBase.Services;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;
using AegisAuth.WebAuthnDemo.Requests;

namespace AegisAuth.WebAuthnDemo.Controllers;

[ApiController]
[Route("api/business")]
public partial class BusinessController : ControllerBase
{
    private readonly IPasskeyService _passkeyService;
    private readonly IUserRepository _userRepo;

    // Static storage for user credentials (demo purposes)
    public static List<UserCredential> _credentials = new();

    public BusinessController(IPasskeyService passkeyService, IUserRepository userRepo)
    {
        _passkeyService = passkeyService;
        _userRepo = userRepo;
    }

    [HttpPost("verify-options")]
    public async Task<IActionResult> GetVerifyOptions()
    {
        var user = await _userRepo.GetUserByUserNameAsync("demo");
        if (user == null) return BadRequest("User not found");

        var options = await _passkeyService.GetLoginOptionsAsync(user);
        return Ok(options);
    }

    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] VerifyRequest request)
    {
        var user = await _userRepo.GetUserByUserNameAsync("demo");
        if (user == null) return BadRequest("User not found");

        var assertion = request.Assertion;

        var isValid = await _passkeyService.LoginAsync(user, assertion, request.OriginalOptions);
        if (isValid)
        {
            var credentialId = Convert.ToBase64String(assertion.RawId);
            var credential = _credentials.FirstOrDefault(c => c.CredentialId == credentialId && c.UserId == user.Id);
            if (credential == null) return BadRequest("Credential not found");
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
