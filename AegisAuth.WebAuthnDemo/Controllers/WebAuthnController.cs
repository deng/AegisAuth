using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using AegisAuthBase.Services;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;
using AegisAuth.WebAuthnDemo.Requests;

namespace AegisAuth.WebAuthnDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class WebauthnController : ControllerBase
    {
        private readonly IPasskeyService _passkeyService;
        private readonly IUserRepository _userRepo;

        public WebauthnController(IPasskeyService passkeyService, IUserRepository userRepo)
        {
            _passkeyService = passkeyService;
            _userRepo = userRepo;
        }

        [HttpPost("register-options")]
        public async Task<IActionResult> GetRegisterOptions()
        {
            // For demo, use a fixed user
            var user = await _userRepo.GetUserByUserNameAsync("demo");
            if (user == null)
            {
                user = new User
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = "demo",
                    PasswordHash = "",
                    PasswordSalt = "",
                    IsActive = true
                };
                await _userRepo.CreateAsync(user);
                await _userRepo.CommitAsync();
            }

            var options = await _passkeyService.GetRegisterOptionsAsync(user);
            return Ok(options);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var user = await _userRepo.GetUserByUserNameAsync("demo");
            if (user == null) return BadRequest("User not found");

            await _passkeyService.RegisterAsync(user, request.Attestation, request.OriginalOptions);

            // Extract credential ID from attestation RawId (matching frontend arrayBufferToBase64)
            var credentialId = Convert.ToBase64String(request.Attestation.RawId);

            // Store the credential
            BusinessController._credentials.Add(new UserCredential
            {
                UserId = user.Id,
                CredentialId = credentialId,
                PublicKey = request.PublicKey
            });

            return Ok("Registration successful");
        }

        [HttpPost("login-options")]
        public async Task<IActionResult> GetLoginOptions()
        {
            var user = await _userRepo.GetUserByUserNameAsync("demo");
            if (user == null) return BadRequest("User not found");

            var options = await _passkeyService.GetLoginOptionsAsync(user);
            return Ok(options);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _userRepo.GetUserByUserNameAsync("demo");
            if (user == null) return BadRequest("User not found");

            var assertion = request.Assertion;

            var isValid = await _passkeyService.LoginAsync(user, assertion, request.OriginalOptions);
            if (!isValid) return BadRequest("Login failed");

            // If PublicKey is provided, store/update the credential (similar to register logic)
            if (!string.IsNullOrEmpty(request.PublicKey))
            {
                // Extract credential ID from assertion RawId (matching frontend arrayBufferToBase64)
                var credentialId = Convert.ToBase64String(assertion.RawId);

                // Check if credential already exists
                var existingCredential = BusinessController._credentials.FirstOrDefault(c => c.CredentialId == credentialId && c.UserId == user.Id);
                if (existingCredential == null)
                {
                    // Store the credential
                    BusinessController._credentials.Add(new UserCredential
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
                }
            }

            return Ok("Login successful");
        }
    }
}
