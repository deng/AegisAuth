using System.ComponentModel.DataAnnotations;

namespace AegisAuth.Core.Requests;

public class LoginRequest
{
    [Required]
    public required string UserName { get; set; }

    [Required]
    public required string Password { get; set; }

    public bool RememberMe { get; set; }
}

public class RefreshTokenRequest
{
    [Required]
    public required string RefreshToken { get; set; }
}