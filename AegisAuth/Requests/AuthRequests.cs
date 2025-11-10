using System.ComponentModel.DataAnnotations;

namespace AegisAuth.Requests;

public class LoginRequest
{
    [Required]
    public required string UserName { get; set; }

    [Required]
    public required string Password { get; set; }
}

public class RefreshTokenRequest
{
    [Required]
    public required string RefreshToken { get; set; }
}