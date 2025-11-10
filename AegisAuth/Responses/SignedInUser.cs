namespace AegisAuth.Responses;

public class SignedInUser
{
    public required string UserId { get; set; }

    public required string UserName { get; set; }

    public required string Token { get; set; }

    public required string RefreshToken { get; set; }

    public string? Role { get; set; }
}