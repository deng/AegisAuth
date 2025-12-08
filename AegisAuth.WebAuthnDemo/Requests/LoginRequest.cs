using Fido2NetLib;

namespace AegisAuth.WebAuthnDemo.Requests;

public class LoginRequest
{
    public required AuthenticatorAssertionRawResponse Assertion { get; set; }

    public required AssertionOptions OriginalOptions { get; set; }

    public string? PublicKey { get; set; }
}
