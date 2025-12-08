using Fido2NetLib;

namespace AegisAuth.WebAuthnDemo.Requests;

public class VerifyRequest
{
    public required AuthenticatorAssertionRawResponse Assertion { get; set; }
    
    public required AssertionOptions OriginalOptions { get; set; }

    public required string Data { get; set; }
    
    public required string Signature { get; set; }
}